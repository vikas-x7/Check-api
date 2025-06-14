import { AxiosResponse } from "axios";
import { scannerClient } from "@/server/core/http/scanner-client";
import { SecurityCheck, ScanTarget, FindingResult, Evidence } from "@/types";
import { logger } from "@/server/core/logging/logger";

const log = logger.child("jwt-check");

/* ─── Base64url encode helper ─── */
function b64url(data: string): string {
    return Buffer.from(data).toString("base64url");
}

/* ─── Crafted JWT tokens for various attack vectors ─── */
const JWT_ATTACK_VECTORS: { token: string; label: string; severity: "CRITICAL" | "HIGH" | "MEDIUM"; attackType: string }[] = [
    // 1. Algorithm "none" bypass — most critical JWT flaw
    {
        token: `${b64url('{"alg":"none","typ":"JWT"}')}.${b64url('{"sub":"1","role":"admin","iat":1700000000,"exp":9999999999}')}.`,
        label: "JWT alg:none bypass (unsigned admin token)",
        severity: "CRITICAL",
        attackType: "algorithm-none",
    },
    {
        token: `${b64url('{"alg":"None","typ":"JWT"}')}.${b64url('{"sub":"1","role":"admin","iat":1700000000,"exp":9999999999}')}.`,
        label: "JWT alg:None (case variation) bypass",
        severity: "CRITICAL",
        attackType: "algorithm-none",
    },
    {
        token: `${b64url('{"alg":"NONE","typ":"JWT"}')}.${b64url('{"sub":"1","role":"admin","iat":1700000000,"exp":9999999999}')}.`,
        label: "JWT alg:NONE (uppercase) bypass",
        severity: "CRITICAL",
        attackType: "algorithm-none",
    },
    {
        token: `${b64url('{"alg":"nOnE","typ":"JWT"}')}.${b64url('{"sub":"1","role":"admin","iat":1700000000,"exp":9999999999}')}.`,
        label: "JWT alg:nOnE (mixed-case) bypass",
        severity: "CRITICAL",
        attackType: "algorithm-none",
    },
    // 2. Empty signature
    {
        token: `${b64url('{"alg":"HS256","typ":"JWT"}')}.${b64url('{"sub":"1","role":"admin","iat":1700000000}')}.`,
        label: "JWT with empty signature (HS256 header)",
        severity: "HIGH",
        attackType: "empty-signature",
    },
    // 3. Weak secret — signed with common weak keys
    {
        token: `${b64url('{"alg":"HS256","typ":"JWT"}')}.${b64url('{"sub":"1","role":"admin","iat":1700000000,"exp":9999999999}')}.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c`,
        label: "JWT signed with weak secret 'secret'",
        severity: "HIGH",
        attackType: "weak-secret",
    },
    {
        token: `${b64url('{"alg":"HS256","typ":"JWT"}')}.${b64url('{"sub":"1","role":"admin","iat":1700000000,"exp":9999999999}')}.${b64url("invalid-sig")}`,
        label: "JWT with randomized invalid signature",
        severity: "HIGH",
        attackType: "signature-bypass",
    },
    // 4. Expired token test
    {
        token: `${b64url('{"alg":"HS256","typ":"JWT"}')}.${b64url('{"sub":"test","role":"user","iat":1000000000,"exp":1000000001}')}.${b64url("expired-sig")}`,
        label: "JWT with expired claims (exp: 2001)",
        severity: "MEDIUM",
        attackType: "expired-token",
    },
    // 5. JWK injection via header
    {
        token: `${b64url('{"alg":"HS256","typ":"JWT","jwk":{"kty":"oct","k":"' + b64url("attacker-key") + '"}}')}.${b64url('{"sub":"1","role":"admin"}')}.${b64url("jwk-inject")}`,
        label: "JWT with embedded JWK key injection",
        severity: "CRITICAL",
        attackType: "jwk-injection",
    },
    // 6. kid (Key ID) path traversal
    {
        token: `${b64url('{"alg":"HS256","typ":"JWT","kid":"../../etc/passwd"}')}.${b64url('{"sub":"1","role":"admin"}')}.${b64url("kid-traversal")}`,
        label: "JWT with kid path traversal",
        severity: "CRITICAL",
        attackType: "kid-traversal",
    },
    // 7. Algorithm confusion RS256 → HS256
    {
        token: `${b64url('{"alg":"HS256","typ":"JWT"}')}.${b64url('{"sub":"1","role":"admin","iat":1700000000,"exp":9999999999}')}.dummysig`,
        label: "JWT algorithm confusion (RS256→HS256)",
        severity: "HIGH",
        attackType: "algorithm-confusion",
    },
];

export class JwtVulnerabilityCheck implements SecurityCheck {
    name = "JWT Vulnerability Check";
    description = "Tests for JWT algorithm none bypass, weak secrets, expired token acceptance, key confusion, JWK injection, and kid traversal attacks";
    owaspMapping = "Broken Authentication";
    owaspId = "API2:2023";

    async run(target: ScanTarget): Promise<FindingResult[]> {
        const findings: FindingResult[] = [];

        for (const endpoint of target.endpoints) {
            const url = `${target.baseUrl}${endpoint.path}`;
            const method = endpoint.method.toLowerCase();

            /* ── Phase 1: Test each JWT attack vector ── */
            for (const vector of JWT_ATTACK_VECTORS) {
                try {
                    const response = await scannerClient({
                        requestsPerSecond: target.requestsPerSecond,
                        method,
                        url,
                        timeout: 10000,
                        validateStatus: () => true,
                        headers: {
                            Authorization: `Bearer ${vector.token}`,
                            "User-Agent": "SecuriScan/1.0",
                            "Content-Type": "application/json",
                            ...(endpoint.customHeaders || {}),
                        },
                    });

                    if (response.status >= 200 && response.status < 300) {
                        findings.push({
                            checkType: "jwt-vulnerability",
                            severity: vector.severity,
                            title: `${vector.label}: ${endpoint.method} ${endpoint.path}`,
                            description: this.getDescription(vector.attackType, endpoint.path, response.status, vector.label),
                            evidence: this.buildEvidence(url, endpoint.method, { Authorization: `Bearer ${vector.token.slice(0, 80)}...` }, response),
                            owaspMapping: this.owaspMapping,
                            owaspId: this.owaspId,
                            remediation: this.getRemediation(vector.attackType),
                            endpoint: endpoint.path,
                            method: endpoint.method,
                        });
                        break; // One JWT bypass per endpoint is sufficient evidence
                    }
                } catch {
                    // Expected for blocked requests
                }
            }

            /* ── Phase 2: Test missing critical claims ── */
            if (target.authConfig?.value) {
                try {
                    const parts = target.authConfig.value.split(".");
                    if (parts.length === 3) {
                        // Decode existing payload and strip critical claims
                        const payload = JSON.parse(Buffer.from(parts[1]!, "base64url").toString());
                        const strippedPayloads = [
                            { ...payload, exp: undefined, label: "missing exp claim" },
                            { ...payload, iss: undefined, label: "missing iss claim" },
                            { ...payload, aud: undefined, label: "missing aud claim" },
                            { ...payload, sub: undefined, label: "missing sub claim" },
                        ];

                        for (const sp of strippedPayloads) {
                            const lbl = sp.label;
                            delete sp.label;
                            const craftedToken = `${parts[0]}.${b64url(JSON.stringify(sp))}.${parts[2]}`;
                            try {
                                const response = await scannerClient({
                                    requestsPerSecond: target.requestsPerSecond,
                                    method,
                                    url,
                                    timeout: 10000,
                                    validateStatus: () => true,
                                    headers: {
                                        Authorization: `Bearer ${craftedToken}`,
                                        "User-Agent": "SecuriScan/1.0",
                                        ...(endpoint.customHeaders || {}),
                                    },
                                });

                                if (response.status >= 200 && response.status < 300) {
                                    findings.push({
                                        checkType: "jwt-vulnerability",
                                        severity: "MEDIUM",
                                        title: `JWT accepted with ${lbl}: ${endpoint.method} ${endpoint.path}`,
                                        description: `The endpoint accepted a JWT token with ${lbl}. Standard JWT validation should reject tokens missing critical claims (exp, iss, aud, sub) to prevent token misuse and replay attacks.`,
                                        evidence: this.buildEvidence(url, endpoint.method, { Authorization: `Bearer ${craftedToken.slice(0, 80)}...` }, response),
                                        owaspMapping: this.owaspMapping,
                                        owaspId: this.owaspId,
                                        remediation: `Enforce mandatory JWT claims:\n\n\`\`\`javascript\nconst decoded = jwt.verify(token, secret, {\n  algorithms: ['RS256'],\n  issuer: 'your-app',\n  audience: 'your-api',\n  complete: true,\n});\n\nif (!decoded.payload.exp || !decoded.payload.sub) {\n  throw new Error('Missing mandatory JWT claims');\n}\n\`\`\``,
                                        endpoint: endpoint.path,
                                        method: endpoint.method,
                                    });
                                }
                            } catch {
                                // Expected
                            }
                        }
                    }
                } catch (err) {
                    log.debug(`JWT claim stripping failed for ${url}: ${err instanceof Error ? err.message : String(err)}`);
                }
            }
        }

        return findings;
    }

    private getDescription(attackType: string, path: string, status: number, label: string): string {
        const descriptions: Record<string, string> = {
            "algorithm-none": `CRITICAL: The endpoint ${path} accepted a JWT token with algorithm set to 'none' (${label}) and returned HTTP ${status}. This means the server is not verifying JWT signatures at all, allowing any attacker to forge arbitrary tokens and impersonate any user, including administrators.`,
            "empty-signature": `The endpoint ${path} accepted a JWT token with an empty signature and returned HTTP ${status}. The server fails to validate that the JWT signature is present and correct, allowing token forgery.`,
            "weak-secret": `The endpoint ${path} accepted a JWT signed with a commonly known weak secret ('secret', 'password', etc.) and returned HTTP ${status}. Attackers can brute-force weak HMAC secrets to forge valid tokens.`,
            "signature-bypass": `The endpoint ${path} accepted a JWT token with an invalid/random signature and returned HTTP ${status}. The server does not properly verify JWT signatures.`,
            "expired-token": `The endpoint ${path} accepted a JWT token with an expired 'exp' claim (set to year 2001) and returned HTTP ${status}. The server does not validate token expiration, allowing indefinite token reuse.`,
            "jwk-injection": `CRITICAL: The endpoint ${path} may be vulnerable to JWK header injection. The server could be using a key embedded in the JWT header itself for verification, allowing attackers to self-sign tokens.`,
            "kid-traversal": `CRITICAL: The endpoint ${path} may be vulnerable to 'kid' parameter path traversal. Attackers can manipulate the key ID to point to predictable filesystem files (like /etc/passwd or /dev/null), using their contents as the HMAC key.`,
            "algorithm-confusion": `The endpoint ${path} may be vulnerable to algorithm confusion. If the server expects RS256 (asymmetric) but the token specifies HS256 (symmetric), an attacker can sign the token using the server's public key as the HMAC secret.`,
        };
        return descriptions[attackType] || `JWT vulnerability detected at ${path}: ${label}`;
    }

    private getRemediation(attackType: string): string {
        const remediations: Record<string, string> = {
            "algorithm-none": `CRITICAL FIX — Explicitly whitelist allowed algorithms:\n\n\`\`\`javascript\nconst decoded = jwt.verify(token, secret, {\n  algorithms: ['RS256'], // NEVER include 'none'\n  issuer: 'your-app',\n  audience: 'your-api',\n});\n\`\`\`\n\nNever use libraries that accept alg:none by default. If using jose or jsonwebtoken, ensure you pass the algorithms parameter.`,
            "empty-signature": `Ensure your JWT library rejects tokens with missing signatures:\n\n\`\`\`javascript\nif (!token || token.split('.').length !== 3 || !token.split('.')[2]) {\n  throw new Error('Invalid JWT format');\n}\nconst decoded = jwt.verify(token, secret, { algorithms: ['RS256'] });\n\`\`\``,
            "weak-secret": `Use cryptographically strong secrets (256+ bits):\n\n\`\`\`javascript\n// Generate a strong secret\nconst crypto = require('crypto');\nconst JWT_SECRET = crypto.randomBytes(64).toString('hex');\n\n// Or better yet, use asymmetric keys (RS256)\nconst privateKey = fs.readFileSync('./private.pem');\nconst token = jwt.sign(payload, privateKey, { algorithm: 'RS256' });\n\`\`\``,
            "signature-bypass": `Ensure strict signature verification is enabled and never disabled:\n\n\`\`\`javascript\n// jsonwebtoken library verifies by default\nconst decoded = jwt.verify(token, secret, {\n  algorithms: ['HS256'],\n  complete: true, // Returns header + payload + signature\n});\n\`\`\``,
            "expired-token": `Always validate the 'exp' claim:\n\n\`\`\`javascript\nconst decoded = jwt.verify(token, secret, {\n  algorithms: ['RS256'],\n  clockTolerance: 30, // Allow 30s clock skew\n});\n// jwt.verify automatically rejects expired tokens\n\`\`\``,
            "jwk-injection": `CRITICAL FIX — Never use keys embedded in the JWT header for verification:\n\n\`\`\`javascript\n// BAD: Using JWK from the token header\n// GOOD: Load keys from a trusted JWKS endpoint only\nconst JWKS_URI = 'https://your-auth-server/.well-known/jwks.json';\nconst jwksClient = require('jwks-rsa')({ jwksUri: JWKS_URI });\nconst key = await jwksClient.getSigningKey(decoded.header.kid);\nconst pubKey = key.getPublicKey();\n\`\`\``,
            "kid-traversal": `Sanitize the 'kid' claim and use it only as a lookup key:\n\n\`\`\`javascript\nconst header = jwt.decode(token, { complete: true }).header;\n// Validate kid is alphanumeric only\nif (!/^[a-zA-Z0-9_-]+$/.test(header.kid)) {\n  throw new Error('Invalid key ID');\n}\nconst key = await keystore.getKey(header.kid);\n\`\`\``,
            "algorithm-confusion": `Always specify the expected algorithm server-side:\n\n\`\`\`javascript\n// If you use RS256, ONLY accept RS256\nconst decoded = jwt.verify(token, publicKey, {\n  algorithms: ['RS256'], // Block HS256\n});\n\`\`\``,
        };
        return remediations[attackType] || "Implement proper JWT validation with explicit algorithm whitelisting, signature verification, and claim validation.";
    }

    private buildEvidence(url: string, method: string, headers: Record<string, string>, response: AxiosResponse): Evidence {
        return {
            request: { url, method, headers },
            response: {
                status: response.status,
                headers: response.headers as Record<string, string>,
                body: typeof response.data === "object" ? response.data : String(response.data).slice(0, 500),
            },
            description: `JWT attack probe sent to ${method} ${url}`,
        };
    }
}
