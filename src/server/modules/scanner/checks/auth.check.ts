import { AxiosResponse } from "axios";
import { scannerClient } from "@/server/core/http/scanner-client";
import { SecurityCheck, ScanTarget, FindingResult, Evidence } from "@/types";
import { logger } from "@/server/core/logging/logger";

const log = logger.child("auth-check");

/* ─── Token Payloads for Bypass Testing ─── */
const INVALID_TOKENS: { token: string; label: string }[] = [
    { token: "Bearer invalid-token-12345", label: "Random invalid token" },
    { token: "Bearer ", label: "Empty bearer value" },
    { token: "Bearer null", label: "Null bearer value" },
    { token: "bearer valid", label: "Lowercase bearer scheme" },
    { token: "Basic dGVzdDp0ZXN0", label: "Basic auth (test:test)" },
    { token: "Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyLCJyb2xlIjoiYWRtaW4ifQ.", label: "JWT with alg:none (admin)" },
    { token: "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIiwicm9sZSI6ImFkbWluIiwiaWF0IjoxfQ.invalid", label: "JWT with forged admin role" },
];

/* ─── Security Header Expectations ─── */
const EXPECTED_SECURITY_HEADERS: { header: string; label: string; severity: "MEDIUM" | "LOW" | "INFO" }[] = [
    { header: "x-content-type-options", label: "X-Content-Type-Options", severity: "MEDIUM" },
    { header: "x-frame-options", label: "X-Frame-Options", severity: "LOW" },
    { header: "strict-transport-security", label: "Strict-Transport-Security (HSTS)", severity: "MEDIUM" },
    { header: "x-xss-protection", label: "X-XSS-Protection", severity: "LOW" },
    { header: "content-security-policy", label: "Content-Security-Policy", severity: "LOW" },
    { header: "cache-control", label: "Cache-Control", severity: "INFO" },
];

export class AuthenticationCheck implements SecurityCheck {
    name = "Authentication & Security Headers Check";
    description = "Tests for missing/broken authentication, token bypass, JWT vulnerabilities, and security header misconfigurations";
    owaspMapping = "Broken Authentication";
    owaspId = "API2:2023";

    async run(target: ScanTarget): Promise<FindingResult[]> {
        const findings: FindingResult[] = [];

        for (const endpoint of target.endpoints) {
            const url = `${target.baseUrl}${endpoint.path}`;
            const method = endpoint.method.toLowerCase() as "get" | "post" | "put" | "delete" | "patch";

            /* ── Test 1: Unauthenticated Access ── */
            try {
                const requestHeaders: Record<string, string> = { "User-Agent": "SecuriScan/1.0", ...(endpoint.customHeaders || {}) };
                const requestConfig: Record<string, unknown> = {
                    requestsPerSecond: target.requestsPerSecond,
                    method,
                    url,
                    timeout: 10000,
                    validateStatus: () => true,
                    headers: requestHeaders,
                };
                if (endpoint.requestBody && ["post", "put", "patch"].includes(method)) {
                    try { requestConfig.data = JSON.parse(endpoint.requestBody); } catch { requestConfig.data = endpoint.requestBody; }
                    if (!requestHeaders["Content-Type"]) requestHeaders["Content-Type"] = "application/json";
                }
                const response = await scannerClient(requestConfig);

                if (response.status >= 200 && response.status < 300) {
                    const hasData = response.data && JSON.stringify(response.data).length > 2;
                    findings.push({
                        checkType: "authentication",
                        severity: hasData ? "HIGH" : "MEDIUM",
                        title: `No Authentication Required: ${endpoint.method} ${endpoint.path}`,
                        description: `The endpoint ${endpoint.method} ${endpoint.path} returned HTTP ${response.status} without any authentication credentials.${hasData ? " The response contains data, indicating the endpoint exposes resources to unauthenticated users." : ""} This violates the principle of least privilege.`,
                        evidence: this.buildEvidence(url, endpoint.method, {}, response),
                        owaspMapping: this.owaspMapping,
                        owaspId: this.owaspId,
                        remediation: `Implement authentication middleware:\n\n\`\`\`javascript\nconst authMiddleware = (req, res, next) => {\n  const token = req.headers.authorization?.split(' ')[1];\n  if (!token) return res.status(401).json({ error: 'Authentication required' });\n  try {\n    const decoded = jwt.verify(token, process.env.JWT_SECRET);\n    req.user = decoded;\n    next();\n  } catch (err) {\n    res.status(401).json({ error: 'Invalid or expired token' });\n  }\n};\n\napp.use('/api/', authMiddleware);\n\`\`\``,
                        endpoint: endpoint.path,
                        method: endpoint.method,
                    });
                }

                /* ── Test 2: Security Headers Audit ── */
                const missingHeaders = EXPECTED_SECURITY_HEADERS.filter(
                    (h) => !response.headers[h.header]
                );
                if (missingHeaders.length >= 3) {
                    findings.push({
                        checkType: "authentication",
                        severity: "MEDIUM",
                        title: `Missing Security Headers: ${endpoint.path}`,
                        description: `The endpoint is missing ${missingHeaders.length} security headers: ${missingHeaders.map((h) => h.label).join(", ")}. These headers protect against XSS, clickjacking, MIME sniffing, and downgrade attacks.`,
                        evidence: {
                            request: { url, method: endpoint.method, headers: {} },
                            response: {
                                status: response.status,
                                headers: response.headers as Record<string, string>,
                            },
                            description: `Missing security headers: ${missingHeaders.map((h) => h.header).join(", ")}`,
                        },
                        owaspMapping: "Security Misconfiguration",
                        owaspId: "API8:2023",
                        remediation: `Add security headers to all responses:\n\n\`\`\`javascript\nconst helmet = require('helmet');\napp.use(helmet());\n\n// Or manually:\napp.use((req, res, next) => {\n  res.setHeader('X-Content-Type-Options', 'nosniff');\n  res.setHeader('X-Frame-Options', 'DENY');\n  res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');\n  res.setHeader('Content-Security-Policy', "default-src 'self'");\n  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate');\n  next();\n});\n\`\`\``,
                        endpoint: endpoint.path,
                        method: endpoint.method,
                    });
                }
            } catch (err) {
                log.debug(`Auth check skipped for ${url}: ${err instanceof Error ? err.message : String(err)}`);
            }

            /* ── Test 3: Token Bypass / JWT Vulnerability Testing ── */
            for (const { token, label } of INVALID_TOKENS) {
                try {
                    const response = await scannerClient({
                        requestsPerSecond: target.requestsPerSecond,
                        method,
                        url,
                        timeout: 10000,
                        validateStatus: () => true,
                        headers: { Authorization: token, "User-Agent": "SecuriScan/1.0" },
                    });

                    if (response.status >= 200 && response.status < 300) {
                        const isJwtBypass = label.includes("JWT");
                        findings.push({
                            checkType: "authentication",
                            severity: isJwtBypass ? "CRITICAL" : "HIGH",
                            title: `Auth Bypass via ${label}: ${endpoint.method} ${endpoint.path}`,
                            description: `The endpoint accepted a request with "${label}" (Authorization: ${token.slice(0, 50)}...) and returned HTTP ${response.status}. ${isJwtBypass ? "This is a CRITICAL JWT vulnerability — the API accepts tokens with algorithm 'none' or fails to verify signatures, allowing complete authentication bypass." : "The endpoint does not properly validate authentication tokens, allowing unauthorized access."}`,
                            evidence: this.buildEvidence(url, endpoint.method, { Authorization: token }, response),
                            owaspMapping: this.owaspMapping,
                            owaspId: this.owaspId,
                            remediation: isJwtBypass
                                ? `CRITICAL: Fix JWT validation immediately:\n\n\`\`\`javascript\n// Always specify allowed algorithms explicitly\nconst decoded = jwt.verify(token, secret, {\n  algorithms: ['HS256', 'RS256'], // NEVER include 'none'\n  issuer: 'your-app',\n  audience: 'your-api',\n});\n\n// Validate token claims\nif (!decoded.sub || !decoded.role) {\n  throw new Error('Invalid token claims');\n}\n\`\`\``
                                : `Implement strict token validation:\n\n\`\`\`javascript\nif (!token || token === 'null' || token.trim() === '') {\n  return res.status(401).json({ error: 'Token required' });\n}\ntry {\n  const decoded = jwt.verify(token, secret, { algorithms: ['HS256'] });\n  req.user = decoded;\n} catch (err) {\n  return res.status(401).json({ error: 'Invalid token' });\n}\n\`\`\``,
                            endpoint: endpoint.path,
                            method: endpoint.method,
                        });
                        break; // One bypass is enough per endpoint
                    }
                } catch {
                    // Expected for blocked tokens
                }
            }

            /* ── Test 4: Privilege Escalation Probe ── */
            if (target.authConfig?.value) {
                try {
                    const adminPaths = [
                        endpoint.path.replace(/\/\d+$/, "/1"),
                        endpoint.path + "?admin=true",
                        endpoint.path + "?role=admin",
                    ];

                    for (const adminPath of adminPaths) {
                        const adminUrl = `${target.baseUrl}${adminPath}`;
                        const response = await scannerClient({
                            requestsPerSecond: target.requestsPerSecond,
                            method: "get",
                            url: adminUrl,
                            timeout: 10000,
                            validateStatus: () => true,
                            headers: {
                                Authorization: `Bearer ${target.authConfig.value}`,
                                "User-Agent": "SecuriScan/1.0",
                                "X-Forwarded-For": "127.0.0.1",
                            },
                        });

                        if (response.status >= 200 && response.status < 300) {
                            const body = JSON.stringify(response.data || "");
                            if (body.includes("admin") || body.includes("role") || body.includes("privilege")) {
                                findings.push({
                                    checkType: "authentication",
                                    severity: "HIGH",
                                    title: `Potential Privilege Escalation: ${adminPath}`,
                                    description: `The endpoint responds to a privilege escalation probe (${adminPath}) with data containing admin/role/privilege keywords. This may indicate insufficient authorization controls.`,
                                    evidence: this.buildEvidence(adminUrl, "GET", { "X-Forwarded-For": "127.0.0.1" }, response),
                                    owaspMapping: "Broken Function Level Authorization",
                                    owaspId: "API5:2023",
                                    remediation: `Never trust query parameters for authorization decisions. Always validate roles server-side:\n\n\`\`\`javascript\nconst requireAdmin = (req, res, next) => {\n  if (req.user.role !== 'admin') {\n    return res.status(403).json({ error: 'Admin access required' });\n  }\n  next();\n};\n\`\`\``,
                                    endpoint: adminPath,
                                    method: "GET",
                                });
                                break;
                            }
                        }
                    }
                } catch {
                    // Privilege escalation probe failed
                }
            }
        }

        return findings;
    }

    private buildEvidence(url: string, method: string, headers: Record<string, string>, response: AxiosResponse): Evidence {
        return {
            request: { url, method, headers },
            response: {
                status: response.status,
                headers: response.headers as Record<string, string>,
                body: typeof response.data === "object" ? response.data : String(response.data).slice(0, 500),
            },
            description: `Sent ${method} request to ${url}`,
        };
    }
}
