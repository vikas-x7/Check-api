import { AxiosResponse } from "axios";
import { scannerClient } from "@/server/core/http/scanner-client";
import { SecurityCheck, ScanTarget, FindingResult, Evidence } from "@/types";
import { logger } from "@/server/core/logging/logger";

const log = logger.child("data-exposure-check");

/* ─── Sensitive Field Name Patterns ─── */
const SENSITIVE_FIELD_PATTERNS: { pattern: RegExp; label: string; criticality: "CRITICAL" | "HIGH" | "MEDIUM" }[] = [
    // Credentials & Secrets
    { pattern: /password/i, label: "password", criticality: "CRITICAL" },
    { pattern: /passwd/i, label: "passwd", criticality: "CRITICAL" },
    { pattern: /secret/i, label: "secret", criticality: "CRITICAL" },
    { pattern: /private[_-]?key/i, label: "private key", criticality: "CRITICAL" },
    { pattern: /api[_-]?key/i, label: "API key", criticality: "CRITICAL" },
    { pattern: /access[_-]?key/i, label: "access key", criticality: "CRITICAL" },

    // Authentication Tokens
    { pattern: /token(?!_type)/i, label: "token", criticality: "HIGH" },
    { pattern: /session[_-]?id/i, label: "session ID", criticality: "HIGH" },
    { pattern: /refresh[_-]?token/i, label: "refresh token", criticality: "CRITICAL" },

    // Personal Identifiable Information (PII)
    { pattern: /ssn|social.?security/i, label: "SSN", criticality: "CRITICAL" },
    { pattern: /credit.?card|card.?number|pan/i, label: "credit card number", criticality: "CRITICAL" },
    { pattern: /cvv|cvc|security.?code/i, label: "card CVV", criticality: "CRITICAL" },
    { pattern: /date.?of.?birth|dob/i, label: "date of birth", criticality: "HIGH" },
    { pattern: /passport.?number/i, label: "passport number", criticality: "CRITICAL" },
    { pattern: /driver.?license/i, label: "driver license", criticality: "CRITICAL" },
    { pattern: /bank.?account/i, label: "bank account", criticality: "CRITICAL" },
    { pattern: /routing.?number/i, label: "routing number", criticality: "HIGH" },

    // Infrastructure
    { pattern: /salt/i, label: "salt value", criticality: "HIGH" },
    { pattern: /hash(?!map|set|table)/i, label: "hash value", criticality: "MEDIUM" },
    { pattern: /internal[_-]?id/i, label: "internal ID", criticality: "MEDIUM" },
    { pattern: /connection.?string/i, label: "connection string", criticality: "CRITICAL" },
    { pattern: /db[_-]?password/i, label: "database password", criticality: "CRITICAL" },
];

/* ─── Sensitive Value Patterns ─── */
const SENSITIVE_VALUE_PATTERNS: { pattern: RegExp; label: string; criticality: "CRITICAL" | "HIGH" | "MEDIUM" }[] = [
    { pattern: /\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}/, label: "bcrypt hash", criticality: "HIGH" },
    { pattern: /eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/, label: "JWT token", criticality: "CRITICAL" },
    { pattern: /[a-f0-9]{64}/, label: "SHA-256 hash", criticality: "MEDIUM" },
    { pattern: /sk_live_[a-zA-Z0-9]{24,}/, label: "Stripe secret key", criticality: "CRITICAL" },
    { pattern: /AKIA[0-9A-Z]{16}/, label: "AWS Access Key ID", criticality: "CRITICAL" },
    { pattern: /AIza[0-9A-Za-z_-]{35}/, label: "Google API key", criticality: "CRITICAL" },
    { pattern: /ghp_[a-zA-Z0-9]{36}/, label: "GitHub personal token", criticality: "CRITICAL" },
    { pattern: /xox[bspra]-[a-zA-Z0-9-]+/, label: "Slack token", criticality: "HIGH" },
];

/* ─── PII Value Patterns ─── */
const PII_VALUE_PATTERNS: { pattern: RegExp; label: string }[] = [
    { pattern: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/, label: "email address" },
    { pattern: /\b\d{3}[-.]?\d{2}[-.]?\d{4}\b/, label: "potential SSN" },
    { pattern: /\b(?:\d{4}[-\s]?){3}\d{4}\b/, label: "potential credit card number" },
    { pattern: /\b\+?1?[-.\s]?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b/, label: "phone number" },
    { pattern: /\b(?:\d{1,3}\.){3}\d{1,3}\b/, label: "IPv4 address" },
];

/* ─── Response Header Leaks ─── */
const LEAKY_HEADERS: { header: string; label: string }[] = [
    { header: "server", label: "Server version" },
    { header: "x-powered-by", label: "X-Powered-By framework" },
    { header: "x-aspnet-version", label: "ASP.NET version" },
    { header: "x-aspnetmvc-version", label: "ASP.NET MVC version" },
    { header: "x-debug-token", label: "Debug token" },
    { header: "x-debug-token-link", label: "Debug token link" },
];

export class DataExposureCheck implements SecurityCheck {
    name = "Data Exposure & PII Leak Check";
    description = "Detects sensitive data exposure, PII leaks, credential exposure, and information leakage in API responses and headers";
    owaspMapping = "Broken Object Property Level Authorization";
    owaspId = "API3:2023";

    async run(target: ScanTarget): Promise<FindingResult[]> {
        const findings: FindingResult[] = [];

        for (const endpoint of target.endpoints) {

            const url = `${target.baseUrl}${endpoint.path}`;
            try {
                const headers: Record<string, string> = { "User-Agent": "SecuriScan/1.0", ...(endpoint.customHeaders || {}) };

                if (target.authConfig?.value) {
                    if (target.authConfig.type === "bearer" || target.authConfig.type === "jwt") {
                        headers["Authorization"] = `Bearer ${target.authConfig.value}`;
                    } else if (target.authConfig.type === "api_key") {
                        headers[target.authConfig.headerName || "X-API-Key"] = target.authConfig.value;
                    }
                }

                // eslint-disable-next-line @typescript-eslint/no-explicit-any
                const requestConfig: any = {
                    requestsPerSecond: target.requestsPerSecond,
                    method: endpoint.method.toLowerCase(),
                    url,
                    timeout: 10000,
                    validateStatus: () => true,
                    headers,
                };

                if (endpoint.requestBody && ["post", "put", "patch"].includes(endpoint.method.toLowerCase())) {
                    try { requestConfig.data = JSON.parse(endpoint.requestBody); } catch { requestConfig.data = endpoint.requestBody; }
                    if (!headers["Content-Type"]) headers["Content-Type"] = "application/json";
                }

                const response = await scannerClient(requestConfig);

                if (response.status >= 200 && response.status < 300 && response.data) {
                    const responseStr = JSON.stringify(response.data);

                    /* ── Test 1: Sensitive Field Name Detection ── */
                    const exposedFields: { label: string; criticality: string }[] = [];
                    for (const { pattern, label, criticality } of SENSITIVE_FIELD_PATTERNS) {
                        if (pattern.test(responseStr)) {
                            exposedFields.push({ label, criticality });
                        }
                    }

                    /* ── Test 2: Sensitive Value Pattern Detection ── */
                    const exposedValues: { label: string; criticality: string }[] = [];
                    for (const { pattern, label, criticality } of SENSITIVE_VALUE_PATTERNS) {
                        if (pattern.test(responseStr)) {
                            exposedValues.push({ label, criticality });
                        }
                    }

                    /* ── Test 3: PII Detection ── */
                    const piiFound: string[] = [];
                    for (const { pattern, label } of PII_VALUE_PATTERNS) {
                        if (pattern.test(responseStr)) {
                            piiFound.push(label);
                        }
                    }

                    /* ── Emit Finding: Sensitive Fields ── */
                    if (exposedFields.length > 0 || exposedValues.length > 0) {
                        const allExposed = [...exposedFields, ...exposedValues];
                        const hasCritical = allExposed.some((e) => e.criticality === "CRITICAL");
                        const hasHigh = allExposed.some((e) => e.criticality === "HIGH");

                        findings.push({
                            checkType: "data_exposure",
                            severity: hasCritical ? "CRITICAL" : hasHigh ? "HIGH" : "MEDIUM",
                            title: `Sensitive Data Exposure: ${endpoint.path}`,
                            description: `The endpoint exposes ${allExposed.length} sensitive field(s)/value(s) in its response: ${allExposed.map((e) => `${e.label} (${e.criticality})`).join(", ")}. This data must be filtered before being sent to the client. ${hasCritical ? "CRITICAL items such as passwords, API keys, or financial data require immediate remediation." : ""}`,
                            evidence: this.buildEvidence(url, headers, response, allExposed.map((e) => e.label)),
                            owaspMapping: this.owaspMapping,
                            owaspId: this.owaspId,
                            remediation: `Implement a DTO/serialization layer to filter sensitive fields:\n\n\`\`\`javascript\n// NEVER return raw database objects\nconst sanitized = {\n  id: user.id,\n  name: user.name,\n  email: user.email,\n  // EXCLUDE: password, hash, salt, token, internal_id, ssn, etc.\n};\nres.json(sanitized);\n\n// Use field-level access control:\nconst publicFields = ['id', 'name', 'email', 'avatar'];\nconst result = pick(user, publicFields);\n\`\`\``,
                            endpoint: endpoint.path,
                            method: endpoint.method,
                        });
                    }

                    /* ── Emit Finding: PII Leak ── */
                    if (piiFound.length > 0) {
                        findings.push({
                            checkType: "data_exposure",
                            severity: "HIGH",
                            title: `PII Data Leak: ${endpoint.path}`,
                            description: `The endpoint response contains Personally Identifiable Information (PII): ${piiFound.join(", ")}. Exposing PII violates GDPR, CCPA, and similar data protection regulations and can lead to identity theft.`,
                            evidence: {
                                request: { url, method: endpoint.method, headers },
                                response: {
                                    status: response.status,
                                    headers: response.headers as Record<string, string>,
                                },
                                description: `PII detected in response: ${piiFound.join(", ")}`,
                            },
                            owaspMapping: this.owaspMapping,
                            owaspId: this.owaspId,
                            remediation: `Mask or encrypt PII in API responses:\n\n\`\`\`javascript\n// Mask sensitive values\nfunction maskEmail(email) {\n  const [name, domain] = email.split('@');\n  return name[0] + '***@' + domain;\n}\n\nfunction maskSSN(ssn) {\n  return '***-**-' + ssn.slice(-4);\n}\n\n// Apply data classification policies\nres.json({\n  email: maskEmail(user.email),\n  phone: '***' + user.phone.slice(-4),\n});\n\`\`\``,
                            endpoint: endpoint.path,
                            method: endpoint.method,
                        });
                    }

                    /* ── Test 4: Excessive Response Size ── */
                    const responseSize = responseStr.length;
                    if (responseSize > 50_000) {
                        findings.push({
                            checkType: "data_exposure",
                            severity: "MEDIUM",
                            title: `Excessive Response Size: ${endpoint.path}`,
                            description: `The endpoint returned ${(responseSize / 1024).toFixed(1)}KB of data. Large responses often indicate the API returns entire database records without pagination or field filtering, increasing the risk of data leakage.`,
                            evidence: {
                                request: { url, method: endpoint.method, headers },
                                response: {
                                    status: response.status,
                                    headers: response.headers as Record<string, string>,
                                    body: { responseSize, sizeKB: `${(responseSize / 1024).toFixed(1)}KB` },
                                },
                                description: `Excessive response: ${(responseSize / 1024).toFixed(1)}KB`,
                            },
                            owaspMapping: "Unrestricted Resource Consumption",
                            owaspId: "API4:2023",
                            remediation: `Implement pagination and field selection:\n\n\`\`\`javascript\napp.get('/api/items', (req, res) => {\n  const page = parseInt(req.query.page) || 1;\n  const limit = Math.min(parseInt(req.query.limit) || 20, 100);\n  const fields = req.query.fields?.split(',');\n  \n  const items = await Item.findAll({ offset: (page-1)*limit, limit });\n  const result = fields ? items.map(i => pick(i, fields)) : items;\n  res.json({ data: result, page, limit, total });\n});\n\`\`\``,
                            endpoint: endpoint.path,
                            method: endpoint.method,
                        });
                    }

                    /* ── Test 5: Deep Object Traversal (nested sensitive data) ── */
                    if (typeof response.data === "object") {
                        const nestedSensitive = this.findDeepSensitiveKeys(response.data, 4);
                        if (nestedSensitive.length > 0 && !exposedFields.some((e) => nestedSensitive.includes(e.label))) {
                            findings.push({
                                checkType: "data_exposure",
                                severity: "MEDIUM",
                                title: `Nested Sensitive Data: ${endpoint.path}`,
                                description: `Deep inspection of the response reveals sensitive keys buried in nested objects: ${nestedSensitive.join(", ")}. This data may be accidentally included through ORM population or nested serialization.`,
                                evidence: {
                                    request: { url, method: endpoint.method, headers },
                                    response: { status: response.status, headers: {} },
                                    description: `Nested sensitive keys: ${nestedSensitive.join(", ")}`,
                                },
                                owaspMapping: this.owaspMapping,
                                owaspId: this.owaspId,
                                remediation: `Use explicit serialization to prevent nested data leaks:\n\n\`\`\`javascript\n// Use a serializer that does NOT deep-include related objects\nconst result = serialize(user, {\n  include: ['id', 'name', 'email'],\n  exclude: ['password', 'sessions', 'tokens'],\n  depth: 1, // Prevent deep nesting\n});\n\`\`\``,
                                endpoint: endpoint.path,
                                method: endpoint.method,
                            });
                        }
                    }
                }

                /* ── Test 6: Response Header Information Leakage ── */
                const leakedHeaders: { header: string; value: string; label: string }[] = [];
                for (const { header, label } of LEAKY_HEADERS) {
                    const val = response.headers[header];
                    if (val) leakedHeaders.push({ header, value: val, label });
                }

                if (leakedHeaders.length > 0) {
                    findings.push({
                        checkType: "data_exposure",
                        severity: "LOW",
                        title: `Information Leakage via Headers: ${endpoint.path}`,
                        description: `The response headers reveal server infrastructure details: ${leakedHeaders.map((h) => `${h.label} (${h.header}: ${h.value})`).join(", ")}. Attackers use this to fingerprint the technology stack and find known vulnerabilities.`,
                        evidence: {
                            request: { url, method: endpoint.method, headers },
                            response: {
                                status: response.status,
                                headers: Object.fromEntries(leakedHeaders.map((h) => [h.header, h.value])),
                            },
                            description: `Leaky headers: ${leakedHeaders.map((h) => h.header).join(", ")}`,
                        },
                        owaspMapping: "Security Misconfiguration",
                        owaspId: "API8:2023",
                        remediation: `Remove version/debug headers in production:\n\n\`\`\`javascript\napp.disable('x-powered-by');\n\n// Or use helmet:\nconst helmet = require('helmet');\napp.use(helmet.hidePoweredBy());\n\n// Nginx:\nserver_tokens off;\n\`\`\``,
                        endpoint: endpoint.path,
                        method: endpoint.method,
                    });
                }
            } catch (err) {
                log.debug(`Data exposure check skipped for ${url}: ${err instanceof Error ? err.message : String(err)}`);
            }
        }

        return findings;
    }

    private buildEvidence(url: string, headers: Record<string, string>, response: AxiosResponse, exposed: string[]): Evidence {
        return {
            request: { url, method: "GET", headers },
            response: {
                status: response.status,
                headers: response.headers as Record<string, string>,
                body: typeof response.data === "object" ? response.data : String(response.data).slice(0, 1000),
            },
            description: `Response contains sensitive data: ${exposed.join(", ")}`,
        };
    }

    /** Recursively searches for sensitive key names in nested objects */
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    private findDeepSensitiveKeys(obj: any, maxDepth: number, depth = 0): string[] {
        if (depth >= maxDepth || !obj || typeof obj !== "object") return [];
        const found: string[] = [];
        const keys = Array.isArray(obj) ? [] : Object.keys(obj);

        for (const key of keys) {
            const lower = key.toLowerCase();
            if (["password", "secret", "token", "private_key", "api_key", "ssn", "credit_card"].some((s) => lower.includes(s))) {
                found.push(key);
            }
            found.push(...this.findDeepSensitiveKeys(obj[key], maxDepth, depth + 1));
        }
        return [...new Set(found)];
    }
}
