import { AxiosResponse } from "axios";
import { scannerClient } from "@/server/core/http/scanner-client";
import { SecurityCheck, ScanTarget, FindingResult, Evidence } from "@/types";
import { logger } from "@/server/core/logging/logger";

const log = logger.child("error-leak-check");

/* ─── Error Pattern Matching ─── */
const ERROR_PATTERNS: { pattern: RegExp; label: string; criticality: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" }[] = [
    // Database
    { pattern: /SQLSTATE|SQL syntax|mysql_|pg_query|ORA-\d+|sqlite_|Microsoft OLE DB/i, label: "SQL error details", criticality: "CRITICAL" },
    { pattern: /database|DB_HOST|DB_PASSWORD|connection.?string/i, label: "Database connection details", criticality: "CRITICAL" },
    { pattern: /table .+ doesn't exist|relation .+ does not exist/i, label: "Database schema leak", criticality: "HIGH" },
    { pattern: /mongodb|mongoose|MongoError/i, label: "MongoDB error details", criticality: "HIGH" },
    { pattern: /redis|REDIS_URL|ioredis/i, label: "Redis details", criticality: "HIGH" },

    // Stack Traces
    { pattern: /at\s+\w+\s+\(.*:\d+:\d+\)/i, label: "Node.js stack trace", criticality: "HIGH" },
    { pattern: /Traceback \(most recent call last\)/i, label: "Python traceback", criticality: "HIGH" },
    { pattern: /java\.lang\.\w+Exception/i, label: "Java exception", criticality: "HIGH" },
    { pattern: /System\.(?:NullReferenceException|ArgumentException|InvalidOperationException)/i, label: ".NET exception", criticality: "HIGH" },
    { pattern: /goroutine \d+ \[running\]/i, label: "Go panic trace", criticality: "HIGH" },
    { pattern: /PHP (?:Fatal|Warning|Notice|Parse) error/i, label: "PHP error", criticality: "HIGH" },

    // File System
    { pattern: /\/home\/\w+|\/var\/\w+|\/usr\/\w+|C:\\\\[Uu]sers|\/app\/|\/opt\//i, label: "File system paths", criticality: "HIGH" },
    { pattern: /node_modules/i, label: "node_modules paths", criticality: "MEDIUM" },
    { pattern: /\.env|dotenv|process\.env/i, label: "Environment variable references", criticality: "CRITICAL" },

    // JavaScript Errors
    { pattern: /TypeError|ReferenceError|SyntaxError|RangeError|EvalError/i, label: "JavaScript runtime error", criticality: "MEDIUM" },
    { pattern: /UnhandledPromiseRejectionWarning/i, label: "Unhandled promise rejection", criticality: "MEDIUM" },

    // Secrets & Config
    { pattern: /SECRET_KEY|JWT_SECRET|ENCRYPTION_KEY/i, label: "Secret/encryption key reference", criticality: "CRITICAL" },
    { pattern: /AWS_ACCESS_KEY|AWS_SECRET|AZURE_|GCP_/i, label: "Cloud credential reference", criticality: "CRITICAL" },
    { pattern: /smtp|MAIL_PASSWORD|email.?password/i, label: "Email/SMTP credentials", criticality: "HIGH" },

    // Versioning
    { pattern: /express|django|flask|laravel|spring|rails/i, label: "Framework name disclosure", criticality: "LOW" },
    { pattern: /version.?\d+\.\d+/i, label: "Version number disclosure", criticality: "LOW" },

    // Debug
    { pattern: /debug|DEBUG|stackTrace|stack_trace/i, label: "Debug information", criticality: "MEDIUM" },
    { pattern: /internal server error/i, label: "Generic server error", criticality: "LOW" },
];

/* ─── Advanced Fuzzing Payloads ─── */
const MALFORMED_PAYLOADS: { path: string; type: string; method: string; body?: unknown; contentType?: string }[] = [
    // Path-based
    { path: "/<script>alert(1)</script>", type: "XSS probe", method: "GET" },
    { path: "/undefined", type: "Undefined path", method: "GET" },
    { path: "/null", type: "Null path", method: "GET" },
    { path: "/' OR 1=1 --", type: "SQL injection (single quote)", method: "GET" },
    { path: '/"; DROP TABLE users; --', type: "SQL injection (double quote)", method: "GET" },
    { path: "/../../../etc/passwd", type: "Path traversal (Linux)", method: "GET" },
    { path: "/..\\..\\..\\windows\\system.ini", type: "Path traversal (Windows)", method: "GET" },
    { path: "/999999999", type: "Invalid ID overflow", method: "GET" },
    { path: "/-1", type: "Negative ID", method: "GET" },
    { path: "/0", type: "Zero ID", method: "GET" },
    { path: "/%00", type: "Null byte injection", method: "GET" },
    { path: "/%0d%0aX-Injected: true", type: "CRLF injection", method: "GET" },
    { path: "/{{7*7}}", type: "Server-Side Template Injection (SSTI)", method: "GET" },
    { path: "/${7*7}", type: "Expression injection", method: "GET" },
    { path: "/?__proto__[admin]=1", type: "Prototype pollution", method: "GET" },

    // Body-based
    { path: "", type: "Malformed JSON body", method: "POST", body: "{invalid json}", contentType: "application/json" },
    { path: "", type: "XML bomb probe", method: "POST", body: '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe "test">]><foo>&xxe;</foo>', contentType: "application/xml" },
    { path: "", type: "Empty body to POST", method: "POST", body: "", contentType: "application/json" },
    { path: "", type: "Oversized field", method: "POST", body: JSON.stringify({ data: "A".repeat(10000) }), contentType: "application/json" },
];

export class ErrorLeakCheck implements SecurityCheck {
    name = "Error Leakage & Information Disclosure Check";
    description = "Tests for verbose error messages, stack trace exposure, server fingerprinting, injection error responses, and debug information leakage";
    owaspMapping = "Security Misconfiguration";
    owaspId = "API8:2023";

    async run(target: ScanTarget): Promise<FindingResult[]> {
        const findings: FindingResult[] = [];
        const seenPatterns = new Set<string>(); // Dedup findings

        for (const payload of MALFORMED_PAYLOADS) {
            try {
                const basePath = target.endpoints[0]?.path?.split("/").slice(0, -1).join("/") || "/api";
                const url = `${target.baseUrl}${basePath}${payload.path}`;

                const config: Record<string, unknown> = {
                    requestsPerSecond: target.requestsPerSecond,
                    method: payload.method.toLowerCase(),
                    url,
                    timeout: 10000,
                    validateStatus: () => true,
                    headers: {
                        "User-Agent": "SecuriScan/1.0",
                        ...(payload.contentType ? { "Content-Type": payload.contentType } : {}),
                    },
                };

                if (payload.body !== undefined) {
                    config.data = payload.body;
                }

                const response = await scannerClient(config);

                if (response.status >= 400) {
                    const responseStr = typeof response.data === "string"
                        ? response.data
                        : JSON.stringify(response.data || "");

                    const detectedPatterns: { label: string; criticality: string }[] = [];
                    for (const { pattern, label, criticality } of ERROR_PATTERNS) {
                        const dedupKey = `${label}:${basePath}`;
                        if (pattern.test(responseStr) && !seenPatterns.has(dedupKey)) {
                            detectedPatterns.push({ label, criticality });
                            seenPatterns.add(dedupKey);
                        }
                    }

                    if (detectedPatterns.length > 0) {
                        const hasCritical = detectedPatterns.some((p) => p.criticality === "CRITICAL");
                        const hasHigh = detectedPatterns.some((p) => p.criticality === "HIGH");

                        findings.push({
                            checkType: "error_leakage",
                            severity: hasCritical ? "CRITICAL" : hasHigh ? "HIGH" : "MEDIUM",
                            title: `Error Leakage via ${payload.type}`,
                            description: `Sending a ${payload.type} probe triggered an error response (HTTP ${response.status}) that leaks ${detectedPatterns.length} type(s) of internal information: ${detectedPatterns.map((p) => `${p.label} (${p.criticality})`).join(", ")}. Attackers can use this for reconnaissance to discover database technologies, framework versions, file paths, and infrastructure details.`,
                            evidence: this.buildEvidence(url, payload.method, response, detectedPatterns.map((p) => p.label), payload.type),
                            owaspMapping: this.owaspMapping,
                            owaspId: this.owaspId,
                            remediation: `Implement global error handling with sanitized responses:\n\n\`\`\`javascript\n// Global error handler\napp.use((err, req, res, next) => {\n  // Log full error internally\n  logger.error({ err, url: req.url, method: req.method });\n\n  // Return sanitized response\n  const statusCode = err.status || 500;\n  res.status(statusCode).json({\n    error: statusCode === 500 ? 'Internal server error' : err.message,\n    requestId: req.id, // For support reference only\n    // NEVER include: stack, path, query, database details\n  });\n});\n\n// Environment-specific config\nif (process.env.NODE_ENV === 'production') {\n  app.set('env', 'production');\n  app.disable('x-powered-by');\n}\n\`\`\``,
                            endpoint: payload.path || basePath,
                            method: payload.method,
                        });
                    }
                }

                /* ── Test: SSTI Detection ── */
                if (payload.type.includes("SSTI") || payload.type.includes("Expression")) {
                    const responseStr = typeof response.data === "string" ? response.data : JSON.stringify(response.data || "");
                    if (responseStr.includes("49")) {
                        findings.push({
                            checkType: "error_leakage",
                            severity: "CRITICAL",
                            title: `Server-Side Template Injection (SSTI): ${basePath}${payload.path}`,
                            description: `The expression "{{7*7}}" or "\${7*7}" was evaluated server-side (response contains "49"). This indicates a critical SSTI vulnerability allowing Remote Code Execution (RCE).`,
                            evidence: this.buildEvidence(url, "GET", response, ["SSTI — RCE possible"], payload.type),
                            owaspMapping: "Security Misconfiguration",
                            owaspId: "API8:2023",
                            remediation: `Never pass user input directly into template engines:\n\n\`\`\`javascript\n// DANGEROUS:\nres.render('page', { title: req.query.input });\n\n// SAFE: Sanitize and validate all user input\nconst sanitized = escapeHtml(req.query.input);\nres.render('page', { title: sanitized });\n\`\`\``,
                            endpoint: payload.path,
                            method: "GET",
                        });
                    }
                }
            } catch (err) {
                log.debug(`Error leak probe skipped for ${payload.type}: ${err instanceof Error ? err.message : String(err)}`);
            }
        }

        /* ── Server Fingerprinting via OPTIONS ── */
        try {
            const baseUrl = target.baseUrl;
            const response = await scannerClient({
                requestsPerSecond: target.requestsPerSecond,
                method: "options",
                url: baseUrl,
                timeout: 10000,
                validateStatus: () => true,
                headers: { "User-Agent": "SecuriScan/1.0" },
            });

            const serverHeader = response.headers["server"];
            const poweredBy = response.headers["x-powered-by"];

            if (serverHeader || poweredBy) {
                findings.push({
                    checkType: "error_leakage",
                    severity: "LOW",
                    title: "Server Technology Fingerprint Detected",
                    description: `The server reveals its technology stack via response headers: ${serverHeader ? `Server: ${serverHeader}` : ""}${poweredBy ? ` X-Powered-By: ${poweredBy}` : ""}. Attackers use this to find known CVEs for the specific server version.`,
                    evidence: {
                        request: { url: baseUrl, method: "OPTIONS", headers: {} },
                        response: {
                            status: response.status,
                            headers: {
                                ...(serverHeader ? { server: serverHeader } : {}),
                                ...(poweredBy ? { "x-powered-by": poweredBy } : {}),
                            },
                        },
                        description: `Server fingerprint: ${serverHeader || ""} ${poweredBy || ""}`,
                    },
                    owaspMapping: this.owaspMapping,
                    owaspId: this.owaspId,
                    remediation: `Remove revealing headers:\n\n\`\`\`javascript\napp.disable('x-powered-by');\n\n// Nginx: server_tokens off;\n// Apache: ServerTokens Prod\n\`\`\``,
                    endpoint: "/",
                    method: "OPTIONS",
                });
            }
        } catch {
            // Skip
        }

        return findings;
    }

    private buildEvidence(url: string, method: string, response: AxiosResponse, patterns: string[], payloadType: string): Evidence {
        const body = typeof response.data === "object" ? response.data : String(response.data).slice(0, 1500);
        return {
            request: { url, method, headers: { "User-Agent": "SecuriScan/1.0" } },
            response: {
                status: response.status,
                headers: response.headers as Record<string, string>,
                body,
            },
            description: `${payloadType} triggered error leaking: ${patterns.join(", ")}`,
            payload: url,
        };
    }
}
