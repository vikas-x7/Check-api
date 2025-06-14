import { scannerClient } from "@/server/core/http/scanner-client";
import { SecurityCheck, ScanTarget, FindingResult } from "@/types";
import { logger } from "@/server/core/logging/logger";

const log = logger.child("cors-check");

/* ─── Comprehensive CORS Test Origins ─── */
const TEST_ORIGINS: { origin: string; label: string; severity: "CRITICAL" | "HIGH" | "MEDIUM" }[] = [
    { origin: "https://evil.com", label: "Arbitrary malicious domain", severity: "HIGH" },
    { origin: "https://attacker.example.com", label: "Attacker-controlled domain", severity: "HIGH" },
    { origin: "null", label: "Null origin (sandboxed iframe, data URI)", severity: "CRITICAL" },
    { origin: "https://evil.target.com", label: "Subdomain impersonation", severity: "HIGH" },
    { origin: "https://target.com.evil.com", label: "Suffix-based domain bypass", severity: "HIGH" },
    { origin: "https://not-target.com", label: "Similar domain name", severity: "HIGH" },
    { origin: "http://localhost", label: "Localhost origin (development bypass)", severity: "MEDIUM" },
    { origin: "http://127.0.0.1", label: "Loopback IP origin", severity: "MEDIUM" },
];

/* ─── Dangerous Methods & Headers ─── */
const DANGEROUS_PREFLIGHT_METHODS = ["PUT", "DELETE", "PATCH"];
const DANGEROUS_PREFLIGHT_HEADERS = ["X-Custom-Header", "X-Forwarded-For", "X-Api-Key"];

export class CorsCheck implements SecurityCheck {
    name = "CORS Misconfiguration Check";
    description = "Tests for CORS misconfigurations including wildcard origins, origin reflection, null origin, credential exposure, and preflight abuse";
    owaspMapping = "Security Misconfiguration";
    owaspId = "API8:2023";

    async run(target: ScanTarget): Promise<FindingResult[]> {
        const findings: FindingResult[] = [];

        // Test on a diverse subset of endpoints (GET and POST)
        const testEndpoints = target.endpoints
            .filter((ep) => ["GET", "POST"].includes(ep.method.toUpperCase()))
            .slice(0, 6);

        for (const endpoint of testEndpoints) {
            const url = `${target.baseUrl}${endpoint.path}`;

            /* ── Test 1: Wildcard Origin with Credentials ── */
            try {
                const response = await scannerClient({
                    requestsPerSecond: target.requestsPerSecond,
                    method: "options",
                    url,
                    timeout: 10000,
                    validateStatus: () => true,
                    headers: {
                        Origin: "https://evil.com",
                        "Access-Control-Request-Method": "GET",
                        "User-Agent": "SecuriScan/1.0",
                    },
                });

                const acao = response.headers["access-control-allow-origin"];
                const acac = response.headers["access-control-allow-credentials"];
                const acam = response.headers["access-control-allow-methods"];

                const acma = response.headers["access-control-max-age"];

                /* Wildcard + Credentials = Critical browser bypass */
                if (acao === "*") {
                    const severity = acac === "true" ? "CRITICAL" : "HIGH";
                    findings.push({
                        checkType: "cors_misconfiguration",
                        severity,
                        title: `CORS Wildcard Origin${acac === "true" ? " + Credentials" : ""}: ${endpoint.path}`,
                        description: `The endpoint returns Access-Control-Allow-Origin: * which permits any website to make cross-origin requests.${acac === "true" ? " Combined with Access-Control-Allow-Credentials: true, cookies and authorization headers are sent with cross-origin requests. This is a CRITICAL attack vector for credential theft via malicious websites." : " Although credentials are not included, sensitive data may still be exfiltrated."}`,
                        evidence: {
                            request: { url, method: "OPTIONS", headers: { Origin: "https://evil.com", "Access-Control-Request-Method": "GET" } },
                            response: {
                                status: response.status,
                                headers: this.filterCorsHeaders(response),
                            },
                            description: `Wildcard ACAO${acac === "true" ? " with credentials" : ""}`,
                        },
                        owaspMapping: this.owaspMapping,
                        owaspId: this.owaspId,
                        remediation: `Configure CORS strictly:\n\n\`\`\`javascript\nconst allowedOrigins = ['https://yourdomain.com'];\n\napp.use(cors({\n  origin: (origin, callback) => {\n    if (!origin || allowedOrigins.includes(origin)) {\n      callback(null, true);\n    } else {\n      callback(new Error('Not allowed by CORS'));\n    }\n  },\n  credentials: true,\n  methods: ['GET', 'POST'],\n  allowedHeaders: ['Content-Type', 'Authorization'],\n  maxAge: 86400,\n}));\n\`\`\``,
                        endpoint: endpoint.path,
                        method: "OPTIONS",
                    });
                }

                /* Overly permissive methods */
                if (acam && this.hasAllDangerousMethods(acam)) {
                    findings.push({
                        checkType: "cors_misconfiguration",
                        severity: "MEDIUM",
                        title: `CORS Overly Permissive Methods: ${endpoint.path}`,
                        description: `The CORS preflight response allows all dangerous HTTP methods (${acam}). This may enable cross-origin DELETE, PUT, or PATCH attacks from a malicious site.`,
                        evidence: {
                            request: { url, method: "OPTIONS", headers: { Origin: "https://evil.com" } },
                            response: {
                                status: response.status,
                                headers: { "access-control-allow-methods": acam },
                            },
                            description: `Permissive CORS methods: ${acam}`,
                        },
                        owaspMapping: this.owaspMapping,
                        owaspId: this.owaspId,
                        remediation: `Only allow the specific methods each endpoint needs:\n\n\`\`\`javascript\napp.use(cors({\n  methods: ['GET', 'POST'], // Only what's needed\n}));\n\`\`\``,
                        endpoint: endpoint.path,
                        method: "OPTIONS",
                    });
                }

                /* Excessive max-age */
                if (acma && parseInt(acma) > 86400) {
                    findings.push({
                        checkType: "cors_misconfiguration",
                        severity: "LOW",
                        title: `CORS Excessive Preflight Cache: ${endpoint.path}`,
                        description: `The Access-Control-Max-Age is set to ${acma} seconds (${Math.round(parseInt(acma) / 3600)} hours). A very long preflight cache makes it harder to revoke CORS policy changes.`,
                        evidence: {
                            request: { url, method: "OPTIONS", headers: {} },
                            response: {
                                status: response.status,
                                headers: { "access-control-max-age": acma },
                            },
                            description: `Excessive preflight max-age: ${acma}s`,
                        },
                        owaspMapping: this.owaspMapping,
                        owaspId: this.owaspId,
                        remediation: `Set a reasonable max-age (e.g., 1 hour):\n\n\`\`\`javascript\napp.use(cors({ maxAge: 3600 }));\n\`\`\``,
                        endpoint: endpoint.path,
                        method: "OPTIONS",
                    });
                }
            } catch (err) {
                log.debug(`CORS wildcard test skipped for ${url}: ${err instanceof Error ? err.message : String(err)}`);
            }

            /* ── Test 2: Origin Reflection Testing ── */
            for (const { origin, label, severity } of TEST_ORIGINS) {
                try {
                    const response = await scannerClient({
                        requestsPerSecond: target.requestsPerSecond,
                        method: "get",
                        url,
                        timeout: 10000,
                        validateStatus: () => true,
                        headers: { Origin: origin, "User-Agent": "SecuriScan/1.0" },
                    });

                    const reflected = response.headers["access-control-allow-origin"];
                    const creds = response.headers["access-control-allow-credentials"];

                    if (reflected === origin && origin !== "*") {
                        findings.push({
                            checkType: "cors_misconfiguration",
                            severity: creds === "true" ? "CRITICAL" : severity,
                            title: `CORS Origin Reflection (${label}): ${endpoint.path}`,
                            description: `The API reflects the attacker Origin "${origin}" (${label}) in the Access-Control-Allow-Origin header.${creds === "true" ? " With credentials enabled, an attacker's website can make authenticated requests on behalf of the victim user, stealing sensitive data." : " This allows the attacker origin to read API responses cross-origin."}`,
                            evidence: {
                                request: { url, method: "GET", headers: { Origin: origin } },
                                response: {
                                    status: response.status,
                                    headers: this.filterCorsHeaders(response),
                                },
                                description: `Origin "${origin}" reflected in ACAO${creds === "true" ? " + credentials" : ""}`,
                            },
                            owaspMapping: this.owaspMapping,
                            owaspId: this.owaspId,
                            remediation: `NEVER reflect the Origin header directly. Use a strict allowlist:\n\n\`\`\`javascript\nconst ALLOWED = new Set(['https://yourdomain.com', 'https://app.yourdomain.com']);\n\napp.use((req, res, next) => {\n  const origin = req.headers.origin;\n  if (ALLOWED.has(origin)) {\n    res.setHeader('Access-Control-Allow-Origin', origin);\n    res.setHeader('Vary', 'Origin');\n  }\n  next();\n});\n\`\`\``,
                            endpoint: endpoint.path,
                            method: "GET",
                        });
                        break; // One reflected origin is enough evidence
                    }
                } catch {
                    // Skip unreachable origins
                }
            }

            /* ── Test 3: Preflight Bypass — Dangerous Methods ── */
            for (const dangerousMethod of DANGEROUS_PREFLIGHT_METHODS) {
                try {
                    const response = await scannerClient({
                        requestsPerSecond: target.requestsPerSecond,
                        method: "options",
                        url,
                        timeout: 10000,
                        validateStatus: () => true,
                        headers: {
                            Origin: "https://evil.com",
                            "Access-Control-Request-Method": dangerousMethod,
                            "Access-Control-Request-Headers": DANGEROUS_PREFLIGHT_HEADERS.join(", "),
                            "User-Agent": "SecuriScan/1.0",
                        },
                    });

                    const acam = response.headers["access-control-allow-methods"];
                    if (acam && acam.toUpperCase().includes(dangerousMethod)) {
                        findings.push({
                            checkType: "cors_misconfiguration",
                            severity: "MEDIUM",
                            title: `CORS Allows Dangerous ${dangerousMethod} from Foreign Origins: ${endpoint.path}`,
                            description: `The CORS preflight response explicitly allows ${dangerousMethod} from the Origin "https://evil.com". A malicious website could perform destructive operations (${dangerousMethod}) cross-origin.`,
                            evidence: {
                                request: { url, method: "OPTIONS", headers: { Origin: "https://evil.com", "Access-Control-Request-Method": dangerousMethod } },
                                response: {
                                    status: response.status,
                                    headers: { "access-control-allow-methods": acam },
                                },
                                description: `Dangerous method ${dangerousMethod} allowed via preflight`,
                            },
                            owaspMapping: this.owaspMapping,
                            owaspId: this.owaspId,
                            remediation: `Only allow safe methods in CORS for sensitive endpoints:\n\n\`\`\`javascript\napp.use(cors({\n  methods: ['GET'],  // No PUT/DELETE/PATCH for public-facing CORS\n}));\n\`\`\``,
                            endpoint: endpoint.path,
                            method: "OPTIONS",
                        });
                        break;
                    }
                } catch {
                    // Skip
                }
            }

            /* ── Test 4: Vary: Origin Header Check ── */
            try {
                const response = await scannerClient({
                    requestsPerSecond: target.requestsPerSecond,
                    method: "get",
                    url,
                    timeout: 10000,
                    validateStatus: () => true,
                    headers: { Origin: "https://test.com", "User-Agent": "SecuriScan/1.0" },
                });

                const acao = response.headers["access-control-allow-origin"];
                const vary = response.headers["vary"] || "";

                if (acao && acao !== "*" && !vary.toLowerCase().includes("origin")) {
                    findings.push({
                        checkType: "cors_misconfiguration",
                        severity: "LOW",
                        title: `CORS Missing Vary: Origin Header: ${endpoint.path}`,
                        description: `The endpoint returns a dynamic Access-Control-Allow-Origin but does not include "Origin" in the Vary header. This can lead to cache poisoning where a CDN or proxy caches the response with one origin's ACAO and serves it to another, potentially leaking data cross-origin.`,
                        evidence: {
                            request: { url, method: "GET", headers: { Origin: "https://test.com" } },
                            response: {
                                status: response.status,
                                headers: { "access-control-allow-origin": acao, vary: vary || "(missing)" },
                            },
                            description: `Dynamic ACAO without Vary: Origin — cache poisoning risk`,
                        },
                        owaspMapping: this.owaspMapping,
                        owaspId: this.owaspId,
                        remediation: `Always include "Vary: Origin" when dynamically setting ACAO:\n\n\`\`\`javascript\nres.setHeader('Vary', 'Origin');\n\`\`\``,
                        endpoint: endpoint.path,
                        method: "GET",
                    });
                }
            } catch {
                // Skip
            }
        }

        return findings;
    }

    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    private filterCorsHeaders(response: { headers: any }): Record<string, string> {
        const corsKeys = ["access-control-allow-origin", "access-control-allow-credentials", "access-control-allow-methods", "access-control-allow-headers", "access-control-max-age", "access-control-expose-headers"];
        const out: Record<string, string> = {};
        for (const k of corsKeys) {
            if (response.headers[k]) out[k] = response.headers[k];
        }
        return out;
    }

    private hasAllDangerousMethods(acam: string): boolean {
        const upper = acam.toUpperCase();
        return DANGEROUS_PREFLIGHT_METHODS.every((m) => upper.includes(m));
    }
}
