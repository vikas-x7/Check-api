import { scannerClient } from "@/server/core/http/scanner-client";
import { SecurityCheck, ScanTarget, FindingResult, Evidence } from "@/types";
import { logger } from "@/server/core/logging/logger";
import { AxiosResponse } from "axios";

const log = logger.child("api-versioning-check");

/* ─── Common API Version Patterns ─── */
const VERSION_PATTERNS = [
    // Path-based versions
    "/v1/", "/v2/", "/v3/", "/v4/", "/v5/",
    "/api/v1/", "/api/v2/", "/api/v3/", "/api/v4/",
    "/api/1/", "/api/2/", "/api/3/",
    "/rest/v1/", "/rest/v2/",
];

/* ─── Deprecated / Debug / Internal Endpoints ─── */
const SHADOW_ENDPOINTS = [
    "/api/test", "/api/debug", "/api/internal",
    "/api/admin", "/api/dev", "/api/staging",
    "/api/swagger", "/api/docs", "/api-docs",
    "/swagger.json", "/swagger-ui", "/openapi.json",
    "/api/graphql", "/graphql", "/api/graphiql",
    "/api/health", "/api/status", "/api/metrics",
    "/api/config", "/api/env", "/actuator",
    "/actuator/env", "/actuator/health", "/actuator/info",
    "/.env", "/api/.env", "/config.json",
    "/api/v1/swagger.json", "/api/v2/swagger.json",
    "/debug/vars", "/debug/pprof",
    "/server-status", "/server-info",
    "/_debug", "/_internal", "/_config",
];

/* ─── Deprecation Indicators ─── */
const DEPRECATION_HEADERS = [
    "deprecation", "sunset", "x-api-deprecated",
    "x-deprecated", "x-api-warn",
];

export class ApiVersioningCheck implements SecurityCheck {
    name = "API Versioning & Shadow API Check";
    description = "Detects deprecated API versions still in service, shadow/undocumented APIs, exposed debug endpoints, and missing versioning best practices";
    owaspMapping = "Improper Inventory Management";
    owaspId = "API9:2023";

    async run(target: ScanTarget): Promise<FindingResult[]> {
        const findings: FindingResult[] = [];
        const testedUrls = new Set<string>();

        /* ── Phase 1: Discover active old API versions ── */
        const currentVersionMatch = target.baseUrl.match(/\/v(\d+)\//i) || target.endpoints[0]?.path.match(/\/v(\d+)\//i);
        const currentVersion = currentVersionMatch ? parseInt(currentVersionMatch[1]!) : null;

        if (currentVersion && currentVersion > 1) {
            for (let v = 1; v < currentVersion; v++) {
                for (const endpoint of target.endpoints.slice(0, 10)) {
                    const oldPath = endpoint.path.replace(/\/v\d+\//i, `/v${v}/`);
                    const oldUrl = `${target.baseUrl.replace(/\/v\d+/i, '')}${oldPath}`;

                    if (testedUrls.has(oldUrl)) continue;
                    testedUrls.add(oldUrl);

                    try {
                        const headers: Record<string, string> = { "User-Agent": "SecuriScan/1.0", ...(endpoint.customHeaders || {}) };
                        if (target.authConfig?.value) {
                            headers["Authorization"] = target.authConfig.type === "api_key" ? target.authConfig.value : `Bearer ${target.authConfig.value}`;
                        }

                        const response = await scannerClient({
                            requestsPerSecond: target.requestsPerSecond,
                            method: "get",
                            url: oldUrl,
                            timeout: 10000,
                            validateStatus: () => true,
                            headers,
                        });

                        if (response.status >= 200 && response.status < 300) {
                            findings.push({
                                checkType: "api-versioning",
                                severity: "HIGH",
                                title: `Deprecated API v${v} Still Active: ${oldPath}`,
                                description: `The deprecated API version v${v} is still responding at ${oldUrl} with HTTP ${response.status}. Older API versions often lack modern security controls, authentication improvements, and input validation. Attackers commonly target deprecated versions to bypass protections added in newer releases.`,
                                evidence: this.buildEvidence(oldUrl, "GET", headers, response),
                                owaspMapping: this.owaspMapping,
                                owaspId: this.owaspId,
                                remediation: `Retire deprecated API versions:\n\n\`\`\`javascript\n// Return 410 Gone for all deprecated versions\napp.use('/api/v${v}/*', (req, res) => {\n  res.status(410).json({\n    error: 'API v${v} has been retired',\n    migration: 'Please upgrade to /api/v${currentVersion}/',\n    docs: 'https://docs.example.com/migration'\n  });\n});\n\`\`\``,
                                endpoint: oldPath,
                                method: "GET",
                            });
                        }
                    } catch {
                        // Expected for non-existent versions
                    }
                }
            }
        }

        /* ── Phase 2: Probe for version patterns if no version detected ── */
        if (!currentVersion) {
            for (const versionPath of VERSION_PATTERNS) {
                for (const endpoint of target.endpoints.slice(0, 3)) {
                    const cleanPath = endpoint.path.replace(/^\/api\/?/i, "").replace(/^\/v\d+\/?/i, "");
                    const testUrl = `${target.baseUrl}${versionPath}${cleanPath}`;

                    if (testedUrls.has(testUrl)) continue;
                    testedUrls.add(testUrl);

                    try {
                        const response = await scannerClient({
                            requestsPerSecond: target.requestsPerSecond,
                            method: "get",
                            url: testUrl,
                            timeout: 8000,
                            validateStatus: () => true,
                            headers: { "User-Agent": "SecuriScan/1.0" },
                        });

                        if (response.status >= 200 && response.status < 300) {
                            findings.push({
                                checkType: "api-versioning",
                                severity: "MEDIUM",
                                title: `Undocumented API Version Discovered: ${versionPath}`,
                                description: `An undocumented API version was found at ${testUrl} (HTTP ${response.status}). This version is not part of the declared endpoints, suggesting it may be a shadow API, a forgotten staging version, or an improperly decommissioned endpoint.`,
                                evidence: this.buildEvidence(testUrl, "GET", { "User-Agent": "SecuriScan/1.0" }, response),
                                owaspMapping: this.owaspMapping,
                                owaspId: this.owaspId,
                                remediation: "Audit all API paths. Ensure undocumented versions are either properly secured or decommissioned. Use an API gateway to enforce routing policies.",
                                endpoint: `${versionPath}${cleanPath}`,
                                method: "GET",
                            });
                            break;
                        }
                    } catch {
                        // Expected
                    }
                }
            }
        }

        /* ── Phase 3: Shadow API / Debug endpoint discovery ── */
        for (const shadowPath of SHADOW_ENDPOINTS) {
            const shadowUrl = `${target.baseUrl}${shadowPath}`;
            if (testedUrls.has(shadowUrl)) continue;
            testedUrls.add(shadowUrl);

            try {
                const response = await scannerClient({
                    requestsPerSecond: target.requestsPerSecond,
                    method: "get",
                    url: shadowUrl,
                    timeout: 8000,
                    validateStatus: () => true,
                    headers: { "User-Agent": "SecuriScan/1.0" },
                });

                if (response.status >= 200 && response.status < 300) {
                    const responseBody = typeof response.data === "string" ? response.data : JSON.stringify(response.data || "");
                    const isDebug = shadowPath.includes("debug") || shadowPath.includes("env") || shadowPath.includes("config") || shadowPath.includes("actuator");
                    const isSensitive = responseBody.toLowerCase().includes("password") || responseBody.toLowerCase().includes("secret") ||
                        responseBody.toLowerCase().includes("key") || responseBody.toLowerCase().includes("token") || responseBody.toLowerCase().includes("database");

                    findings.push({
                        checkType: "api-versioning",
                        severity: isDebug || isSensitive ? "CRITICAL" : "HIGH",
                        title: `Shadow/Debug Endpoint Exposed: ${shadowPath}`,
                        description: `The endpoint ${shadowUrl} is publicly accessible (HTTP ${response.status}). ${isDebug ? "This appears to be a debug/internal endpoint that exposes sensitive operational data." : "This is an undocumented endpoint that may leak implementation details or provide unauthorized access."} ${isSensitive ? "WARNING: The response contains potentially sensitive keywords (password, secret, key, token, or database)." : ""}`,
                        evidence: this.buildEvidence(shadowUrl, "GET", { "User-Agent": "SecuriScan/1.0" }, response),
                        owaspMapping: this.owaspMapping,
                        owaspId: this.owaspId,
                        remediation: `Remove or restrict access to internal endpoints:\n\n\`\`\`javascript\n// Only expose in development\nif (process.env.NODE_ENV === 'development') {\n  app.get('${shadowPath}', debugHandler);\n}\n\n// Or require admin authentication\napp.get('${shadowPath}', requireAdmin, debugHandler);\n\`\`\``,
                        endpoint: shadowPath,
                        method: "GET",
                    });
                }
            } catch {
                // Expected for non-existent endpoints
            }
        }

        /* ── Phase 4: Check for deprecation headers on current endpoints ── */
        for (const endpoint of target.endpoints.slice(0, 10)) {
            const url = `${target.baseUrl}${endpoint.path}`;
            try {
                const response = await scannerClient({
                    requestsPerSecond: target.requestsPerSecond,
                    method: endpoint.method.toLowerCase(),
                    url,
                    timeout: 10000,
                    validateStatus: () => true,
                    headers: { "User-Agent": "SecuriScan/1.0", ...(endpoint.customHeaders || {}) },
                });

                // Check for deprecation headers
                const foundDeprecation = DEPRECATION_HEADERS.filter(
                    h => response.headers[h] !== undefined
                );

                if (foundDeprecation.length > 0) {
                    findings.push({
                        checkType: "api-versioning",
                        severity: "MEDIUM",
                        title: `Deprecated Endpoint In Use: ${endpoint.path}`,
                        description: `The endpoint ${endpoint.path} contains deprecation headers (${foundDeprecation.join(", ")}), indicating it is scheduled for removal. Continued use of deprecated endpoints risks sudden breakage and potential security gaps when the endpoint reaches its sunset date.`,
                        evidence: this.buildEvidence(url, endpoint.method, {}, response),
                        owaspMapping: this.owaspMapping,
                        owaspId: this.owaspId,
                        remediation: "Migrate to the recommended replacement endpoint before the sunset date. Check the 'Sunset' and 'Link' headers for migration guidance.",
                        endpoint: endpoint.path,
                        method: endpoint.method,
                    });
                }

                // Check for missing API versioning indicator
                const hasVersionInPath = endpoint.path.match(/\/v\d+\//i);
                const hasVersionHeader = response.headers["api-version"] || response.headers["x-api-version"];
                if (!hasVersionInPath && !hasVersionHeader && target.endpoints.length > 3) {
                    // Only report once
                    const alreadyReported = findings.some(f => f.title.includes("No API Versioning"));
                    if (!alreadyReported) {
                        findings.push({
                            checkType: "api-versioning",
                            severity: "LOW",
                            title: `No API Versioning Strategy Detected`,
                            description: `The API at ${target.baseUrl} does not appear to use either URL-based versioning (e.g., /v1/) or header-based versioning (API-Version header). This makes it difficult to manage breaking changes and deprecate endpoints safely.`,
                            evidence: this.buildEvidence(url, endpoint.method, {}, response),
                            owaspMapping: this.owaspMapping,
                            owaspId: this.owaspId,
                            remediation: `Implement API versioning:\n\n\`\`\`javascript\n// URL-based (recommended)\napp.use('/api/v1/', v1Router);\napp.use('/api/v2/', v2Router);\n\n// Or header-based\napp.use('/api/', (req, res, next) => {\n  const version = req.headers['api-version'] || 'v2';\n  if (version === 'v1') return v1Handler(req, res, next);\n  return v2Handler(req, res, next);\n});\n\`\`\``,
                            endpoint: endpoint.path,
                            method: endpoint.method,
                        });
                    }
                }
            } catch (err) {
                log.debug(`Versioning check skipped: ${err instanceof Error ? err.message : String(err)}`);
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
            description: `API versioning/shadow probe sent to ${method} ${url}`,
        };
    }
}
