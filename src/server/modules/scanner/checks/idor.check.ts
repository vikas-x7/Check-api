import { scannerClient } from "@/server/core/http/scanner-client";
import { SecurityCheck, ScanTarget, FindingResult } from "@/types";
import { logger } from "@/server/core/logging/logger";

const log = logger.child("idor-check");

export class IdorCheck implements SecurityCheck {
    name = "IDOR & Broken Object-Level Authorization Check";
    description = "Tests for Insecure Direct Object Reference vulnerabilities through ID manipulation, sequential enumeration, and horizontal access control bypass";
    owaspMapping = "Broken Object Level Authorization";
    owaspId = "API1:2023";

    async run(target: ScanTarget): Promise<FindingResult[]> {
        const findings: FindingResult[] = [];

        /* ── Identify endpoints with ID parameters ── */
        const idEndpoints = target.endpoints.filter((ep) =>
            /\/\d+|\/[a-f0-9-]{36}|\/:\w*[Ii]d|\/:\w+/i.test(ep.path) ||
            ep.parameters?.some((p) => p.in === "path" && /id$/i.test(p.name))
        );

        for (const endpoint of idEndpoints) {
            const url = `${target.baseUrl}${endpoint.path}`;
            const method = endpoint.method.toLowerCase() as "get" | "post" | "put" | "delete" | "patch";
            const headers: Record<string, string> = { "User-Agent": "SecuriScan/1.0", ...(endpoint.customHeaders || {}) };

            if (target.authConfig?.value) {
                if (target.authConfig.type === "bearer" || target.authConfig.type === "jwt") {
                    headers["Authorization"] = `Bearer ${target.authConfig.value}`;
                } else if (target.authConfig.type === "api_key") {
                    headers[target.authConfig.headerName || "X-API-Key"] = target.authConfig.value;
                }
            }

            /* ── Test 1: Horizontal Access — Sequential ID Enumeration ── */
            try {
                const originalResponse = await scannerClient({
                    requestsPerSecond: target.requestsPerSecond,
                    method,
                    url,
                    timeout: 10000,
                    validateStatus: () => true,
                    headers,
                });

                if (originalResponse.status >= 200 && originalResponse.status < 300) {
                    const idVariations = this.generateIdVariations(endpoint.path);

                    for (const variedPath of idVariations) {
                        try {
                            const variedUrl = `${target.baseUrl}${variedPath}`;
                            const variedResponse = await scannerClient({
                                requestsPerSecond: target.requestsPerSecond,
                                method,
                                url: variedUrl,
                                timeout: 10000,
                                validateStatus: () => true,
                                headers,
                            });

                            if (variedResponse.status >= 200 && variedResponse.status < 300) {
                                const originalStr = JSON.stringify(originalResponse.data);
                                const variedStr = JSON.stringify(variedResponse.data);

                                if (originalStr !== variedStr && variedStr.length > 10) {
                                    /* Verify it's not a list endpoint returning same structure */
                                    const isListEndpoint = Array.isArray(variedResponse.data);
                                    if (!isListEndpoint) {
                                        findings.push({
                                            checkType: "idor",
                                            severity: "CRITICAL",
                                            title: `IDOR: Horizontal Access via ${endpoint.method} ${endpoint.path}`,
                                            description: `Successfully accessed a different user's resource by manipulating the ID in the URL. Original: ${endpoint.path} → Modified: ${variedPath}. Both returned HTTP 200 with DIFFERENT data (${originalStr.length} vs ${variedStr.length} bytes). This confirms broken object-level authorization — any authenticated user can access any other user's resource.`,
                                            evidence: {
                                                request: { url: variedUrl, method: endpoint.method, headers },
                                                response: {
                                                    status: variedResponse.status,
                                                    headers: variedResponse.headers as Record<string, string>,
                                                    body: {
                                                        originalPath: endpoint.path,
                                                        modifiedPath: variedPath,
                                                        originalDataSize: originalStr.length,
                                                        modifiedDataSize: variedStr.length,
                                                        dataIsDifferent: true,
                                                    },
                                                },
                                                description: `ID manipulation returned a different user's data without authorization`,
                                            },
                                            owaspMapping: this.owaspMapping,
                                            owaspId: this.owaspId,
                                            remediation: `Implement object-level authorization on every resource access:\n\n\`\`\`javascript\napp.get('/api/users/:id', authMiddleware, async (req, res) => {\n  const resource = await User.findById(req.params.id);\n  if (!resource) return res.status(404).json({ error: 'Not found' });\n  \n  // CRITICAL: Verify ownership or admin role\n  if (resource.ownerId !== req.user.id && !req.user.isAdmin) {\n    return res.status(403).json({ error: 'Access denied' });\n  }\n  \n  res.json(resource);\n});\n\`\`\``,
                                            endpoint: endpoint.path,
                                            method: endpoint.method,
                                        });
                                        break;
                                    }
                                }
                            }
                        } catch {
                            // Variation failed, skip
                        }
                    }
                }
            } catch (err) {
                log.debug(`IDOR horizontal test skipped for ${url}: ${err instanceof Error ? err.message : String(err)}`);
            }

            /* ── Test 2: Unauthenticated IDOR (no auth header) ── */
            if (target.authConfig?.value) {
                try {
                    const noAuthResponse = await scannerClient({
                        requestsPerSecond: target.requestsPerSecond,
                        method,
                        url,
                        timeout: 10000,
                        validateStatus: () => true,
                        headers: { "User-Agent": "SecuriScan/1.0" },
                    });

                    if (noAuthResponse.status >= 200 && noAuthResponse.status < 300) {
                        const bodyStr = JSON.stringify(noAuthResponse.data || "");
                        if (bodyStr.length > 10) {
                            findings.push({
                                checkType: "idor",
                                severity: "CRITICAL",
                                title: `IDOR: Unauthenticated Access to ${endpoint.method} ${endpoint.path}`,
                                description: `The resource at ${endpoint.path} is accessible WITHOUT any authentication headers and returns ${bodyStr.length} bytes of data. Any anonymous user can access this resource by simply knowing or guessing the ID.`,
                                evidence: {
                                    request: { url, method: endpoint.method, headers: { "User-Agent": "SecuriScan/1.0" } },
                                    response: {
                                        status: noAuthResponse.status,
                                        headers: noAuthResponse.headers as Record<string, string>,
                                        body: typeof noAuthResponse.data === "object" ? noAuthResponse.data : String(noAuthResponse.data).slice(0, 500),
                                    },
                                    description: `Resource accessible without authentication`,
                                },
                                owaspMapping: this.owaspMapping,
                                owaspId: this.owaspId,
                                remediation: `Require authentication for all resource endpoints:\n\n\`\`\`javascript\n// Apply auth middleware to all /api routes\napp.use('/api', authMiddleware);\n\n// Verify access per-resource\napp.get('/api/data/:id', async (req, res) => {\n  if (!req.user) return res.status(401).json({ error: 'Login required' });\n  // ... rest of handler\n});\n\`\`\``,
                                endpoint: endpoint.path,
                                method: endpoint.method,
                            });
                        }
                    }
                } catch {
                    // Expected for properly secured endpoints
                }
            }

            /* ── Test 3: Mass Assignment / Write-based IDOR ── */
            if (["PUT", "PATCH", "POST"].includes(endpoint.method.toUpperCase())) {
                try {
                    const writeResponse = await scannerClient({
                        requestsPerSecond: target.requestsPerSecond,
                        method,
                        url,
                        timeout: 10000,
                        validateStatus: () => true,
                        headers: { ...headers, "Content-Type": "application/json" },
                        data: JSON.stringify({ role: "admin", isAdmin: true, admin: true, verified: true }),
                    });

                    if (writeResponse.status >= 200 && writeResponse.status < 300) {
                        const body = JSON.stringify(writeResponse.data || "");
                        if (body.includes("admin") || body.includes("true")) {
                            findings.push({
                                checkType: "idor",
                                severity: "CRITICAL",
                                title: `Mass Assignment: ${endpoint.method} ${endpoint.path}`,
                                description: `The endpoint accepts and may process unauthorized fields (role=admin, isAdmin=true). The response contains "admin" or "true" after sending a mass assignment payload. This could allow privilege escalation by modifying protected object properties.`,
                                evidence: {
                                    request: { url, method: endpoint.method, headers },
                                    response: {
                                        status: writeResponse.status,
                                        headers: writeResponse.headers as Record<string, string>,
                                        body: typeof writeResponse.data === "object" ? writeResponse.data : String(writeResponse.data).slice(0, 500),
                                    },
                                    description: `Mass assignment payload accepted — potential privilege escalation`,
                                    payload: '{"role":"admin","isAdmin":true,"admin":true,"verified":true}',
                                },
                                owaspMapping: "Broken Object Property Level Authorization",
                                owaspId: "API3:2023",
                                remediation: `Use explicit field allowlists for updates:\n\n\`\`\`javascript\nconst ALLOWED_FIELDS = ['name', 'email', 'avatar'];\n\napp.put('/api/users/:id', (req, res) => {\n  // Only pick allowed fields from request body\n  const updates = {};\n  for (const field of ALLOWED_FIELDS) {\n    if (req.body[field] !== undefined) updates[field] = req.body[field];\n  }\n  // NEVER: User.update(req.params.id, req.body)\n  User.update(req.params.id, updates);\n});\n\`\`\``,
                                endpoint: endpoint.path,
                                method: endpoint.method,
                            });
                        }
                    }
                } catch {
                    // Skip
                }
            }

            /* ── Test 4: Enumeration Detection (sequential IDs) ── */
            if (endpoint.method.toUpperCase() === "GET") {
                try {
                    const enumPaths = ["/1", "/2", "/3", "/4", "/5"];
                    const basePath = endpoint.path.replace(/\/\d+$/, "").replace(/\/:\w+$/, "");
                    let successCount = 0;

                    for (const suffix of enumPaths) {
                        const enumUrl = `${target.baseUrl}${basePath}${suffix}`;
                        const response = await scannerClient({
                            requestsPerSecond: target.requestsPerSecond,
                            method: "get",
                            url: enumUrl,
                            timeout: 10000,
                            validateStatus: () => true,
                            headers,
                        });
                        if (response.status >= 200 && response.status < 300) successCount++;
                    }

                    if (successCount >= 4) {
                        findings.push({
                            checkType: "idor",
                            severity: "HIGH",
                            title: `Sequential ID Enumeration: ${basePath}/:id`,
                            description: `The endpoint ${basePath} uses sequential numeric IDs (1-5 tested, ${successCount}/5 accessible). Sequential IDs make it trivial for attackers to enumerate all resources. Use UUIDs or opaque tokens instead.`,
                            evidence: {
                                request: { url: `${target.baseUrl}${basePath}/1`, method: "GET", headers },
                                response: {
                                    status: 200,
                                    headers: {},
                                    body: { testedIds: enumPaths, successCount, totalTested: enumPaths.length },
                                },
                                description: `${successCount}/${enumPaths.length} sequential IDs returned data`,
                            },
                            owaspMapping: this.owaspMapping,
                            owaspId: this.owaspId,
                            remediation: `Use UUIDs instead of sequential IDs:\n\n\`\`\`javascript\n// Use UUIDs for resource identifiers\nconst { v4: uuidv4 } = require('uuid');\n\nconst newResource = {\n  id: uuidv4(), // 'f47ac10b-58cc-4372-a567-0e02b2c3d479'\n  // ...\n};\n\n// Rate-limit enumeration attempts\nconst enumLimiter = rateLimit({ windowMs: 60000, max: 10 });\napp.use('/api/resources/:id', enumLimiter);\n\`\`\``,
                            endpoint: `${basePath}/:id`,
                            method: "GET",
                        });
                    }
                } catch {
                    // Skip
                }
            }
        }

        return findings;
    }

    private generateIdVariations(path: string): string[] {
        const variations: string[] = [];

        // Replace numeric IDs with adjacent values
        const numericMatch = path.match(/\/(\d+)/);
        if (numericMatch) {
            const id = parseInt(numericMatch[1]);
            const candidates = [id + 1, id - 1, id + 100, 1, 2, 999].filter((n) => n > 0 && n !== id);
            for (const newId of [...new Set(candidates)].slice(0, 4)) {
                variations.push(path.replace(/\/\d+/, `/${newId}`));
            }
        }

        // Replace :param placeholders with test IDs
        if (path.includes(":")) {
            variations.push(path.replace(/\/:\w+/, "/1"));
            variations.push(path.replace(/\/:\w+/, "/2"));
            variations.push(path.replace(/\/:\w+/, "/999"));
        }

        // Replace UUID-like strings
        const uuidMatch = path.match(/\/([a-f0-9-]{36})/i);
        if (uuidMatch) {
            variations.push(path.replace(/\/[a-f0-9-]{36}/i, "/00000000-0000-0000-0000-000000000001"));
            variations.push(path.replace(/\/[a-f0-9-]{36}/i, "/00000000-0000-0000-0000-000000000002"));
        }

        return [...new Set(variations)].slice(0, 5);
    }
}
