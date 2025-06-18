import { AxiosResponse } from "axios";
import { scannerClient } from "@/server/core/http/scanner-client";
import { SecurityCheck, ScanTarget, FindingResult, Evidence } from "@/types";



/* ─── HTTP Methods to Test ─── */
const STANDARD_METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"] as const;
const DANGEROUS_METHODS = ["TRACE", "CONNECT"] as const;
const OVERRIDE_HEADERS = [
    "X-HTTP-Method-Override",
    "X-Method-Override",
    "X-HTTP-Method",
    "_method",
];

export class MethodFuzzCheck implements SecurityCheck {
    name = "HTTP Method Fuzzing & Override Check";
    description = "Tests for unintended HTTP methods, dangerous TRACE/CONNECT support, method override bypass, and content negotiation abuse";
    owaspMapping = "Broken Function Level Authorization";
    owaspId = "API5:2023";

    async run(target: ScanTarget): Promise<FindingResult[]> {
        const findings: FindingResult[] = [];

        for (const endpoint of target.endpoints) {
            const url = `${target.baseUrl}${endpoint.path}`;
            const declaredMethod = endpoint.method.toUpperCase();
            const headers: Record<string, string> = { "User-Agent": "SecuriScan/1.0", ...(endpoint.customHeaders || {}) };

            /* ── Test 1: Undeclared Standard Methods ── */
            const otherMethods = STANDARD_METHODS.filter(
                (m) => m !== declaredMethod && m !== "OPTIONS" && m !== "HEAD"
            );

            for (const method of otherMethods) {
                try {
                    const response = await scannerClient({
                        requestsPerSecond: target.requestsPerSecond,
                        method: method.toLowerCase() as string,
                        url,
                        timeout: 10000,
                        validateStatus: () => true,
                        headers,
                        data: ["POST", "PUT", "PATCH"].includes(method) ? {} : undefined,
                    });

                    if (response.status >= 200 && response.status < 300) {
                        const isDangerous = ["DELETE", "PUT", "PATCH", "POST"].includes(method);
                        const hasData = response.data && JSON.stringify(response.data).length > 2;

                        findings.push({
                            checkType: "method_fuzzing",
                            severity: isDangerous ? "HIGH" : "MEDIUM",
                            title: `Unintended Method: ${method} ${endpoint.path}`,
                            description: `The endpoint ${endpoint.path} (declared as ${declaredMethod}) also accepts ${method} requests and returned HTTP ${response.status}.${isDangerous ? ` The ${method} method is destructive/mutative — an attacker could modify or delete data without proper authorization.` : ` This exposes additional functionality that may not be intentionally available.`}${hasData ? ` The response contains data (${JSON.stringify(response.data).length} bytes), confirming the method is processed.` : ""}`,
                            evidence: this.buildEvidence(url, method, response),
                            owaspMapping: this.owaspMapping,
                            owaspId: this.owaspId,
                            remediation: `Restrict HTTP methods per endpoint:\n\n\`\`\`javascript\n// Express: Only define handlers for intended methods\napp.route('${endpoint.path}')\n  .${declaredMethod.toLowerCase()}(handler)\n  .all((req, res) => res.status(405).json({\n    error: 'Method not allowed',\n    allowed: ['${declaredMethod}'],\n  }));\n\n// Or use middleware:\nconst allowMethods = (...methods) => (req, res, next) => {\n  if (!methods.includes(req.method)) {\n    res.setHeader('Allow', methods.join(', '));\n    return res.status(405).json({ error: 'Method not allowed' });\n  }\n  next();\n};\n\napp.use('${endpoint.path}', allowMethods('${declaredMethod}'));\n\`\`\``,
                            endpoint: endpoint.path,
                            method,
                        });
                    }
                } catch {
                    // Skip
                }
            }

            /* ── Test 2: Dangerous TRACE Method (XST — Cross-Site Tracing) ── */
            for (const method of DANGEROUS_METHODS) {
                try {
                    const response = await scannerClient({
                        requestsPerSecond: target.requestsPerSecond,
                        method: method.toLowerCase() as string,
                        url,
                        timeout: 10000,
                        validateStatus: () => true,
                        headers: { ...headers, "X-Secret-Test": "SecuriScan-Trace-Probe" },
                    });

                    if (response.status >= 200 && response.status < 300) {
                        const responseStr = JSON.stringify(response.data || "") + JSON.stringify(response.headers || "");
                        const reflectsHeaders = responseStr.includes("SecuriScan-Trace-Probe");

                        findings.push({
                            checkType: "method_fuzzing",
                            severity: method === "TRACE" && reflectsHeaders ? "CRITICAL" : "HIGH",
                            title: `Dangerous ${method} Method Enabled: ${endpoint.path}`,
                            description: method === "TRACE"
                                ? `The TRACE method is enabled and${reflectsHeaders ? " reflects request headers in the response body (confirmed Cross-Site Tracing — XST)" : " accepts requests"}. TRACE can be exploited to steal HttpOnly cookies via XST attacks when combined with XSS.`
                                : `The CONNECT method is enabled on ${endpoint.path}. This is typically used for proxying and can be abused to tunnel connections through the server (SSRF proxy).`,
                            evidence: {
                                request: { url, method, headers: { "X-Secret-Test": "SecuriScan-Trace-Probe" } },
                                response: {
                                    status: response.status,
                                    headers: response.headers as Record<string, string>,
                                    body: typeof response.data === "object" ? response.data : String(response.data).slice(0, 500),
                                },
                                description: `${method} method is active${reflectsHeaders ? " — headers reflected in response (XST confirmed)" : ""}`,
                            },
                            owaspMapping: "Security Misconfiguration",
                            owaspId: "API8:2023",
                            remediation: `Disable TRACE and CONNECT in production:\n\n\`\`\`javascript\n// Express middleware\napp.use((req, res, next) => {\n  if (['TRACE', 'CONNECT'].includes(req.method)) {\n    return res.status(405).json({ error: 'Method not allowed' });\n  }\n  next();\n});\n\n// Nginx:\nif ($request_method ~ ^(TRACE|CONNECT)$) {\n  return 405;\n}\n\n// Apache:\nTraceEnable Off\n\`\`\``,
                            endpoint: endpoint.path,
                            method,
                        });
                    }
                } catch {
                    // Expected — most servers reject TRACE/CONNECT
                }
            }

            /* ── Test 3: HTTP Method Override Bypass ── */
            for (const overrideHeader of OVERRIDE_HEADERS) {
                for (const overrideMethod of ["DELETE", "PUT", "PATCH"]) {
                    if (overrideMethod === declaredMethod) continue;

                    try {
                        const response = await scannerClient({
                            requestsPerSecond: target.requestsPerSecond,
                            method: "post" as string,
                            url,
                            timeout: 10000,
                            validateStatus: () => true,
                            headers: {
                                ...headers,
                                [overrideHeader]: overrideMethod,
                                "Content-Type": "application/json",
                            },
                            data: {},
                        });

                        if (response.status >= 200 && response.status < 300) {
                            findings.push({
                                checkType: "method_fuzzing",
                                severity: "HIGH",
                                title: `Method Override Bypass: ${overrideHeader}: ${overrideMethod} on ${endpoint.path}`,
                                description: `The API accepts the "${overrideHeader}: ${overrideMethod}" header on a POST request, effectively allowing the caller to execute a ${overrideMethod} operation. Attackers can use this to bypass WAF/firewall rules that only inspect the actual HTTP method, or to perform destructive operations via a simple POST.`,
                                evidence: {
                                    request: {
                                        url,
                                        method: "POST",
                                        headers: { [overrideHeader]: overrideMethod, "Content-Type": "application/json" },
                                    },
                                    response: {
                                        status: response.status,
                                        headers: response.headers as Record<string, string>,
                                    },
                                    description: `POST + ${overrideHeader}: ${overrideMethod} → treated as ${overrideMethod}`,
                                },
                                owaspMapping: this.owaspMapping,
                                owaspId: this.owaspId,
                                remediation: `Disable HTTP method override headers in production:\n\n\`\`\`javascript\n// Do NOT use method-override middleware\n// const methodOverride = require('method-override');\n// app.use(methodOverride('X-HTTP-Method-Override')); // REMOVE THIS\n\n// If needed, restrict to specific routes only\napp.use('/admin/legacy', methodOverride('X-HTTP-Method-Override'));\n\`\`\``,
                                endpoint: endpoint.path,
                                method: "POST",
                            });
                            break; // One override bypass per endpoint is enough
                        }
                    } catch {
                        // Skip
                    }
                }
            }

            /* ── Test 4: Content-Type Confusion ── */
            if (declaredMethod === "POST" || declaredMethod === "PUT" || declaredMethod === "PATCH") {
                const contentTypes = [
                    { ct: "application/xml", body: '<root><test>1</test></root>', label: "XML" },
                    { ct: "text/plain", body: "test=1", label: "Plain text" },
                    { ct: "application/x-www-form-urlencoded", body: "test=1&admin=true", label: "Form URL-encoded" },
                    { ct: "multipart/form-data; boundary=---test", body: "-----test\r\nContent-Disposition: form-data; name=\"file\"\r\n\r\nmalicious\r\n-----test--", label: "Multipart form" },
                ];

                for (const { ct, body, label } of contentTypes) {
                    try {
                        const response = await scannerClient({
                            requestsPerSecond: target.requestsPerSecond,
                            method: declaredMethod.toLowerCase() as string,
                            url,
                            timeout: 10000,
                            validateStatus: () => true,
                            headers: { ...headers, "Content-Type": ct },
                            data: body,
                        });

                        if (response.status >= 200 && response.status < 300) {
                            findings.push({
                                checkType: "method_fuzzing",
                                severity: "MEDIUM",
                                title: `Content-Type Confusion: ${label} accepted at ${endpoint.path}`,
                                description: `The endpoint accepts ${label} content type (${ct}) and returned HTTP ${response.status}. If the API only expects JSON, accepting other content types may lead to parsing vulnerabilities, XML External Entity (XXE) injection, or bypass of input validation.`,
                                evidence: {
                                    request: { url, method: declaredMethod, headers: { "Content-Type": ct } },
                                    response: {
                                        status: response.status,
                                        headers: response.headers as Record<string, string>,
                                    },
                                    description: `${label} (${ct}) accepted with HTTP ${response.status}`,
                                },
                                owaspMapping: "Security Misconfiguration",
                                owaspId: "API8:2023",
                                remediation: `Enforce strict Content-Type validation:\n\n\`\`\`javascript\napp.use((req, res, next) => {\n  if (['POST', 'PUT', 'PATCH'].includes(req.method)) {\n    if (!req.is('application/json')) {\n      return res.status(415).json({\n        error: 'Unsupported Media Type',\n        expected: 'application/json',\n      });\n    }\n  }\n  next();\n});\n\`\`\``,
                                endpoint: endpoint.path,
                                method: declaredMethod,
                            });
                            break; // One content-type confusion per endpoint
                        }
                    } catch {
                        // Skip
                    }
                }
            }
        }

        return findings;
    }

    private buildEvidence(url: string, method: string, response: AxiosResponse): Evidence {
        return {
            request: { url, method, headers: { "User-Agent": "SecuriScan/1.0" } },
            response: {
                status: response.status,
                headers: response.headers as Record<string, string>,
                body: typeof response.data === "object" ? response.data : String(response.data).slice(0, 500),
            },
            description: `${method} request to ${url} returned ${response.status} — method should not be allowed`,
        };
    }
}
