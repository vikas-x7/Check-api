import { AxiosResponse } from "axios";
import { scannerClient } from "@/server/core/http/scanner-client";
import { SecurityCheck, ScanTarget, FindingResult, Evidence } from "@/types";
import { logger } from "@/server/core/logging/logger";

const log = logger.child("cmdi-check");

/* ─── OS Command Injection Payloads ─── */
const CMDI_PAYLOADS: { payload: string; label: string; technique: string; expectedSignature: string[] }[] = [
    // Time-based blind injection
    { payload: "; sleep 3", label: "Unix semicolon sleep", technique: "time-based", expectedSignature: [] },
    { payload: "| sleep 3", label: "Unix pipe sleep", technique: "time-based", expectedSignature: [] },
    { payload: "|| sleep 3", label: "Unix OR sleep", technique: "time-based", expectedSignature: [] },
    { payload: "& sleep 3", label: "Unix background sleep", technique: "time-based", expectedSignature: [] },
    { payload: "`sleep 3`", label: "Backtick sleep", technique: "time-based", expectedSignature: [] },
    { payload: "$(sleep 3)", label: "Subshell sleep", technique: "time-based", expectedSignature: [] },
    { payload: "& ping -c 3 127.0.0.1 &", label: "Ping-based delay", technique: "time-based", expectedSignature: [] },
    { payload: "| timeout 3", label: "Timeout command", technique: "time-based", expectedSignature: [] },
    { payload: "; ping -n 3 127.0.0.1", label: "Windows ping delay", technique: "time-based", expectedSignature: [] },
    { payload: "& timeout /t 3 /nobreak", label: "Windows timeout delay", technique: "time-based", expectedSignature: [] },

    // Output-based (look for command output in response)
    { payload: "; id", label: "Unix id command", technique: "output", expectedSignature: ["uid=", "gid=", "groups="] },
    { payload: "| id", label: "Pipe id command", technique: "output", expectedSignature: ["uid=", "gid=", "groups="] },
    { payload: "$(id)", label: "Subshell id", technique: "output", expectedSignature: ["uid=", "gid=", "groups="] },
    { payload: "`id`", label: "Backtick id", technique: "output", expectedSignature: ["uid=", "gid=", "groups="] },
    { payload: "; whoami", label: "Unix whoami", technique: "output", expectedSignature: ["root", "www-data", "node", "app"] },
    { payload: "| whoami", label: "Pipe whoami", technique: "output", expectedSignature: ["root", "www-data", "node", "app"] },
    { payload: "; uname -a", label: "Unix uname", technique: "output", expectedSignature: ["Linux", "Darwin", "x86_64", "GNU"] },
    { payload: "; cat /etc/passwd", label: "Read /etc/passwd", technique: "output", expectedSignature: ["root:", "/bin/", "/home/", "nologin"] },
    { payload: "| cat /etc/passwd", label: "Pipe /etc/passwd", technique: "output", expectedSignature: ["root:", "/bin/", "/home/", "nologin"] },
    { payload: "; echo SECURISCAN_CMDI_PROBE", label: "Echo canary marker", technique: "output", expectedSignature: ["SECURISCAN_CMDI_PROBE"] },
    { payload: "| echo SECURISCAN_CMDI_PROBE", label: "Pipe echo canary", technique: "output", expectedSignature: ["SECURISCAN_CMDI_PROBE"] },
    { payload: "$(echo SECURISCAN_CMDI_PROBE)", label: "Subshell echo canary", technique: "output", expectedSignature: ["SECURISCAN_CMDI_PROBE"] },
    { payload: "; ls -la /", label: "List root directory", technique: "output", expectedSignature: ["bin", "etc", "usr", "var", "tmp"] },
    { payload: "; env", label: "Print environment variables", technique: "output", expectedSignature: ["PATH=", "HOME=", "USER="] },

    // Windows-specific
    { payload: "& whoami", label: "Windows whoami", technique: "output", expectedSignature: ["\\"] },
    { payload: "| type C:\\Windows\\system.ini", label: "Windows system.ini", technique: "output", expectedSignature: ["[drivers]", "mci", "386enh"] },
    { payload: "& set", label: "Windows env variables", technique: "output", expectedSignature: ["COMPUTERNAME=", "OS=", "PROCESSOR"] },
];

/* ─── Shell Error Signatures ─── */
const SHELL_ERROR_SIGNATURES = [
    "sh:", "bash:", "/bin/sh", "/bin/bash", "not found",
    "command not found", "Permission denied", "syntax error",
    "No such file or directory", "cannot execute",
    "Operation not permitted", "exec()", "system()",
    "popen(", "child_process", "subprocess", "os.system",
    "cmd.exe", "powershell", "proc_open",
];

export class CommandInjectionCheck implements SecurityCheck {
    name = "Command Injection Check";
    description = "Tests for OS command injection via semicolons, pipes, backticks, subshells, and Windows-specific operators using time-based and output-based detection";
    owaspMapping = "Injection";
    owaspId = "API8:2023";

    async run(target: ScanTarget): Promise<FindingResult[]> {
        const findings: FindingResult[] = [];
        const foundEndpoints = new Set<string>();

        for (const endpoint of target.endpoints) {
            const url = `${target.baseUrl}${endpoint.path}`;
            const endpointKey = `${endpoint.method}:${endpoint.path}`;

            /* ── Baseline ── */
            let baselineTime = 0;
            try {
                const headers: Record<string, string> = { "User-Agent": "SecuriScan/1.0", ...(endpoint.customHeaders || {}) };
                if (target.authConfig?.value) {
                    headers["Authorization"] = target.authConfig.type === "api_key" ? target.authConfig.value : `Bearer ${target.authConfig.value}`;
                }
                const start = Date.now();
                await scannerClient({
                    requestsPerSecond: target.requestsPerSecond,
                    method: endpoint.method.toLowerCase(),
                    url,
                    timeout: 15000,
                    validateStatus: () => true,
                    headers,
                });
                baselineTime = Date.now() - start;
            } catch {
                continue;
            }

            /* ── Test each payload ── */
            for (const { payload, label, technique, expectedSignature } of CMDI_PAYLOADS) {
                if (foundEndpoints.has(endpointKey)) break;

                try {
                    const injPoints = this.buildInjectionPoints(url, endpoint, payload);

                    for (const injPoint of injPoints) {
                        const headers: Record<string, string> = {
                            "User-Agent": "SecuriScan/1.0",
                            "Content-Type": "application/json",
                            ...(endpoint.customHeaders || {}),
                        };
                        if (target.authConfig?.value) {
                            headers["Authorization"] = target.authConfig.type === "api_key" ? target.authConfig.value : `Bearer ${target.authConfig.value}`;
                        }

                        const start = Date.now();
                        const response = await scannerClient({
                            requestsPerSecond: target.requestsPerSecond,
                            method: endpoint.method.toLowerCase(),
                            url: injPoint.url,
                            timeout: technique === "time-based" ? 15000 : 10000,
                            validateStatus: () => true,
                            headers,
                            data: injPoint.body,
                        });
                        const elapsed = Date.now() - start;
                        const responseBody = typeof response.data === "string" ? response.data : JSON.stringify(response.data || "");
                        const lowerBody = responseBody.toLowerCase();

                        let isVulnerable = false;
                        let evidenceDesc = "";

                        // Time-based detection
                        if (technique === "time-based" && elapsed > baselineTime + 2500) {
                            isVulnerable = true;
                            evidenceDesc = `Time-based command injection detected. Baseline: ${baselineTime}ms, Injected: ${elapsed}ms (delta: ${elapsed - baselineTime}ms). The sleep/ping payload delayed the server response.`;
                        }

                        // Output-based detection
                        if (technique === "output") {
                            const matchedSigs = expectedSignature.filter(sig => lowerBody.includes(sig.toLowerCase()));
                            if (matchedSigs.length > 0) {
                                isVulnerable = true;
                                evidenceDesc = `Command output detected in response! Matched signatures: ${matchedSigs.join(", ")}. The injected OS command (${label}) was executed by the server and its output was returned.`;
                            }
                        }

                        // Shell error leak detection
                        const shellErrors = SHELL_ERROR_SIGNATURES.filter(sig => lowerBody.includes(sig.toLowerCase()));
                        if (shellErrors.length > 0 && !isVulnerable) {
                            isVulnerable = true;
                            evidenceDesc = `Shell error signatures detected in response: ${shellErrors.join(", ")}. The server attempted to execute the payload as a system command, leaking shell error details.`;
                        }

                        if (isVulnerable) {
                            foundEndpoints.add(endpointKey);
                            findings.push({
                                checkType: "command-injection",
                                severity: "CRITICAL",
                                title: `Command Injection (${label}): ${endpoint.method} ${endpoint.path}`,
                                description: `${evidenceDesc}\n\nPayload: ${payload}\nTechnique: ${technique}`,
                                evidence: this.buildEvidence(injPoint.url, endpoint.method, headers, response, payload, elapsed),
                                owaspMapping: this.owaspMapping,
                                owaspId: this.owaspId,
                                remediation: `CRITICAL: Never pass user input to system commands. Use safe alternatives:\n\n\`\`\`javascript\n//  VULNERABLE — Direct command execution with user input\nconst { exec } = require('child_process');\nexec(\`ping \${req.query.host}\`); // Attacker sends: 127.0.0.1; rm -rf /\n\n//  SECURE — Use execFile with argument arrays (no shell expansion)\nconst { execFile } = require('child_process');\nexecFile('ping', ['-c', '4', validatedHost], (err, stdout) => {\n  res.send(stdout);\n});\n\n//  SECURE — Use purpose-built libraries instead of shell commands\nconst dns = require('dns');\ndns.lookup(validatedHost, (err, address) => {\n  res.json({ address });\n});\n\`\`\`\n\nAdditional defenses:\n- Never use exec(), system(), or popen() with user input\n- Use execFile() or spawn() with argument arrays\n- Implement strict input validation (alphanumeric-only allow-lists)\n- Run application processes in sandboxed containers with minimal privileges`,
                                endpoint: endpoint.path,
                                method: endpoint.method,
                            });
                            break;
                        }
                    }
                } catch (err) {
                    log.debug(`CMDi test skipped: ${err instanceof Error ? err.message : String(err)}`);
                }
            }
        }

        return findings;
    }

    private buildInjectionPoints(baseUrl: string, endpoint: { path: string; method: string; parameters?: { name: string; in: string }[]; requestBody?: string }, payload: string): { url: string; body?: unknown }[] {
        const results: { url: string; body?: unknown }[] = [];
        const encoded = encodeURIComponent(payload);

        // Query parameters
        const paramName = endpoint.parameters?.find(p => p.in === "query")?.name || "host";
        const sep = baseUrl.includes("?") ? "&" : "?";
        results.push({ url: `${baseUrl}${sep}${paramName}=${encoded}` });

        // Also try common command-injection-prone parameters
        for (const p of ["cmd", "exec", "command", "ping", "ip", "host", "url", "filename", "file", "path"]) {
            results.push({ url: `${baseUrl}${sep}${p}=${encoded}` });
        }

        // Path injection
        const pathInjected = baseUrl.replace(/\/([^/]+)$/, `/${encoded}`);
        if (pathInjected !== baseUrl) {
            results.push({ url: pathInjected });
        }

        // Body injection for POST/PUT/PATCH
        if (["post", "put", "patch"].includes(endpoint.method.toLowerCase())) {
            if (endpoint.requestBody) {
                try {
                    const body = JSON.parse(endpoint.requestBody);
                    for (const key of Object.keys(body)) {
                        if (typeof body[key] === "string") {
                            results.push({ url: baseUrl, body: { ...body, [key]: payload } });
                            break;
                        }
                    }
                } catch {
                    results.push({ url: baseUrl, body: { input: payload } });
                }
            } else {
                results.push({ url: baseUrl, body: { command: payload, input: payload, host: payload } });
            }
        }

        return results;
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
            description: `Command injection probe sent to ${method} ${url}`,
            payload,
        };
    }
}
