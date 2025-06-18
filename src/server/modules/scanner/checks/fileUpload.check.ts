import { AxiosResponse } from "axios";
import { scannerClient } from "@/server/core/http/scanner-client";
import { SecurityCheck, ScanTarget, FindingResult, Evidence } from "@/types";
import { logger } from "@/server/core/logging/logger";

const log = logger.child("file-upload-check");

/* ─── Malicious File Upload Payloads ─── */
const UPLOAD_TESTS: {
    filename: string;
    contentType: string;
    body: string;
    label: string;
    severity: "CRITICAL" | "HIGH" | "MEDIUM";
    attackType: string;
}[] = [
        // Web shell uploads
        {
            filename: "shell.php",
            contentType: "application/x-php",
            body: "<?php echo 'SECURISCAN_WEBSHELL_PROBE'; ?>",
            label: "PHP web shell upload",
            severity: "CRITICAL",
            attackType: "webshell",
        },
        {
            filename: "shell.jsp",
            contentType: "application/x-jsp",
            body: "<% out.print(\"SECURISCAN_WEBSHELL_PROBE\"); %>",
            label: "JSP web shell upload",
            severity: "CRITICAL",
            attackType: "webshell",
        },
        {
            filename: "shell.aspx",
            contentType: "application/octet-stream",
            body: "<%@ Page Language=\"C#\" %><% Response.Write(\"SECURISCAN_WEBSHELL_PROBE\"); %>",
            label: "ASPX web shell upload",
            severity: "CRITICAL",
            attackType: "webshell",
        },

        // Double extension bypass
        {
            filename: "image.php.jpg",
            contentType: "image/jpeg",
            body: "<?php echo 'SECURISCAN_DOUBLE_EXT'; ?>",
            label: "Double extension bypass (.php.jpg)",
            severity: "HIGH",
            attackType: "extension-bypass",
        },
        {
            filename: "doc.php%00.pdf",
            contentType: "application/pdf",
            body: "<?php echo 'SECURISCAN_NULL_BYTE'; ?>",
            label: "Null byte extension bypass (.php%00.pdf)",
            severity: "HIGH",
            attackType: "extension-bypass",
        },
        {
            filename: "script.phtml",
            contentType: "text/html",
            body: "<?php echo 'SECURISCAN_ALT_EXT'; ?>",
            label: "Alternative PHP extension (.phtml)",
            severity: "HIGH",
            attackType: "extension-bypass",
        },
        {
            filename: "test.php5",
            contentType: "application/octet-stream",
            body: "<?php echo 'SECURISCAN_PHP5'; ?>",
            label: "PHP5 extension bypass",
            severity: "HIGH",
            attackType: "extension-bypass",
        },

        // Content-Type mismatch
        {
            filename: "image.jpg",
            contentType: "image/jpeg",
            body: "<?php system($_GET['cmd']); ?>",
            label: "Content-Type spoofing (PHP in JPEG header)",
            severity: "HIGH",
            attackType: "content-type-spoofing",
        },

        // SVG XSS
        {
            filename: "evil.svg",
            contentType: "image/svg+xml",
            body: `<svg xmlns="http://www.w3.org/2000/svg" onload="alert('SECURISCAN_SVG_XSS')"><text>test</text></svg>`,
            label: "SVG with JavaScript (XSS via upload)",
            severity: "HIGH",
            attackType: "svg-xss",
        },

        // HTML upload
        {
            filename: "malicious.html",
            contentType: "text/html",
            body: `<html><body><script>alert('SECURISCAN_HTML_XSS')</script></body></html>`,
            label: "HTML file upload (stored XSS)",
            severity: "HIGH",
            attackType: "html-xss",
        },

        // Server-Side Template Injection via upload
        {
            filename: "template.txt",
            contentType: "text/plain",
            body: "{{7*7}}${7*7}<%=7*7%>",
            label: "SSTI probe via file content",
            severity: "HIGH",
            attackType: "ssti",
        },

        // Path traversal via filename
        {
            filename: "../../../etc/passwd",
            contentType: "text/plain",
            body: "path_traversal_test",
            label: "Path traversal in filename",
            severity: "CRITICAL",
            attackType: "path-traversal",
        },
        {
            filename: "..\\..\\..\\windows\\system.ini",
            contentType: "text/plain",
            body: "path_traversal_test",
            label: "Windows path traversal in filename",
            severity: "CRITICAL",
            attackType: "path-traversal",
        },

        // Oversized filename
        {
            filename: "A".repeat(500) + ".txt",
            contentType: "text/plain",
            body: "buffer_overflow_test",
            label: "Oversized filename (500 chars)",
            severity: "MEDIUM",
            attackType: "overflow",
        },

        // .exe / .bat upload
        {
            filename: "exploit.exe",
            contentType: "application/x-msdownload",
            body: "MZ_FAKE_HEADER",
            label: "Executable file upload (.exe)",
            severity: "HIGH",
            attackType: "executable",
        },
        {
            filename: "exploit.bat",
            contentType: "application/x-msdos-program",
            body: "@echo off\necho SECURISCAN_BAT_PROBE",
            label: "Batch file upload (.bat)",
            severity: "HIGH",
            attackType: "executable",
        },
    ];

export class FileUploadCheck implements SecurityCheck {
    name = "File Upload Security Check";
    description = "Tests for unrestricted file uploads including web shell uploads, extension bypass, content-type spoofing, SVG XSS, path traversal in filenames, and executable uploads";
    owaspMapping = "Security Misconfiguration";
    owaspId = "API8:2023";

    async run(target: ScanTarget): Promise<FindingResult[]> {
        const findings: FindingResult[] = [];

        // Identify upload endpoints (heuristic)
        const uploadEndpoints = target.endpoints.filter(ep => {
            const lower = `${ep.path} ${ep.description || ""}`.toLowerCase();
            return (
                ["post", "put", "patch"].includes(ep.method.toLowerCase()) &&
                (lower.includes("upload") || lower.includes("file") || lower.includes("image") ||
                    lower.includes("avatar") || lower.includes("attach") || lower.includes("document") ||
                    lower.includes("media") || lower.includes("import") || lower.includes("photo"))
            );
        });

        // Also test all POST endpoints as potential upload targets
        const postEndpoints = target.endpoints.filter(
            ep => ep.method.toLowerCase() === "post" && !uploadEndpoints.some(u => u.path === ep.path)
        );

        const allTargetEndpoints = [...uploadEndpoints, ...postEndpoints.slice(0, 5)];

        for (const endpoint of allTargetEndpoints) {
            const url = `${target.baseUrl}${endpoint.path}`;
            const foundTypes = new Set<string>();

            for (const test of UPLOAD_TESTS) {
                if (foundTypes.has(test.attackType)) continue;

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

                    // Build multipart form data manually
                    const boundary = "----SecuriScanBoundary" + Date.now();
                    headers["Content-Type"] = `multipart/form-data; boundary=${boundary}`;

                    const body = [
                        `--${boundary}`,
                        `Content-Disposition: form-data; name="file"; filename="${test.filename}"`,
                        `Content-Type: ${test.contentType}`,
                        "",
                        test.body,
                        `--${boundary}--`,
                    ].join("\r\n");

                    const response = await scannerClient({
                        requestsPerSecond: target.requestsPerSecond,
                        method: endpoint.method.toLowerCase(),
                        url,
                        timeout: 15000,
                        validateStatus: () => true,
                        headers,
                        data: body,
                    });

                    const responseBody = typeof response.data === "string"
                        ? response.data
                        : JSON.stringify(response.data || "");
                    const lower = responseBody.toLowerCase();

                    let isVulnerable = false;
                    let evidenceDesc = "";

                    // File was accepted (2xx response)
                    if (response.status >= 200 && response.status < 300) {
                        // Check if it returned a file URL (indicating storage)
                        if (lower.includes("url") || lower.includes("path") || lower.includes("location") || lower.includes("filename")) {
                            isVulnerable = true;
                            evidenceDesc = `The server accepted the upload of "${test.filename}" (${test.contentType}) and returned HTTP ${response.status} with potential file location data. This indicates the file was stored without proper validation of its extension, content, or content-type.`;
                        } else {
                            isVulnerable = true;
                            evidenceDesc = `The server accepted the upload of "${test.filename}" (${test.contentType}) and returned HTTP ${response.status}. The file may have been stored without proper security validation.`;
                        }
                    }

                    // Check for webshell execution markers in response
                    if (lower.includes("securiscan_") || lower.includes("49")) {
                        isVulnerable = true;
                        evidenceDesc = `CRITICAL: The uploaded file appears to have been EXECUTED by the server! The output of the payload was detected in the response. The file "${test.filename}" was not only stored but also interpreted/executed.`;
                    }

                    if (isVulnerable) {
                        foundTypes.add(test.attackType);
                        findings.push({
                            checkType: "file-upload",
                            severity: test.severity,
                            title: `${test.label}: ${endpoint.method} ${endpoint.path}`,
                            description: evidenceDesc,
                            evidence: this.buildEvidence(url, endpoint.method, headers, response, test.filename),
                            owaspMapping: this.owaspMapping,
                            owaspId: this.owaspId,
                            remediation: this.getRemediation(test.attackType),
                            endpoint: endpoint.path,
                            method: endpoint.method,
                        });
                    }
                } catch (err) {
                    log.debug(`File upload test skipped for ${url} [${test.label}]: ${err instanceof Error ? err.message : String(err)}`);
                }
            }
        }

        return findings;
    }

    private getRemediation(attackType: string): string {
        const rems: Record<string, string> = {
            "webshell": `CRITICAL: Implement strict file upload validation:\n\n\`\`\`javascript\nconst ALLOWED_EXTENSIONS = ['.jpg', '.jpeg', '.png', '.gif', '.pdf'];\nconst ALLOWED_MIMES = ['image/jpeg', 'image/png', 'image/gif', 'application/pdf'];\n\n// 1. Validate extension\nconst ext = path.extname(file.originalname).toLowerCase();\nif (!ALLOWED_EXTENSIONS.includes(ext)) {\n  return res.status(400).json({ error: 'File type not allowed' });\n}\n\n// 2. Validate MIME type via magic bytes (not Content-Type header)\nconst fileType = await fileTypeFromBuffer(buffer);\nif (!fileType || !ALLOWED_MIMES.includes(fileType.mime)) {\n  return res.status(400).json({ error: 'Invalid file content' });\n}\n\n// 3. Rename file to prevent execution\nconst safeName = crypto.randomUUID() + ext;\n\n// 4. Store outside web root\nawait fs.writeFile(path.join('/data/uploads/', safeName), buffer);\n\`\`\``,
            "extension-bypass": `Block double extensions and null bytes:\n\n\`\`\`javascript\n// Strip null bytes and double extensions\nconst sanitized = filename.replace(/\\0/g, '').replace(/\\.[^.]+(?=\\.[^.]+$)/, '');\nconst ext = path.extname(sanitized).toLowerCase();\n\nif (!ALLOWED_EXTENSIONS.includes(ext)) {\n  return res.status(400).json({ error: 'File type not allowed' });\n}\n\`\`\``,
            "content-type-spoofing": `Always validate file content via magic bytes, never trust Content-Type headers:\n\n\`\`\`javascript\nimport { fileTypeFromBuffer } from 'file-type';\n\nconst detected = await fileTypeFromBuffer(fileBuffer);\nif (!detected || detected.mime !== expectedMime) {\n  return res.status(400).json({ error: 'File content does not match type' });\n}\n\`\`\``,
            "svg-xss": `Sanitize SVG files or convert them to safe formats:\n\n\`\`\`javascript\nimport DOMPurify from 'isomorphic-dompurify';\nconst cleanSvg = DOMPurify.sanitize(svgContent, {\n  USE_PROFILES: { svg: true },\n  ADD_TAGS: ['svg', 'path', 'circle', 'rect'],\n  FORBID_TAGS: ['script', 'foreignObject'],\n  FORBID_ATTR: ['onload', 'onclick', 'onerror'],\n});\n\`\`\``,
            "html-xss": "Reject HTML file uploads entirely, or sanitize them with DOMPurify. Serve user-uploaded content from a separate domain with strict CSP headers.",
            "ssti": "Never render user-uploaded content through a template engine. Treat all uploaded files as static blobs and serve them with Content-Disposition: attachment.",
            "path-traversal": `Sanitize filenames to prevent path traversal:\n\n\`\`\`javascript\nconst path = require('path');\n\n// Strip directory components\nconst safeName = path.basename(filename).replace(/[^a-zA-Z0-9._-]/g, '_');\n\n// Ensure the resolved path stays within uploads directory\nconst resolved = path.resolve('/data/uploads/', safeName);\nif (!resolved.startsWith('/data/uploads/')) {\n  return res.status(400).json({ error: 'Invalid filename' });\n}\n\`\`\``,
            "overflow": "Enforce maximum filename length (e.g., 255 characters) and maximum file size limits on the server side.",
            "executable": "Block all executable file types (.exe, .bat, .sh, .cmd, .ps1, .msi). Maintain a strict allowlist of permitted extensions rather than a denylist.",
        };
        return rems[attackType] || "Implement strict file upload validation with extension allowlists, magic byte verification, and storage outside the web root.";
    }

    private buildEvidence(url: string, method: string, headers: Record<string, string>, response: AxiosResponse, filename: string): Evidence {
        return {
            request: { url, method, headers },
            response: {
                status: response.status,
                headers: response.headers as Record<string, string>,
                body: typeof response.data === "object" ? response.data : String(response.data).slice(0, 500),
            },
            description: `File upload probe: attempted to upload "${filename}" to ${method} ${url}`,
            payload: filename,
        };
    }
}
