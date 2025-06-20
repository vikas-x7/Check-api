import { EndpointInfo, ParameterInfo } from "@/types";
import yaml from "js-yaml";
import { logger } from "@/server/core/logging/logger";
import { ApiError } from "@/server/core/errors/api-error";

interface OpenAPIParameter {
    name?: string;
    in?: string;
    schema?: { type?: string; example?: unknown };
    type?: string;
    required?: boolean;
    example?: unknown;
}

interface OpenAPIOperation {
    summary?: string;
    description?: string;
    parameters?: OpenAPIParameter[];
}

interface OpenAPISpec {
    openapi?: string;
    swagger?: string;
    paths?: Record<string, Record<string, OpenAPIOperation>>;
    servers?: { url: string }[];
    host?: string;
    basePath?: string;
}

export class OpenAPIParser {
    static parse(content: string): { endpoints: EndpointInfo[]; baseUrl?: string } {
        let spec: OpenAPISpec;

        try {
            spec = JSON.parse(content);
        } catch {
            try {
                spec = yaml.load(content) as OpenAPISpec;
            } catch {
                throw new Error("Invalid OpenAPI spec: must be valid JSON or YAML");
            }
        }

        if (!spec.paths) {
            logger.warn("Parsed OpenAPI document has no paths", { spec });
            throw new ApiError("Invalid OpenAPI spec: no paths defined", { statusCode: 422, code: "E_INVALID_OPENAPI" });
        }

        const endpoints: EndpointInfo[] = [];
        let baseUrl: string | undefined;

        // Extract base URL
        if (spec.servers?.[0]?.url) {
            baseUrl = spec.servers[0].url;
        } else if (spec.host) {
            baseUrl = `http${spec.host.includes("localhost") ? "" : "s"}://${spec.host}${spec.basePath || ""}`;
        }

        // Extract endpoints
        for (const [path, methods] of Object.entries(spec.paths)) {
            for (const [method, operation] of Object.entries(methods)) {
                if (["get", "post", "put", "delete", "patch"].includes(method.toLowerCase())) {
                    const params = (operation.parameters || [])
                        .filter((p: OpenAPIParameter) => typeof p.name === "string")
                        .map((p: OpenAPIParameter) => {
                            const paramIn = p.in as ParameterInfo["in"];
                            const rawExample = p.example ?? p.schema?.example;
                            const normalizedExample = typeof rawExample === "string" ? rawExample : undefined;

                            return {
                                name: p.name as string,
                                in: paramIn || "query",
                                type: p.schema?.type || p.type || "string",
                                required: p.required || false,
                                example: normalizedExample,
                            };
                        });

                    endpoints.push({
                        path: path.replace(/{(\w+)}/g, (_, name) => {
                            const param = params.find((p) => p.name === name);
                            return String(param?.example || "1");
                        }),
                        method: method.toUpperCase(),
                        description: operation.summary || operation.description || "",
                        parameters: params,
                    });
                }
            }
        }

        return { endpoints, baseUrl };
    }
}
