import { NextRequest, NextResponse } from "next/server";
import { auth } from "@/lib/auth";
import prisma from "@/lib/prisma";
import { z } from "zod";
import { ScannerEngine } from "@/server/modules/scanner/scanner.engine";
import { ALL_CHECKS } from "@/server/modules/scanner/checks";
import { OpenAPIParser } from "@/server/modules/openapi/parser.service";
import { ScanTarget, EndpointInfo } from "@/types";
import { logger } from "@/server/core/logging/logger";
import { ApiError } from "@/server/core/errors/api-error";
import { handleError } from "@/server/core/errors/handler";

const log = logger.child("scan-route");

const createScanSchema = z.object({
    targetUrl: z.string().url("Must be a valid URL"),
    intensity: z.enum(["LIGHT", "MEDIUM", "AGGRESSIVE"]).default("MEDIUM"),
    openApiSpec: z.string().optional(),
    projectId: z.string().optional(),
    endpoints: z.array(
        z.object({
            path: z.string().min(1),
            method: z.enum(["GET", "POST", "PUT", "DELETE", "PATCH"]).default("GET"),
            description: z.string().optional(),
            headers: z.record(z.string(), z.string()).optional(),
            body: z.string().optional(),
            queryParams: z.record(z.string(), z.string()).optional(),
        })
    ).optional(),
    authConfig: z.object({
        type: z.enum(["none", "api_key", "bearer", "jwt"]),
        value: z.string().optional(),
        headerName: z.string().optional(),
    }).optional(),
    requestsPerSecond: z.number().int().min(1).max(100).optional(),
});

export async function GET(req: NextRequest) {
    const session = await auth();
    if (!session?.user?.id) {
        const response = handleError(ApiError.unauthorized());
        return NextResponse.json(response.payload, { status: response.status });
    }

    const { searchParams } = new URL(req.url);
    const limit = parseInt(searchParams.get("limit") || "10");
    const cursor = searchParams.get("cursor");
    const search = searchParams.get("search");
    const status = searchParams.get("status");
    const intensity = searchParams.get("intensity");
    const minFindingsParam = searchParams.get("minFindings");
    const maxFindingsParam = searchParams.get("maxFindings");

    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const where: any = { userId: session.user.id };
    if (search) {
        where.targetUrl = { contains: search, mode: "insensitive" };
    }
    if (status) {
        where.status = status;
    }
    if (intensity) {
        where.intensity = intensity;
    }

    const scans = await prisma.scan.findMany({
        take: limit + 1,
        cursor: cursor ? { id: cursor } : undefined,
        where,
        include: { _count: { select: { findings: true } } },
        orderBy: { createdAt: "desc" },
    });

    let nextCursor: string | null = null;
    if (scans.length > limit) {
        const nextItem = scans.pop();
        nextCursor = nextItem!.id;
    }

    // Apply findings count filter in-memory
    const minFindings = minFindingsParam != null ? parseInt(minFindingsParam) : null;
    const maxFindings = maxFindingsParam != null ? parseInt(maxFindingsParam) : null;

    let filteredScans = scans;
    if (minFindings != null || maxFindings != null) {
        filteredScans = scans.filter(s => {
            const count = s._count.findings;
            if (minFindings != null && count < minFindings) return false;
            if (maxFindings != null && count > maxFindings) return false;
            return true;
        });
    }

    const mappedScans = filteredScans.map(s => ({
        id: s.id,
        targetUrl: s.targetUrl,
        status: s.status,
        intensity: s.intensity,
        progress: s.progress,
        findingsCount: s._count.findings,
        createdAt: s.createdAt.toISOString(),
        completedAt: s.completedAt?.toISOString() || null,
    }));

    return NextResponse.json({
        scans: mappedScans,
        nextCursor,
    });
}

export async function POST(req: NextRequest) {
    const session = await auth();
    if (!session?.user?.id) {
        const response = handleError(ApiError.unauthorized());
        return NextResponse.json(response.payload, { status: response.status });
    }

    try {
        const body = await req.json();
        const validated = createScanSchema.parse(body);

        let endpoints: EndpointInfo[] = [];
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        let parsedSpec: any = null;

        // Priority 1: OpenAPI spec
        if (validated.openApiSpec) {
            try {
                const parsed = OpenAPIParser.parse(validated.openApiSpec);
                endpoints = parsed.endpoints;
                parsedSpec = JSON.parse(validated.openApiSpec);
                log.info("OpenAPI spec parsed", { url: validated.targetUrl, endpointCount: endpoints.length });
            } catch (error) {
                log.warn("OpenAPI spec could not be parsed", { error });
            }
        }

        // Priority 2: Structured manual endpoints
        if (!validated.openApiSpec && validated.endpoints?.length) {
            endpoints = validated.endpoints.map((e) => {
                // Build path with query params if provided
                let path = e.path.startsWith("/") ? e.path : `/${e.path}`;
                if (e.queryParams && Object.keys(e.queryParams).length > 0) {
                    const qs = new URLSearchParams(e.queryParams as Record<string, string>).toString();
                    path = `${path}?${qs}`;
                }

                const endpointInfo: EndpointInfo = {
                    path,
                    method: e.method || "GET",
                    description: e.description,
                };

                // Attach custom headers and body as parameters for checks to use
                if (e.headers && Object.keys(e.headers).length > 0) {
                    endpointInfo.customHeaders = e.headers as Record<string, string>;
                }
                if (e.body) {
                    endpointInfo.requestBody = e.body;
                }

                return endpointInfo;
            });
            log.info("Manual endpoints loaded", { url: validated.targetUrl, endpointCount: endpoints.length });
        }

        // Require endpoints — no fallback
        if (!endpoints || endpoints.length === 0) {
            const response = handleError(ApiError.badRequest("At least one endpoint must be provided: upload an OpenAPI spec or define endpoints manually"));
            return NextResponse.json(response.payload, { status: response.status });
        }

        // Check Project permissions if projectId is provided
        if (validated.projectId) {
            const project = await prisma.project.findFirst({
                where: {
                    id: validated.projectId,
                    OR: [
                        { ownerId: session.user.id },
                        { members: { some: { userId: session.user.id } } },
                        { teams: { some: { team: { OR: [{ ownerId: session.user.id }, { members: { some: { userId: session.user.id } } }] } } } }
                    ],
                },
            });

            if (!project) {
                const response = handleError(ApiError.unauthorized("You do not have access to this project"));
                return NextResponse.json(response.payload, { status: response.status });
            }
        }

        const initialStatus = "RUNNING";
        const totalChecks = ALL_CHECKS.length || 0;

        const scan = await prisma.scan.create({
            data: {
                userId: session.user.id,
                targetUrl: validated.targetUrl,
                projectId: validated.projectId || null,
                intensity: validated.intensity,
                openApiSpec: parsedSpec,
                authConfig: validated.authConfig as any, // eslint-disable-line @typescript-eslint/no-explicit-any
                status: initialStatus,
                totalChecks,
                progress: 0,
                startedAt: new Date(),
            },
        });

        const target: ScanTarget = {
            baseUrl: validated.targetUrl.replace(/\/$/, ""),
            endpoints,
            authConfig: validated.authConfig,
            intensity: validated.intensity,
            requestsPerSecond: validated.requestsPerSecond,
        };

        const engine = new ScannerEngine();

        engine.setProgressCallback(async (progress) => {
            await prisma.scan.update({
                where: { id: scan.id },
                data: {
                    status: progress.status,
                    progress: progress.progress,
                    updatedAt: new Date(),
                },
            });
        });

        void (async () => {
            try {
                const findings = await engine.runScan(scan.id, target);

                const validFindings = findings.filter((f) => {
                    if (!f) {
                        log.warn("Scan engine returned undefined finding");
                        return false;
                    }
                    return true;
                });

                log.info("Persisting findings", { scanId: scan.id, findingCount: validFindings.length });

                await Promise.all(
                    validFindings.map(async (f) => {
                        try {
                            const severityRaw = (f.severity || "INFO").toString().toUpperCase();
                            const allowedSeverities = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];
                            const severity = allowedSeverities.includes(severityRaw) ? severityRaw : "INFO";

                            const title = f.title || `${f.checkType || "finding"}`;
                            const description = f.description || "";
                            const owaspMapping = f.owaspMapping || "Unknown OWASP mapping";
                            const owaspId = f.owaspId || "UNKNOWN";
                            const remediation = f.remediation || "No remediation provided.";

                            // eslint-disable-next-line @typescript-eslint/no-explicit-any
                            let safeEvidence: any = null;
                            try {
                                safeEvidence = f.evidence === undefined ? null : JSON.parse(JSON.stringify(f.evidence));
                            } catch {
                                safeEvidence = null;
                            }

                            await prisma.finding.create({
                                data: {
                                    scanId: scan.id,
                                    checkType: f.checkType || "unknown",
                                    severity: severity as "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO",
                                    title,
                                    description,
                                    evidence: safeEvidence,
                                    owaspMapping,
                                    owaspId,
                                    remediation,
                                    endpoint: f.endpoint || null,
                                    method: f.method || null,
                                },
                            });
                        } catch (err) {
                            log.error("Failed to persist finding", { scanId: scan.id, finding: f, error: err });
                        }
                    })
                );

                await prisma.scan.update({
                    where: { id: scan.id },
                    data: {
                        status: "COMPLETED",
                        progress: 100,
                        completedAt: new Date(),
                    },
                });

                log.info("Scan completed", { scanId: scan.id, findings: validFindings.length });
            } catch (err) {
                log.error("Scan execution failed", { scanId: scan.id, error: err });
                await prisma.scan.update({
                    where: { id: scan.id },
                    data: {
                        status: "FAILED",
                        progress: 100,
                        completedAt: new Date(),
                    },
                });
            }
        })();

        return NextResponse.json(scan, { status: 202 });
    } catch (error) {
        if (error instanceof z.ZodError) {
            const message = error.issues?.[0]?.message ?? "Invalid input";
            const response = handleError(ApiError.badRequest(message));
            return NextResponse.json(response.payload, { status: response.status });
        }

        const response = handleError(error);
        return NextResponse.json(response.payload, { status: response.status });
    }
}
