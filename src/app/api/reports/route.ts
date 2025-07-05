import { NextRequest, NextResponse } from "next/server";
import { auth } from "@/lib/auth";
import prisma from "@/lib/prisma";
import { mapFindingsToOWASP, calculateRiskScore } from "@/server/modules/report/mappers/owasp.mapper";
import { FindingResult } from "@/types";
import { logger } from "@/server/core/logging/logger";
import { ApiError } from "@/server/core/errors/api-error";
import { handleError } from "@/server/core/errors/handler";

const log = logger.child("reports-route");

export async function POST(req: NextRequest) {
    const session = await auth();
    if (!session?.user?.id) {
        const response = handleError(ApiError.unauthorized());
        return NextResponse.json(response.payload, { status: response.status });
    }

    try {
        const { scanId, format = "JSON" } = await req.json();

        const scan = await prisma.scan.findFirst({
            where: { id: scanId, userId: session.user.id },
            include: { findings: true },
        });

        if (!scan) {
            const response = handleError(ApiError.notFound("Scan not found"));
            return NextResponse.json(response.payload, { status: response.status });
        }

        const findings: FindingResult[] = scan.findings.map((f) => ({
            id: f.id,
            checkType: f.checkType,
            severity: f.severity as FindingResult["severity"],
            title: f.title,
            description: f.description,
            evidence: f.evidence as any, // eslint-disable-line @typescript-eslint/no-explicit-any
            owaspMapping: f.owaspMapping,
            owaspId: f.owaspId,
            remediation: f.remediation,
            endpoint: f.endpoint || undefined,
            method: f.method || undefined,
        }));

        const owaspCoverage = mapFindingsToOWASP(findings);
        const riskScore = calculateRiskScore(findings);

        const reportData = {
            scan: {
                id: scan.id,
                targetUrl: scan.targetUrl,
                status: scan.status,
                intensity: scan.intensity,
                startedAt: scan.startedAt?.toISOString() || "",
                completedAt: scan.completedAt?.toISOString() || "",
            },
            findings,
            summary: {
                total: findings.length,
                critical: findings.filter((f) => f.severity === "CRITICAL").length,
                high: findings.filter((f) => f.severity === "HIGH").length,
                medium: findings.filter((f) => f.severity === "MEDIUM").length,
                low: findings.filter((f) => f.severity === "LOW").length,
                info: findings.filter((f) => f.severity === "INFO").length,
                riskScore,
            },
            owaspCoverage,
        };

        const report = await prisma.report.create({
            data: {
                scanId: scan.id,
                format: format as any, // eslint-disable-line @typescript-eslint/no-explicit-any
                data: reportData as any, // eslint-disable-line @typescript-eslint/no-explicit-any
            },
        });

        log.info("Created report", { reportId: report.id, scanId: scan.id });
        return NextResponse.json({ ...report, reportData }, { status: 201 });
    } catch (error) {
        const response = handleError(error);
        return NextResponse.json(response.payload, { status: response.status });
    }
}

export async function GET() {
    const session = await auth();
    if (!session?.user?.id) {
        const response = handleError(ApiError.unauthorized());
        return NextResponse.json(response.payload, { status: response.status });
    }

    const reports = await prisma.report.findMany({
        where: { scan: { userId: session.user.id } },
        include: { scan: { select: { targetUrl: true, status: true } } },
        orderBy: { createdAt: "desc" },
    });

    log.info("Fetched reports", { userId: session.user.id, count: reports.length });
    return NextResponse.json(reports);
}
