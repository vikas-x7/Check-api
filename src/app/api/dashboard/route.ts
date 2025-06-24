import { NextResponse } from "next/server";
import { auth } from "@/lib/auth";
import prisma from "@/lib/prisma";
import { startOfDay, subDays, format } from "date-fns";

type RecentScan = Awaited<
    ReturnType<
        typeof prisma.scan.findMany<{
            include: { _count: { select: { findings: true } } };
        }>
    >
>[number];

// GET /api/dashboard — Get dashboard statistics
export async function GET() {
    const session = await auth();
    if (!session?.user?.id) {
        return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
    }

    const userId = session.user.id;

    // Parallel fetch core counts
    const [scans, findings, recentScans, criticalFindings] = await Promise.all([
        prisma.scan.count({ where: { userId } }),
        prisma.finding.count({ where: { scan: { userId } } }),
        prisma.scan.findMany({
            where: { userId },
            include: { _count: { select: { findings: true } } },
            orderBy: { createdAt: "desc" },
            take: 10,
        }),
        prisma.finding.count({ where: { scan: { userId }, severity: "CRITICAL" } }),
    ]);

    // Aggregate Severity
    const severityDist = await prisma.finding.groupBy({
        by: ["severity"],
        where: { scan: { userId } },
        _count: true,
    });

    // Aggregate by Check Type (Top 10)
    const findingsByCheck = await prisma.finding.groupBy({
        by: ["checkType"],
        where: { scan: { userId } },
        _count: true,
        orderBy: { _count: { checkType: 'desc' } },
        take: 10,
    });

    // Aggregate by OWASP Category
    const findingsByOwasp = await prisma.finding.groupBy({
        by: ["owaspId"],
        where: { scan: { userId }, owaspId: { not: "" } },
        _count: true,
    });

    // 7-day Trend Timeline (Findings discovered per day)
    const last7Days = Array.from({ length: 7 }, (_, i) => {
        return startOfDay(subDays(new Date(), i));
    }).reverse();

    const timelineData = await Promise.all(
        last7Days.map(async (day) => {
            const nextDay = new Date(day.getTime() + 24 * 60 * 60 * 1000);
            const count = await prisma.finding.count({
                where: {
                    scan: { userId },
                    createdAt: { gte: day, lt: nextDay }
                }
            });
            const crit = await prisma.finding.count({
                where: {
                    scan: { userId },
                    severity: "CRITICAL",
                    createdAt: { gte: day, lt: nextDay }
                }
            });
            return { date: format(day, "MMM dd"), total: count, critical: crit };
        })
    );

    return NextResponse.json({
        totalScans: scans,
        totalFindings: findings,
        criticalFindings,
        severityDistribution: severityDist,
        findingsByCheck: findingsByCheck.map(f => ({ checkType: f.checkType, count: f._count })),
        findingsByOwasp: findingsByOwasp.map(f => ({ owaspId: f.owaspId, count: f._count })),
        timeline: timelineData,
        recentScans: recentScans.map((s: RecentScan) => ({
            id: s.id,
            targetUrl: s.targetUrl,
            status: s.status,
            progress: s.progress,
            findingsCount: s._count.findings,
            createdAt: s.createdAt.toISOString(),
        })),
    });
}
