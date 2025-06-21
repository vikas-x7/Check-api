import { NextRequest, NextResponse } from "next/server";
import { auth } from "@/lib/auth";
import prisma from "@/lib/prisma";
import { logger } from "@/server/core/logging/logger";
import { ApiError } from "@/server/core/errors/api-error";
import { handleError } from "@/server/core/errors/handler";

const log = logger.child("scan-id-route");

export async function GET(
    req: NextRequest,
    { params }: { params: Promise<{ scanId: string }> }
) {
    const session = await auth();
    if (!session?.user?.id) {
        const response = handleError(ApiError.unauthorized());
        return NextResponse.json(response.payload, { status: response.status });
    }

    try {
        const { scanId } = await params;

        const scan = await prisma.scan.findFirst({
            where: { id: scanId, userId: session.user.id },
            include: {
                findings: { orderBy: { severity: "asc" } },
                reports: true,
            },
        });

        if (!scan) {
            const response = handleError(ApiError.notFound("Scan not found"));
            return NextResponse.json(response.payload, { status: response.status });
        }

        log.info("Fetched scan details", { scanId, userId: session.user.id });
        return NextResponse.json(scan);
    } catch (error) {
        const response = handleError(error);
        return NextResponse.json(response.payload, { status: response.status });
    }
}

export async function DELETE(
    req: NextRequest,
    { params }: { params: Promise<{ scanId: string }> }
) {
    const session = await auth();
    if (!session?.user?.id) {
        const response = handleError(ApiError.unauthorized());
        return NextResponse.json(response.payload, { status: response.status });
    }

    try {
        const { scanId } = await params;
        const deleted = await prisma.scan.deleteMany({
            where: { id: scanId, userId: session.user.id },
        });

        log.info("Deleted scan", { scanId, userId: session.user.id, deletedCount: deleted.count });
        return NextResponse.json({ success: true });
    } catch (error) {
        const response = handleError(error);
        return NextResponse.json(response.payload, { status: response.status });
    }
}
