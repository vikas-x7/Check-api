import { NextRequest, NextResponse } from "next/server";
import { auth } from "@/lib/auth";

import prisma from "@/lib/prisma";

type Ctx = { params: Promise<{ projectId: string }> };

export async function GET(_req: NextRequest, ctx: Ctx) {
    const session = await auth();
    if (!session?.user?.id) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
    const { projectId } = await ctx.params;

    const project = await prisma.project.findFirst({
        where: {
            id: projectId,
            OR: [
                { ownerId: session.user.id },
                { members: { some: { userId: session.user.id } } },
                { teams: { some: { team: { OR: [{ ownerId: session.user.id }, { members: { some: { userId: session.user.id } } }] } } } }
            ],
        },
        include: {
            owner: { select: { id: true, name: true, email: true } },
            members: { include: { user: { select: { id: true, name: true, email: true } } }, orderBy: { joinedAt: "asc" } },
            scans: { orderBy: { createdAt: "desc" }, take: 20, include: { _count: { select: { findings: true } }, findings: { select: { id: true, severity: true, checkType: true, owaspId: true, endpoint: true } } } },
            teams: { include: { team: { select: { id: true, name: true, color: true, owner: { select: { name: true } }, _count: { select: { members: true } } } } } },
            invitations: { where: { status: "PENDING", type: "PROJECT" }, include: { receiver: { select: { id: true, name: true, email: true } } } },
            _count: { select: { scans: true, members: true } },
        },
    });

    if (!project) return NextResponse.json({ error: "Project not found" }, { status: 404 });
    return NextResponse.json(project);
}

export async function PATCH(req: NextRequest, ctx: Ctx) {
    const session = await auth();
    if (!session?.user?.id) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
    const { projectId } = await ctx.params;

    const membership = await prisma.projectMember.findFirst({
        where: { projectId, userId: session.user.id, role: { in: ["OWNER", "ADMIN"] } },
    });
    if (!membership) return NextResponse.json({ error: "Forbidden" }, { status: 403 });

    const body = await req.json();
    const project = await prisma.project.update({
        where: { id: projectId },
        data: {
            ...(body.name ? { name: body.name.trim() } : {}),
            ...(body.description !== undefined ? { description: body.description?.trim() || null } : {}),
            ...(body.color ? { color: body.color } : {}),
        },
        include: { owner: { select: { id: true, name: true, email: true } }, _count: { select: { scans: true, members: true } } },
    });

    return NextResponse.json(project);
}

export async function DELETE(_req: NextRequest, ctx: Ctx) {
    const session = await auth();
    if (!session?.user?.id) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
    const { projectId } = await ctx.params;

    const project = await prisma.project.findFirst({ where: { id: projectId, ownerId: session.user.id } });
    if (!project) return NextResponse.json({ error: "Only the project owner can delete it" }, { status: 403 });

    await prisma.project.delete({ where: { id: projectId } });
    return NextResponse.json({ success: true });
}
