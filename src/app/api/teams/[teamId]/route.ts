import { NextRequest, NextResponse } from "next/server";
import { auth } from "@/lib/auth";

import prisma from "@/lib/prisma";

type Ctx = { params: Promise<{ teamId: string }> };

export async function GET(_req: NextRequest, ctx: Ctx) {
    const session = await auth();
    if (!session?.user?.id) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
    const { teamId } = await ctx.params;

    const team = await prisma.team.findFirst({
        where: {
            id: teamId,
            OR: [{ ownerId: session.user.id }, { members: { some: { userId: session.user.id } } }],
        },
        include: {
            owner: { select: { id: true, name: true, email: true } },
            members: { include: { user: { select: { id: true, name: true, email: true } } }, orderBy: { joinedAt: "asc" } },
            projects: { include: { project: { select: { id: true, name: true, color: true, owner: { select: { name: true } }, _count: { select: { scans: true } } } } } },
            invitations: { where: { status: "PENDING", type: "TEAM" }, include: { receiver: { select: { id: true, name: true, email: true } } } },
            _count: { select: { members: true } },
        },
    });

    if (!team) return NextResponse.json({ error: "Team not found" }, { status: 404 });
    return NextResponse.json(team);
}

export async function PATCH(req: NextRequest, ctx: Ctx) {
    const session = await auth();
    if (!session?.user?.id) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
    const { teamId } = await ctx.params;

    const membership = await prisma.teamMember.findFirst({
        where: { teamId, userId: session.user.id, role: "LEADER" },
    });
    if (!membership) return NextResponse.json({ error: "Only team leaders can edit" }, { status: 403 });

    const body = await req.json();
    const team = await prisma.team.update({
        where: { id: teamId },
        data: {
            ...(body.name ? { name: body.name.trim() } : {}),
            ...(body.description !== undefined ? { description: body.description?.trim() || null } : {}),
            ...(body.color ? { color: body.color } : {}),
        },
        include: { owner: { select: { id: true, name: true, email: true } }, _count: { select: { members: true } } },
    });

    return NextResponse.json(team);
}

export async function DELETE(_req: NextRequest, ctx: Ctx) {
    const session = await auth();
    if (!session?.user?.id) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
    const { teamId } = await ctx.params;

    const team = await prisma.team.findFirst({ where: { id: teamId, ownerId: session.user.id } });
    if (!team) return NextResponse.json({ error: "Only the team owner can delete it" }, { status: 403 });

    await prisma.team.delete({ where: { id: teamId } });
    return NextResponse.json({ success: true });
}
