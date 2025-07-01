import { NextRequest, NextResponse } from "next/server";
import { auth } from "@/lib/auth";
import prisma from "@/lib/prisma";

type Ctx = { params: Promise<{ projectId: string }> };

// GET — list teams linked to a project
export async function GET(_req: NextRequest, ctx: Ctx) {
    const session = await auth();
    if (!session?.user?.id) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
    const { projectId } = await ctx.params;

    const links = await prisma.teamsOnProjects.findMany({
        where: { projectId },
        include: { team: { include: { _count: { select: { members: true } }, owner: { select: { id: true, name: true } } } } },
        orderBy: { assignedAt: "desc" },
    });

    return NextResponse.json(links.map(l => ({ ...l.team, assignedAt: l.assignedAt, linkId: l.id })));
}

// POST — link a team to a project
export async function POST(req: NextRequest, ctx: Ctx) {
    const session = await auth();
    if (!session?.user?.id) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
    const { projectId } = await ctx.params;

    const membership = await prisma.projectMember.findFirst({
        where: { projectId, userId: session.user.id, role: { in: ["OWNER", "ADMIN"] } },
    });
    if (!membership) return NextResponse.json({ error: "Only owners/admins can link teams" }, { status: 403 });

    const { teamId } = await req.json();
    if (!teamId) return NextResponse.json({ error: "teamId is required" }, { status: 400 });

    const team = await prisma.team.findFirst({
        where: { id: teamId, OR: [{ ownerId: session.user.id }, { members: { some: { userId: session.user.id } } }] },
    });
    if (!team) return NextResponse.json({ error: "Team not found or you don't have access" }, { status: 404 });

    const existing = await prisma.teamsOnProjects.findUnique({
        where: { teamId_projectId: { teamId, projectId } },
    });
    if (existing) return NextResponse.json({ error: "Team is already linked to this project" }, { status: 409 });

    const link = await prisma.teamsOnProjects.create({
        data: { teamId, projectId },
        include: { team: { include: { _count: { select: { members: true } }, owner: { select: { id: true, name: true } } } } },
    });

    return NextResponse.json(link, { status: 201 });
}

// DELETE — unlink a team from a project
export async function DELETE(req: NextRequest, ctx: Ctx) {
    const session = await auth();
    if (!session?.user?.id) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
    const { projectId } = await ctx.params;

    const membership = await prisma.projectMember.findFirst({
        where: { projectId, userId: session.user.id, role: { in: ["OWNER", "ADMIN"] } },
    });
    if (!membership) return NextResponse.json({ error: "Forbidden" }, { status: 403 });

    const { searchParams } = new URL(req.url);
    const teamId = searchParams.get("teamId");
    if (!teamId) return NextResponse.json({ error: "teamId is required" }, { status: 400 });

    await prisma.teamsOnProjects.deleteMany({ where: { teamId, projectId } });
    return NextResponse.json({ success: true });
}
