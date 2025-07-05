import { NextRequest, NextResponse } from "next/server";
import { auth } from "@/lib/auth";
import prisma from "@/lib/prisma";

type Ctx = { params: Promise<{ teamId: string }> };

// POST — invite a user to the team (creates invitation, NOT auto-add)
export async function POST(req: NextRequest, ctx: Ctx) {
    const session = await auth();
    if (!session?.user?.id) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
    const { teamId } = await ctx.params;

    const leadership = await prisma.teamMember.findFirst({
        where: { teamId, userId: session.user.id, role: "LEADER" },
    });
    if (!leadership) return NextResponse.json({ error: "Only leaders can invite" }, { status: 403 });

    const body = await req.json();
    const { email, role, message } = body;
    if (!email) return NextResponse.json({ error: "Email is required" }, { status: 400 });

    const user = await prisma.user.findUnique({ where: { email } });
    if (!user) return NextResponse.json({ error: "User not found" }, { status: 404 });
    if (user.id === session.user.id) return NextResponse.json({ error: "Cannot invite yourself" }, { status: 400 });

    const existing = await prisma.teamMember.findUnique({
        where: { teamId_userId: { teamId, userId: user.id } },
    });
    if (existing) return NextResponse.json({ error: "User is already a member" }, { status: 409 });

    const pending = await prisma.invitation.findFirst({
        where: { receiverId: user.id, teamId: teamId, type: "TEAM", status: "PENDING" },
    });
    if (pending) return NextResponse.json({ error: "Invitation already pending" }, { status: 409 });

    const validRoles = ["MEMBER", "VIEWER"];
    const invitation = await prisma.invitation.create({
        data: {
            type: "TEAM",
            role: validRoles.includes(role) ? role : "MEMBER",
            senderId: session.user.id,
            receiverId: user.id,
            teamId: teamId,
            message: message?.trim() || null,
        },
        include: {
            sender: { select: { id: true, name: true, email: true } },
            receiver: { select: { id: true, name: true, email: true } },
        },
    });

    return NextResponse.json({ invitation, message: "Invitation sent. User must accept to join." }, { status: 201 });
}

// PATCH — change role
export async function PATCH(req: NextRequest, ctx: Ctx) {
    const session = await auth();
    if (!session?.user?.id) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
    const { teamId } = await ctx.params;

    const leadership = await prisma.teamMember.findFirst({
        where: { teamId, userId: session.user.id, role: "LEADER" },
    });
    if (!leadership) return NextResponse.json({ error: "Forbidden" }, { status: 403 });

    const body = await req.json();
    const { memberId, role } = body;
    if (!memberId || !role) return NextResponse.json({ error: "memberId and role required" }, { status: 400 });

    const target = await prisma.teamMember.findFirst({ where: { id: memberId, teamId } });
    if (!target) return NextResponse.json({ error: "Member not found" }, { status: 404 });
    if (target.role === "LEADER" && target.userId !== session.user.id) {
        return NextResponse.json({ error: "Cannot change another leader's role" }, { status: 403 });
    }

    const updated = await prisma.teamMember.update({
        where: { id: memberId }, data: { role },
        include: { user: { select: { id: true, name: true, email: true } } },
    });
    return NextResponse.json(updated);
}

// DELETE — remove member
export async function DELETE(req: NextRequest, ctx: Ctx) {
    const session = await auth();
    if (!session?.user?.id) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
    const { teamId } = await ctx.params;

    const leadership = await prisma.teamMember.findFirst({
        where: { teamId, userId: session.user.id, role: "LEADER" },
    });
    if (!leadership) return NextResponse.json({ error: "Forbidden" }, { status: 403 });

    const { searchParams } = new URL(req.url);
    const memberId = searchParams.get("memberId");
    if (!memberId) return NextResponse.json({ error: "memberId required" }, { status: 400 });

    const target = await prisma.teamMember.findFirst({ where: { id: memberId, teamId } });
    if (!target) return NextResponse.json({ error: "Not found" }, { status: 404 });
    if (target.role === "LEADER") return NextResponse.json({ error: "Cannot remove leader" }, { status: 403 });

    await prisma.teamMember.delete({ where: { id: memberId } });
    return NextResponse.json({ success: true });
}
