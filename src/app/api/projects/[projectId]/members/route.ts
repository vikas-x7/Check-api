import { NextRequest, NextResponse } from "next/server";
import { auth } from "@/lib/auth";
import prisma from "@/lib/prisma";

type Ctx = { params: Promise<{ projectId: string }> };

// POST — invite a user to the project (creates invitation, NOT auto-add)
export async function POST(req: NextRequest, ctx: Ctx) {
    const session = await auth();
    if (!session?.user?.id) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
    const { projectId } = await ctx.params;

    const membership = await prisma.projectMember.findFirst({
        where: { projectId, userId: session.user.id, role: { in: ["OWNER", "ADMIN"] } },
    });
    if (!membership) return NextResponse.json({ error: "Only owners and admins can invite members" }, { status: 403 });

    const body = await req.json();
    const { email, role, message } = body;
    if (!email) return NextResponse.json({ error: "Email is required" }, { status: 400 });

    const user = await prisma.user.findUnique({ where: { email } });
    if (!user) return NextResponse.json({ error: "No user found with that email" }, { status: 404 });
    if (user.id === session.user.id) return NextResponse.json({ error: "Cannot invite yourself" }, { status: 400 });

    const existing = await prisma.projectMember.findUnique({
        where: { projectId_userId: { projectId, userId: user.id } },
    });
    if (existing) return NextResponse.json({ error: "User is already a member" }, { status: 409 });

    const pending = await prisma.invitation.findFirst({
        where: { receiverId: user.id, projectId, type: "PROJECT", status: "PENDING" },
    });
    if (pending) return NextResponse.json({ error: "Invitation already pending for this user" }, { status: 409 });

    const validRoles = ["ADMIN", "MEMBER", "VIEWER"];
    const invitation = await prisma.invitation.create({
        data: {
            type: "PROJECT",
            role: validRoles.includes(role) ? role : "MEMBER",
            senderId: session.user.id,
            receiverId: user.id,
            projectId,
            message: message?.trim() || null,
        },
        include: {
            sender: { select: { id: true, name: true, email: true } },
            receiver: { select: { id: true, name: true, email: true } },
        },
    });

    return NextResponse.json({ invitation, message: "Invitation sent. User must accept to join." }, { status: 201 });
}

// PATCH — change an existing member's role
export async function PATCH(req: NextRequest, ctx: Ctx) {
    const session = await auth();
    if (!session?.user?.id) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
    const { projectId } = await ctx.params;

    const membership = await prisma.projectMember.findFirst({
        where: { projectId, userId: session.user.id, role: { in: ["OWNER", "ADMIN"] } },
    });
    if (!membership) return NextResponse.json({ error: "Forbidden" }, { status: 403 });

    const body = await req.json();
    const { memberId, role } = body;
    if (!memberId || !role) return NextResponse.json({ error: "memberId and role are required" }, { status: 400 });

    const target = await prisma.projectMember.findFirst({ where: { id: memberId, projectId } });
    if (!target) return NextResponse.json({ error: "Member not found" }, { status: 404 });
    if (target.role === "OWNER") return NextResponse.json({ error: "Cannot change owner's role" }, { status: 403 });

    const updated = await prisma.projectMember.update({
        where: { id: memberId },
        data: { role },
        include: { user: { select: { id: true, name: true, email: true } } },
    });

    return NextResponse.json(updated);
}

// DELETE — remove a member from the project
export async function DELETE(req: NextRequest, ctx: Ctx) {
    const session = await auth();
    if (!session?.user?.id) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
    const { projectId } = await ctx.params;

    const membership = await prisma.projectMember.findFirst({
        where: { projectId, userId: session.user.id, role: { in: ["OWNER", "ADMIN"] } },
    });
    if (!membership) return NextResponse.json({ error: "Forbidden" }, { status: 403 });

    const { searchParams } = new URL(req.url);
    const memberId = searchParams.get("memberId");
    if (!memberId) return NextResponse.json({ error: "memberId is required" }, { status: 400 });

    const target = await prisma.projectMember.findFirst({ where: { id: memberId, projectId } });
    if (!target) return NextResponse.json({ error: "Member not found" }, { status: 404 });
    if (target.role === "OWNER") return NextResponse.json({ error: "Cannot remove the owner" }, { status: 403 });

    await prisma.projectMember.delete({ where: { id: memberId } });
    return NextResponse.json({ success: true });
}
