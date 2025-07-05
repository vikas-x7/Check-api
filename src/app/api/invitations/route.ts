import { NextRequest, NextResponse } from "next/server";
import { auth } from "@/lib/auth";
import prisma from "@/lib/prisma";

// GET all invitations for the current user (received)
export async function GET() {
    const session = await auth();
    if (!session?.user?.id) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });

    const invitations = await prisma.invitation.findMany({
        where: { receiverId: session.user.id, status: "PENDING" },
        include: {
            sender: { select: { id: true, name: true, email: true } },
            project: { select: { id: true, name: true, color: true } },
            team: { select: { id: true, name: true, color: true } },
        },
        orderBy: { createdAt: "desc" },
    });

    return NextResponse.json(invitations);
}

// POST — Create a new invitation (send invite by email)
export async function POST(req: NextRequest) {
    const session = await auth();
    if (!session?.user?.id) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });

    const body = await req.json();
    const { email, type, projectId, teamId, role, message } = body;

    if (!email) return NextResponse.json({ error: "Email is required" }, { status: 400 });
    if (!type || !["PROJECT", "TEAM"].includes(type)) return NextResponse.json({ error: "Invalid invite type" }, { status: 400 });

    const targetUser = await prisma.user.findUnique({ where: { email } });
    if (!targetUser) return NextResponse.json({ error: "No user found with that email" }, { status: 404 });
    if (targetUser.id === session.user.id) return NextResponse.json({ error: "Cannot invite yourself" }, { status: 400 });

    if (type === "PROJECT") {
        if (!projectId) return NextResponse.json({ error: "projectId is required for project invites" }, { status: 400 });

        // Check sender has OWNER/ADMIN role
        const membership = await prisma.projectMember.findFirst({
            where: { projectId, userId: session.user.id, role: { in: ["OWNER", "ADMIN"] } },
        });
        if (!membership) return NextResponse.json({ error: "Only owners/admins can invite" }, { status: 403 });

        // Check if already a member
        const existing = await prisma.projectMember.findUnique({
            where: { projectId_userId: { projectId, userId: targetUser.id } },
        });
        if (existing) return NextResponse.json({ error: "User is already a project member" }, { status: 409 });

        // Check if pending invitation already exists
        const pendingInvite = await prisma.invitation.findFirst({
            where: { receiverId: targetUser.id, projectId, type: "PROJECT", status: "PENDING" },
        });
        if (pendingInvite) return NextResponse.json({ error: "An invitation is already pending for this user" }, { status: 409 });
    }

    if (type === "TEAM") {
        if (!teamId) return NextResponse.json({ error: "teamId is required for team invites" }, { status: 400 });

        const leadership = await prisma.teamMember.findFirst({
            where: { teamId, userId: session.user.id, role: "LEADER" },
        });
        if (!leadership) return NextResponse.json({ error: "Only leaders can invite" }, { status: 403 });

        const existing = await prisma.teamMember.findUnique({
            where: { teamId_userId: { teamId, userId: targetUser.id } },
        });
        if (existing) return NextResponse.json({ error: "User is already a team member" }, { status: 409 });

        const pendingInvite = await prisma.invitation.findFirst({
            where: { receiverId: targetUser.id, teamId, type: "TEAM", status: "PENDING" },
        });
        if (pendingInvite) return NextResponse.json({ error: "An invitation is already pending for this user" }, { status: 409 });
    }

    const invitation = await prisma.invitation.create({
        data: {
            type,
            role: role || "MEMBER",
            senderId: session.user.id,
            receiverId: targetUser.id,
            projectId: type === "PROJECT" ? projectId : null,
            teamId: type === "TEAM" ? teamId : null,
            message: message?.trim() || null,
        },
        include: {
            sender: { select: { id: true, name: true, email: true } },
            receiver: { select: { id: true, name: true, email: true } },
            project: { select: { id: true, name: true, color: true } },
            team: { select: { id: true, name: true, color: true } },
        },
    });

    return NextResponse.json(invitation, { status: 201 });
}
