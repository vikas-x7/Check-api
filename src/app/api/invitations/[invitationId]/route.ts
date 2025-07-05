import { NextRequest, NextResponse } from "next/server";
import { auth } from "@/lib/auth";
import prisma from "@/lib/prisma";

type Ctx = { params: Promise<{ invitationId: string }> };

// PATCH — Accept or decline an invitation
export async function PATCH(req: NextRequest, ctx: Ctx) {
    const session = await auth();
    if (!session?.user?.id) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
    const { invitationId } = await ctx.params;

    const invitation = await prisma.invitation.findFirst({
        where: { id: invitationId, receiverId: session.user.id, status: "PENDING" },
    });
    if (!invitation) return NextResponse.json({ error: "Invitation not found or already processed" }, { status: 404 });

    const body = await req.json();
    const { action } = body;

    if (!action || !["accept", "decline"].includes(action)) {
        return NextResponse.json({ error: "action must be 'accept' or 'decline'" }, { status: 400 });
    }

    if (action === "decline") {
        await prisma.invitation.update({ where: { id: invitationId }, data: { status: "DECLINED" } });
        return NextResponse.json({ success: true, status: "DECLINED" });
    }

    // Accept — add user to project or team
    if (invitation.type === "PROJECT" && invitation.projectId) {
        await prisma.projectMember.create({
            data: {
                projectId: invitation.projectId,
                userId: session.user.id,
                // eslint-disable-next-line @typescript-eslint/no-explicit-any
                role: invitation.role as any,
            },
        });
    } else if (invitation.type === "TEAM" && invitation.teamId) {
        await prisma.teamMember.create({
            data: {
                teamId: invitation.teamId,
                userId: session.user.id,
                // eslint-disable-next-line @typescript-eslint/no-explicit-any
                role: invitation.role as any,
            },
        });
    }

    await prisma.invitation.update({ where: { id: invitationId }, data: { status: "ACCEPTED" } });

    return NextResponse.json({ success: true, status: "ACCEPTED" });
}

// DELETE — Cancel a sent invitation (sender only)
export async function DELETE(_req: NextRequest, ctx: Ctx) {
    const session = await auth();
    if (!session?.user?.id) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
    const { invitationId } = await ctx.params;

    const invitation = await prisma.invitation.findFirst({
        where: { id: invitationId, senderId: session.user.id, status: "PENDING" },
    });
    if (!invitation) return NextResponse.json({ error: "Invitation not found" }, { status: 404 });

    await prisma.invitation.delete({ where: { id: invitationId } });
    return NextResponse.json({ success: true });
}
