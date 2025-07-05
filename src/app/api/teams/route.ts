import { NextRequest, NextResponse } from "next/server";
import { auth } from "@/lib/auth";

import prisma from "@/lib/prisma";

export async function GET() {
    const session = await auth();
    if (!session?.user?.id) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });

    const teams = await prisma.team.findMany({
        where: {
            OR: [
                { ownerId: session.user.id },
                { members: { some: { userId: session.user.id } } },
            ],
        },
        include: {
            owner: { select: { id: true, name: true, email: true } },
            members: { include: { user: { select: { id: true, name: true, email: true } } } },
            _count: { select: { members: true } },
        },
        orderBy: { updatedAt: "desc" },
    });

    return NextResponse.json(teams);
}

export async function POST(req: NextRequest) {
    const session = await auth();
    if (!session?.user?.id) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });

    const body = await req.json();
    const { name, description, color } = body;

    if (!name || typeof name !== "string" || name.trim().length < 2) {
        return NextResponse.json({ error: "Team name must be at least 2 characters" }, { status: 400 });
    }

    const slug = name.trim().toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/(^-|-$)/g, "") + "-" + Date.now().toString(36);

    const team = await prisma.team.create({
        data: {
            name: name.trim(),
            description: description?.trim() || null,
            slug,
            color: color || "#8b5cf6",
            ownerId: session.user.id,
            members: {
                create: { userId: session.user.id, role: "LEADER" },
            },
        },
        include: {
            owner: { select: { id: true, name: true, email: true } },
            members: { include: { user: { select: { id: true, name: true, email: true } } } },
            _count: { select: { members: true } },
        },
    });

    return NextResponse.json(team, { status: 201 });
}
