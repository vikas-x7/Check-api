"use client";

import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { motion, AnimatePresence } from "framer-motion";
import Link from "next/link";
import { useState, useEffect, useCallback } from "react";
import api from "@/lib/axios";
import { FiUsers, FiPlus, FiTrash2, FiX } from "react-icons/fi";

type Team = {
    id: string; name: string; description: string | null; slug: string; color: string;
    owner: { id: string; name: string; email: string };
    members: { id: string; role: string; user: { id: string; name: string; email: string } }[];
    _count: { members: number };
    createdAt: string;
};

const COLORS = ["#8b5cf6", "#6366f1", "#ec4899", "#f43f5e", "#f97316", "#eab308", "#22c55e", "#06b6d4", "#3b82f6"];

function TeamsSkeleton() {
    return (
        <div className="px-5 py-3 space-y-6 animate-pulse">
            <div className="flex justify-between items-center mb-6">
                <div>
                    <div className="h-8 w-24 bg-[#1A1A1A] rounded-[4px] mb-2"></div>
                    <div className="h-4 w-40 bg-[#1A1A1A] rounded-[4px]"></div>
                </div>
                <div className="h-10 w-28 bg-[#1A1A1A] rounded-[4px]"></div>
            </div>
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                {[...Array(6)].map((_, i) => (
                    <div key={i} className="rounded-[4px] border border-[#2D2D2D] bg-[#0F0F0F] p-5">
                        <div className="flex items-start gap-3 mb-3">
                            <div className="w-10 h-10 bg-[#1A1A1A] rounded-[4px]"></div>
                            <div className="flex-1">
                                <div className="h-4 w-3/4 bg-[#1A1A1A] rounded-[4px] mb-2"></div>
                                <div className="h-3 w-1/2 bg-[#1A1A1A] rounded-[4px]"></div>
                            </div>
                        </div>
                        <div className="h-3 w-24 bg-[#1A1A1A] rounded-[4px] mb-3"></div>
                        <div className="flex gap-2">
                            <div className="h-6 w-6 bg-[#1A1A1A] rounded-full"></div>
                            <div className="h-6 w-6 bg-[#1A1A1A] rounded-full"></div>
                            <div className="h-6 w-6 bg-[#1A1A1A] rounded-full"></div>
                        </div>
                    </div>
                ))}
            </div>
        </div>
    );
}

export default function TeamsPage() {
    const queryClient = useQueryClient();
    const [showCreate, setShowCreate] = useState(false);
    const [name, setName] = useState("");
    const [description, setDescription] = useState("");
    const [color, setColor] = useState("#8b5cf6");

    const handleClose = useCallback(() => {
        setShowCreate(false);
        setName("");
        setDescription("");
        setColor("#8b5cf6");
    }, []);

    useEffect(() => {
        const handleKeyDown = (e: KeyboardEvent) => {
            if (e.key === "Escape" && showCreate) {
                handleClose();
            }
        };
        document.addEventListener("keydown", handleKeyDown);
        return () => document.removeEventListener("keydown", handleKeyDown);
    }, [showCreate, handleClose]);

    useEffect(() => {
        if (showCreate) {
            document.body.style.overflow = "hidden";
        } else {
            document.body.style.overflow = "";
        }
        return () => { document.body.style.overflow = ""; };
    }, [showCreate]);

    const { data: teams = [], isLoading } = useQuery<Team[]>({
        queryKey: ["teams"],
        queryFn: async () => (await api.get("/teams")).data,
    });

    const createMutation = useMutation({
        mutationFn: async () => (await api.post("/teams", { name, description, color })).data,
        onSuccess: () => { queryClient.invalidateQueries({ queryKey: ["teams"] }); handleClose(); },
    });

    const deleteMutation = useMutation({
        mutationFn: async (id: string) => (await api.delete(`/teams/${id}`)).data,
        onSuccess: () => queryClient.invalidateQueries({ queryKey: ["teams"] }),
    });

    if (isLoading) {
        return <TeamsSkeleton />;
    }

    return (
        <div className="px-5 py-3">
            <div className="flex justify-between items-center mb-6">
                <div>
                    <h1 className="text-3xl font-serif -tracking-[1px] text-[#E7E7E7]">
                        Teams
                    </h1>
                    <p className="text-sm text-[#797979] font-dnsans">
                        Manage your security teams
                    </p>
                </div>
                <button
                    onClick={() => setShowCreate(true)}
                    className="flex items-center gap-2 px-5 py-2.5 rounded-[4px] text-[13px] font-bold bg-[#8b5cf6] hover:bg-[#7c3aed] transition-all text-white disabled:opacity-40"
                >
                    <FiPlus className="w-4 h-4" />
                    New Team
                </button>
            </div>

            {!isLoading && teams.length === 0 && (
                <motion.div
                    initial={{ opacity: 0, scale: 0.95 }}
                    animate={{ opacity: 1, scale: 1 }}
                    className="text-center py-20 rounded-[4px] border border-dashed border-[#2D2D2D] bg-[#0F0F0F]"
                >
                    <div className="w-16 h-16 mx-auto mb-4 rounded-[4px] bg-[#1A1A1A] flex items-center justify-center">
                        <FiUsers className="w-8 h-8 text-[#797979]" />
                    </div>
                    <h3 className="text-lg font-bold text-[#E7E7E7] mb-2">No Teams Yet</h3>
                    <p className="text-sm text-[#797979] mb-6 max-w-w-sm mx-auto">Create your first team to collaborate on security testing</p>
                    <button
                        onClick={() => setShowCreate(true)}
                        className="px-6 py-2.5 rounded-[4px] text-[13px] font-bold bg-[#8b5cf6] hover:bg-[#7c3aed] transition-all text-white"
                    >
                        + Create First Team
                    </button>
                </motion.div>
            )}

            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                <AnimatePresence mode="popLayout">
                    {teams.map((team, i) => (
                        <motion.div
                            key={team.id}
                            layout
                            initial={{ opacity: 0, y: 20 }}
                            animate={{ opacity: 1, y: 0 }}
                            exit={{ opacity: 0, scale: 0.9 }}
                            transition={{ delay: i * 0.05, duration: 0.3 }}
                            className="group relative rounded-[4px] border border-[#2D2D2D] bg-[#0F0F0F] overflow-hidden hover:border-[#8b5cf6]/30 transition-all duration-300"
                        >
                            <div className="h-1 w-full" style={{ background: team.color }} />
                            <div className="p-5">
                                <div className="flex items-start justify-between mb-3">
                                    <div className="flex items-center gap-3">
                                        <div
                                            className="w-10 h-10 rounded-[4px] flex items-center justify-center text-white text-sm font-black shrink-0"
                                            style={{ background: team.color }}
                                        >
                                            {team.name.charAt(0).toUpperCase()}
                                        </div>
                                        <div>
                                            <Link
                                                href={`/teams/${team.id}`}
                                                className="text-sm font-bold text-[#E7E7E7] hover:text-[#8b5cf6] transition-colors no-underline"
                                            >
                                                {team.name}
                                            </Link>
                                            <p className="text-[11px] text-[#797979] mt-0.5">Led by {team.owner.name}</p>
                                        </div>
                                    </div>
                                    <button
                                        onClick={() => { if (confirm("Delete this team?")) deleteMutation.mutate(team.id); }}
                                        className="opacity-0 group-hover:opacity-100 text-[#797979] hover:text-red-400 transition-all p-2 rounded-[4px] hover:bg-red-500/10"
                                    >
                                        <FiTrash2 className="w-4 h-4" />
                                    </button>
                                </div>

                                {team.description && (
                                    <p className="text-xs text-[#797979] mb-3 line-clamp-2">{team.description}</p>
                                )}

                                <div className="flex items-center gap-4 text-[11px] text-[#797979] mb-3">
                                    <span className="flex items-center gap-1.5">
                                        <FiUsers className="w-3.5 h-3.5" />
                                        {team._count.members} members
                                    </span>
                                </div>

                                <div className="flex items-center -space-x-2">
                                    {team.members.slice(0, 5).map(m => (
                                        <div
                                            key={m.id}
                                            className="w-7 h-7 rounded-full border-2 border-[#0F0F0F] flex items-center justify-center text-[10px] font-bold text-white"
                                            style={{ background: team.color }}
                                        >
                                            {m.user.name.charAt(0).toUpperCase()}
                                        </div>
                                    ))}
                                    {team.members.length > 5 && (
                                        <div className="w-7 h-7 rounded-full border-2 border-[#0F0F0F] bg-[#1A1A1A] flex items-center justify-center text-[10px] font-bold text-[#E7E7E7]">
                                            +{team.members.length - 5}
                                        </div>
                                    )}
                                </div>
                            </div>
                        </motion.div>
                    ))}
                </AnimatePresence>
            </div>

            <AnimatePresence>
                {showCreate && (
                    <motion.div
                        initial={{ opacity: 0 }}
                        animate={{ opacity: 1 }}
                        exit={{ opacity: 0 }}
                        className="fixed inset-0 z-50 flex items-center justify-center p-4"
                    >
                        <motion.div
                            initial={{ opacity: 0 }}
                            animate={{ opacity: 1 }}
                            exit={{ opacity: 0 }}
                            className="absolute inset-0 bg-black/60 backdrop-blur-sm"
                            onClick={handleClose}
                        />
                        <motion.div
                            initial={{ opacity: 0, scale: 0.95, y: 20 }}
                            animate={{ opacity: 1, scale: 1, y: 0 }}
                            exit={{ opacity: 0, scale: 0.95, y: 20 }}
                            transition={{ duration: 0.2 }}
                            className="relative w-full max-w-lg bg-[#0F0F0F] border border-[#2D2D2D] rounded-[4px] overflow-hidden"
                        >
                            <div className="flex items-center justify-between px-5 py-4 bg-[#0a0a0a] border-b border-[#2D2D2D]">
                                <span className="text-[13px] font-bold text-[#E7E7E7] uppercase tracking-wider">Create New Team</span>
                                <button
                                    onClick={handleClose}
                                    className="text-[#797979] hover:text-[#E7E7E7] transition-colors"
                                >
                                    <FiX className="w-5 h-5" />
                                </button>
                            </div>
                            <div className="p-5 space-y-4">
                                <div>
                                    <label className="block text-[11px] font-semibold text-[#797979] mb-1.5 uppercase tracking-wider">Team Name *</label>
                                    <input
                                        type="text"
                                        value={name}
                                        onChange={e => setName(e.target.value)}
                                        placeholder="Security Red Team"
                                        className="w-full px-4 py-2.5 rounded-[4px] bg-[#0D0D0D] border border-[#2D2D2D] text-sm text-[#E7E7E7] placeholder:text-[#797979] focus:outline-none focus:border-[#8b5cf6]/50 focus:ring-1 focus:ring-[#8b5cf6]/20 transition-all"
                                        autoFocus
                                    />
                                </div>
                                <div>
                                    <label className="block text-[11px] font-semibold text-[#797979] mb-1.5 uppercase tracking-wider">Color</label>
                                    <div className="flex items-center gap-2 flex-wrap">
                                        {COLORS.map(c => (
                                            <button
                                                key={c}
                                                onClick={() => setColor(c)}
                                                className={`w-8 h-8 rounded-full transition-all duration-200 ${color === c ? "ring-2 ring-white ring-offset-2 ring-offset-[#0F0F0F] scale-110" : "hover:scale-110"}`}
                                                style={{ background: c }}
                                            />
                                        ))}
                                    </div>
                                </div>
                                <div>
                                    <label className="block text-[11px] font-semibold text-[#797979] mb-1.5 uppercase tracking-wider">Description</label>
                                    <textarea
                                        value={description}
                                        onChange={e => setDescription(e.target.value)}
                                        rows={2}
                                        placeholder="Optional team description..."
                                        className="w-full px-4 py-2.5 rounded-[4px] bg-[#0D0D0D] border border-[#2D2D2D] text-sm text-[#E7E7E7] placeholder:text-[#797979] focus:outline-none focus:border-[#8b5cf6]/50 focus:ring-1 focus:ring-[#8b5cf6]/20 transition-all resize-none"
                                    />
                                </div>
                                <div className="flex justify-end gap-3 pt-2">
                                    <button
                                        onClick={handleClose}
                                        className="px-4 py-2 rounded-[4px] text-[12px] font-semibold border border-[#2D2D2D] bg-[#1A1A1A] hover:bg-[#252525] transition-all text-[#E7E7E7]"
                                    >
                                        Cancel
                                    </button>
                                    <button
                                        onClick={() => createMutation.mutate()}
                                        disabled={!name.trim() || createMutation.isPending}
                                        className="px-5 py-2 rounded-[4px] text-[12px] font-bold bg-[#8b5cf6] hover:bg-[#7c3aed] transition-all disabled:opacity-40 text-white"
                                    >
                                        {createMutation.isPending ? "Creating…" : "Create Team"}
                                    </button>
                                </div>
                            </div>
                        </motion.div>
                    </motion.div>
                )}
            </AnimatePresence>
        </div>
    );
}
