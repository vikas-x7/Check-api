"use client";

import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { motion, AnimatePresence } from "framer-motion";
import Link from "next/link";
import { useState } from "react";
import api from "@/lib/axios";
import Navbar from "@/client/home/components/Navbar";

const COLORS = ["#6366f1", "#8b5cf6", "#ec4899", "#f43f5e", "#f97316", "#eab308", "#22c55e", "#06b6d4", "#3b82f6"];

type Project = {
    id: string; name: string; description: string | null; slug: string; color: string;
    owner: { id: string; name: string; email: string };
    members: { id: string; role: string; user: { id: string; name: string; email: string } }[];
    _count: { scans: number; members: number };
    createdAt: string; updatedAt: string;
};

export default function ProjectsPage() {
    const queryClient = useQueryClient();
    const [showCreate, setShowCreate] = useState(false);
    const [name, setName] = useState("");
    const [description, setDescription] = useState("");
    const [color, setColor] = useState("#6366f1");

    const { data: projects = [], isLoading } = useQuery<Project[]>({
        queryKey: ["projects"],
        queryFn: async () => (await api.get("/projects")).data,
    });

    const createMutation = useMutation({
        mutationFn: async () => (await api.post("/projects", { name, description, color })).data,
        onSuccess: () => { queryClient.invalidateQueries({ queryKey: ["projects"] }); setShowCreate(false); setName(""); setDescription(""); },
    });

    const deleteMutation = useMutation({
        mutationFn: async (id: string) => (await api.delete(`/projects/${id}`)).data,
        onSuccess: () => queryClient.invalidateQueries({ queryKey: ["projects"] }),
    });

    return (
        <div className="min-h-screen bg-slate-950 text-slate-200">
            <Navbar />
            <div className="max-w-6xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
                {/* Header */}
                <motion.div initial={{ opacity: 0, y: -20 }} animate={{ opacity: 1, y: 0 }} className="flex items-center justify-between mb-8">
                    <div>
                        <h1 className="text-3xl font-black bg-gradient-to-r from-indigo-400 via-violet-400 to-purple-400 bg-clip-text text-transparent">Projects</h1>
                        <p className="text-sm text-slate-500 mt-1">Organize your security scans by project, manage access with RBAC</p>
                    </div>
                    <button onClick={() => setShowCreate(!showCreate)}
                        className="px-5 py-2.5 rounded-xl text-sm font-bold bg-gradient-to-r from-indigo-600 to-violet-600 hover:from-indigo-500 hover:to-violet-500 transition-all duration-200 shadow-lg shadow-indigo-500/20 flex items-center gap-2">
                        ＋ New Project
                    </button>
                </motion.div>

                {/* Create Project Modal */}
                <AnimatePresence>
                    {showCreate && (
                        <motion.div initial={{ opacity: 0, height: 0 }} animate={{ opacity: 1, height: "auto" }} exit={{ opacity: 0, height: 0 }}
                            className="overflow-hidden mb-6">
                            <div className="rounded-2xl border border-slate-700/50 bg-slate-900/80 backdrop-blur p-6">
                                <h3 className="text-lg font-bold text-slate-200 mb-4">Create New Project</h3>
                                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                                    <div>
                                        <label className="block text-xs font-semibold text-slate-400 mb-1.5 uppercase tracking-wider">Project Name *</label>
                                        <input type="text" value={name} onChange={e => setName(e.target.value)} placeholder="My API Project"
                                            className="w-full px-4 py-2.5 rounded-xl bg-slate-800 border border-slate-700 text-sm text-slate-200 placeholder:text-slate-600 focus:outline-none focus:border-indigo-500/50 focus:ring-1 focus:ring-indigo-500/20 transition-all" />
                                    </div>
                                    <div>
                                        <label className="block text-xs font-semibold text-slate-400 mb-1.5 uppercase tracking-wider">Color</label>
                                        <div className="flex items-center gap-2 flex-wrap">
                                            {COLORS.map(c => (
                                                <button key={c} onClick={() => setColor(c)}
                                                    className={`w-8 h-8 rounded-full transition-all duration-200 ${color === c ? "ring-2 ring-white ring-offset-2 ring-offset-slate-900 scale-110" : "hover:scale-110"}`}
                                                    style={{ background: c }} />
                                            ))}
                                        </div>
                                    </div>
                                </div>
                                <div className="mt-4">
                                    <label className="block text-xs font-semibold text-slate-400 mb-1.5 uppercase tracking-wider">Description</label>
                                    <textarea value={description} onChange={e => setDescription(e.target.value)} rows={2} placeholder="Optional project description..."
                                        className="w-full px-4 py-2.5 rounded-xl bg-slate-800 border border-slate-700 text-sm text-slate-200 placeholder:text-slate-600 focus:outline-none focus:border-indigo-500/50 focus:ring-1 focus:ring-indigo-500/20 transition-all resize-none" />
                                </div>
                                <div className="flex justify-end gap-3 mt-4">
                                    <button onClick={() => setShowCreate(false)} className="px-4 py-2 rounded-lg text-sm font-semibold border border-slate-600 bg-slate-800 hover:bg-slate-700 transition-all">Cancel</button>
                                    <button onClick={() => createMutation.mutate()} disabled={!name.trim() || createMutation.isPending}
                                        className="px-5 py-2 rounded-lg text-sm font-bold bg-gradient-to-r from-indigo-600 to-violet-600 hover:from-indigo-500 hover:to-violet-500 transition-all disabled:opacity-40 shadow-lg shadow-indigo-500/20">
                                        {createMutation.isPending ? "Creating…" : "Create Project"}
                                    </button>
                                </div>
                            </div>
                        </motion.div>
                    )}
                </AnimatePresence>

                {/* Loading */}
                {isLoading && (
                    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                        {[1, 2, 3].map(i => (
                            <div key={i} className="rounded-2xl border border-slate-700/30 bg-slate-900/40 p-6 animate-pulse">
                                <div className="h-4 bg-slate-800 rounded w-3/4 mb-3" />
                                <div className="h-3 bg-slate-800 rounded w-1/2 mb-4" />
                                <div className="h-8 bg-slate-800 rounded w-full" />
                            </div>
                        ))}
                    </div>
                )}

                {/* Empty State */}
                {!isLoading && projects.length === 0 && (
                    <motion.div initial={{ opacity: 0, scale: 0.95 }} animate={{ opacity: 1, scale: 1 }}
                        className="text-center py-20 rounded-2xl border border-dashed border-slate-700/50">
                        <div className="text-5xl mb-4"></div>
                        <h3 className="text-lg font-bold text-slate-300 mb-2">No Projects Yet</h3>
                        <p className="text-sm text-slate-500 mb-6 max-w-sm mx-auto">Create your first project to organize scans, manage team access, and track security posture</p>
                        <button onClick={() => setShowCreate(true)}
                            className="px-6 py-2.5 rounded-xl text-sm font-bold bg-gradient-to-r from-indigo-600 to-violet-600 hover:from-indigo-500 hover:to-violet-500 transition-all shadow-lg shadow-indigo-500/20">
                            ＋ Create First Project
                        </button>
                    </motion.div>
                )}

                {/* Project Grid */}
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                    <AnimatePresence mode="popLayout">
                        {projects.map((project, i) => (
                            <motion.div key={project.id} layout
                                initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, scale: 0.9 }}
                                transition={{ delay: i * 0.05, duration: 0.3 }}
                                className="group relative rounded-2xl border border-slate-700/50 bg-slate-900/80 backdrop-blur overflow-hidden hover:border-indigo-500/30 transition-all duration-300 hover:shadow-lg hover:shadow-indigo-500/5">
                                {/* Color bar */}
                                <div className="h-1 w-full" style={{ background: project.color }} />
                                <div className="p-5">
                                    <div className="flex items-start justify-between mb-3">
                                        <div className="flex items-center gap-3">
                                            <div className="w-10 h-10 rounded-xl flex items-center justify-center text-white text-sm font-black shrink-0" style={{ background: project.color }}>
                                                {project.name.charAt(0).toUpperCase()}
                                            </div>
                                            <div>
                                                <Link href={`/projects/${project.id}`} className="text-sm font-bold text-slate-100 hover:text-indigo-400 transition-colors no-underline">
                                                    {project.name}
                                                </Link>
                                                <p className="text-[11px] text-slate-500 mt-0.5">{project.owner.name}</p>
                                            </div>
                                        </div>
                                        <button onClick={() => { if (confirm("Delete this project?")) deleteMutation.mutate(project.id); }}
                                            className="opacity-0 group-hover:opacity-100 text-xs text-slate-500 hover:text-red-400 transition-all px-2 py-1 rounded-lg hover:bg-red-500/10">
                                            
                                        </button>
                                    </div>

                                    {project.description && <p className="text-xs text-slate-500 mb-3 line-clamp-2">{project.description}</p>}

                                    <div className="flex items-center gap-4 text-[11px] text-slate-500 mb-3">
                                        <span className="flex items-center gap-1"> {project._count.members} members</span>
                                        <span className="flex items-center gap-1"> {project._count.scans} scans</span>
                                    </div>

                                    {/* Member Avatars */}
                                    <div className="flex items-center -space-x-2">
                                        {project.members.slice(0, 5).map(m => (
                                            <div key={m.id} className="w-7 h-7 rounded-full border-2 border-slate-900 flex items-center justify-center text-[10px] font-bold text-white" style={{ background: project.color }}>
                                                {m.user.name.charAt(0).toUpperCase()}
                                            </div>
                                        ))}
                                        {project.members.length > 5 && (
                                            <div className="w-7 h-7 rounded-full border-2 border-slate-900 bg-slate-700 flex items-center justify-center text-[10px] font-bold text-slate-300">
                                                +{project.members.length - 5}
                                            </div>
                                        )}
                                    </div>
                                </div>
                            </motion.div>
                        ))}
                    </AnimatePresence>
                </div>
            </div>
        </div>
    );
}
