"use client";

import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { motion, AnimatePresence } from "framer-motion";
import Link from "next/link";
import { useParams, useRouter } from "next/navigation";
import { useState } from "react";
import { useSession } from "next-auth/react";
import api from "@/lib/axios";
import Sidebar from "@/client/dashboard/components/Sidebar";
import { FiUsers, FiSettings, FiLink, FiTrash2 } from "react-icons/fi";

const ROLE_COLORS: Record<string, string> = { LEADER: "bg-[#8b5cf6]/15 text-[#8b5cf6] border-[#8b5cf6]/30", MEMBER: "bg-[#1A1A1A] text-[#797979] border-[#2D2D2D]", VIEWER: "bg-[#1A1A1A] text-[#797979] border-[#2D2D2D]" };

type Team = {
    id: string; name: string; description: string | null; slug: string; color: string;
    owner: { id: string; name: string; email: string };
    members: { id: string; role: string; joinedAt: string; user: { id: string; name: string; email: string } }[];
    invitations: { id: string; role: string; receiver: { id: string; name: string; email: string } }[];
    projects: { project: { id: string; name: string; color: string; owner: { name: string }; _count: { scans: number } } }[];
    _count: { members: number };
    createdAt: string;
};

export default function TeamDetailPage() {
    const params = useParams();
    const router = useRouter();
    const queryClient = useQueryClient();
    const { data: session } = useSession();
    const teamId = params.teamId as string;

    const [activeTab, setActiveTab] = useState<"overview" | "members" | "projects" | "settings">("overview");
    const [inviteEmail, setInviteEmail] = useState("");
    const [inviteRole, setInviteRole] = useState("MEMBER");
    const [editName, setEditName] = useState("");
    const [editDesc, setEditDesc] = useState("");

    const { data: team, isLoading } = useQuery<Team>({
        queryKey: ["team", teamId],
        queryFn: async () => (await api.get(`/teams/${teamId}`)).data,
    });

    const inviteMutation = useMutation({
        mutationFn: async () => (await api.post(`/teams/${teamId}/members`, { email: inviteEmail, role: inviteRole })).data,
        onSuccess: () => { queryClient.invalidateQueries({ queryKey: ["team", teamId] }); setInviteEmail(""); },
    });

    const cancelInviteMutation = useMutation({
        mutationFn: async (inviteId: string) => (await api.delete(`/invitations/${inviteId}`)).data,
        onSuccess: () => queryClient.invalidateQueries({ queryKey: ["team", teamId] }),
    });

    const removeMutation = useMutation({
        mutationFn: async (memberId: string) => (await api.delete(`/teams/${teamId}/members?memberId=${memberId}`)).data,
        onSuccess: () => queryClient.invalidateQueries({ queryKey: ["team", teamId] }),
    });

    const changeRoleMutation = useMutation({
        mutationFn: async ({ memberId, role }: { memberId: string; role: string }) => (await api.patch(`/teams/${teamId}/members`, { memberId, role })).data,
        onSuccess: () => queryClient.invalidateQueries({ queryKey: ["team", teamId] }),
    });

    const updateMutation = useMutation({
        mutationFn: async () => (await api.patch(`/teams/${teamId}`, { name: editName || undefined, description: editDesc })).data,
        onSuccess: () => queryClient.invalidateQueries({ queryKey: ["team", teamId] }),
    });

    const deleteMutation = useMutation({
        mutationFn: async () => (await api.delete(`/teams/${teamId}`)).data,
        onSuccess: () => router.push("/dashboard/teams"),
    });

    const myRole = team?.members.find(m => m.user.id === session?.user?.id)?.role;
    const isLeader = myRole === "LEADER";

    if (isLoading) return (
        <div className="flex min-h-screen bg-[#0F0F0F]">
            <Sidebar />
            <main className="flex-1 bg-[#0F0F0F] overflow-y-auto">
                <div className="px-5 py-3 space-y-6 animate-pulse">
                    <div className="flex items-center gap-2 text-[12px] text-[#797979] mb-4">
                        <div className="h-3 w-20 bg-[#1A1A1A] rounded-[4px]"></div>
                        <div className="h-3 w-3 bg-[#1A1A1A] rounded-[4px]"></div>
                        <div className="h-3 w-16 bg-[#1A1A1A] rounded-[4px]"></div>
                        <div className="h-3 w-3 bg-[#1A1A1A] rounded-[4px]"></div>
                        <div className="h-3 w-24 bg-[#1A1A1A] rounded-[4px]"></div>
                    </div>
                    <div>
                        <div className="h-8 w-24 bg-[#1A1A1A] rounded-[4px] mb-2"></div>
                        <div className="h-4 w-40 bg-[#1A1A1A] rounded-[4px]"></div>
                    </div>
                    <div className="relative overflow-hidden rounded-[4px] border border-[#2D2D2D] bg-[#0a0a0a] p-5">
                        <div className="h-1 w-full bg-[#1A1A1A] rounded-full mb-4"></div>
                        <div className="flex items-center gap-4">
                            <div className="w-12 h-12 bg-[#1A1A1A] rounded-[4px]"></div>
                            <div className="flex-1">
                                <div className="h-5 w-40 bg-[#1A1A1A] rounded-[4px] mb-2"></div>
                                <div className="h-3 w-64 bg-[#1A1A1A] rounded-[4px] mb-3"></div>
                                <div className="flex gap-4">
                                    <div className="h-3 w-24 bg-[#1A1A1A] rounded-[4px]"></div>
                                    <div className="h-3 w-20 bg-[#1A1A1A] rounded-[4px]"></div>
                                    <div className="h-3 w-20 bg-[#1A1A1A] rounded-[4px]"></div>
                                </div>
                            </div>
                        </div>
                    </div>
                    <div className="flex items-center gap-1 p-1 rounded-[4px] bg-[#0a0a0a] border border-[#2D2D2D]">
                        {[...Array(4)].map((_, i) => (
                            <div key={i} className="h-9 w-24 bg-[#1A1A1A] rounded-[4px]"></div>
                        ))}
                    </div>
                    <div className="grid grid-cols-1 sm:grid-cols-4 gap-3">
                        {[...Array(4)].map((_, i) => (
                            <div key={i} className="rounded-[4px] border border-[#2D2D2D] bg-[#0a0a0a] p-4 text-center">
                                <div className="h-8 w-full bg-[#1A1A1A] rounded-[4px] mb-2"></div>
                                <div className="h-3 w-20 mx-auto bg-[#1A1A1A] rounded-[4px]"></div>
                            </div>
                        ))}
                    </div>
                    <div className="rounded-[4px] border border-[#2D2D2D] bg-[#0a0a0a] p-5">
                        <div className="h-4 w-40 bg-[#1A1A1A] rounded-[4px] mb-4"></div>
                        <div className="space-y-3">
                            {[...Array(3)].map((_, i) => (
                                <div key={i}>
                                    <div className="flex justify-between mb-1">
                                        <div className="h-3 w-16 bg-[#1A1A1A] rounded-[4px]"></div>
                                        <div className="h-3 w-12 bg-[#1A1A1A] rounded-[4px]"></div>
                                    </div>
                                    <div className="h-2 bg-[#1A1A1A] rounded-full"></div>
                                </div>
                            ))}
                        </div>
                    </div>
                </div>
            </main>
        </div>
    );

    if (!team) return (
        <div className="flex min-h-screen bg-[#0F0F0F]">
            <Sidebar />
            <main className="flex-1 bg-[#0F0F0F] overflow-y-auto">
                <div className="flex items-center justify-center min-h-[60vh] text-[#797979]">Team not found</div>
            </main>
        </div>
    );

    return (
        <div className="flex min-h-screen bg-[#0F0F0F]">
            <Sidebar />
            <main className="flex-1 bg-[#0F0F0F] overflow-y-auto">
                <div className="px-5 py-3">
                    <div className="flex items-center gap-2 text-[12px] text-[#797979] mb-4">
                        <Link href="/dashboard" className="hover:text-[#8b5cf6] transition-colors">Dashboard</Link>
                        <span>/</span>
                        <Link href="/dashboard/teams" className="hover:text-[#8b5cf6] transition-colors">Teams</Link>
                        <span>/</span>
                        <span className="text-[#E7E7E7]">{team?.name}</span>
                    </div>
                    <div className="mb-6">
                        <h1 className="text-3xl font-serif -tracking-[1px] text-[#E7E7E7]">
                            Teams
                        </h1>
                        <p className="text-sm text-[#797979] font-dnsans">
                            View and manage team details
                        </p>
                    </div>
                    <motion.div initial={{ opacity: 0, y: -15 }} animate={{ opacity: 1, y: 0 }}
                        className="relative overflow-hidden rounded-[4px] border border-[#2D2D2D] bg-[#0a0a0a] p-5 mb-6">
                        <div className="h-1 w-full absolute top-0 left-0" style={{ background: team.color }} />
                        <div className="flex items-start justify-between mt-2">
                            <div className="flex items-center gap-4">
                                <div className="w-12 h-12 rounded-[4px] flex items-center justify-center text-xl font-black text-white shrink-0" style={{ background: team.color }}>
                                    {team.name.charAt(0).toUpperCase()}
                                </div>
                                <div>
                                    <h1 className="text-xl font-bold text-[#E7E7E7]">{team.name}</h1>
                                    <p className="text-sm text-[#797979] mt-0.5">{team.description || "No description"}</p>
                                    <div className="flex items-center gap-4 mt-2 text-xs text-[#797979]">
                                        <span> Leader: {team.owner.name}</span>
                                        <span> {team._count.members} members</span>
                                        <span> {team.projects?.length || 0} projects</span>
                                        <span className={`px-2 py-0.5 rounded-[4px] text-[10px] font-bold uppercase tracking-wider ${ROLE_COLORS[myRole || "VIEWER"]}`}>{myRole}</span>
                                    </div>
                                </div>
                            </div>

                        </div>
                    </motion.div>

                    <div className="flex items-center gap-1 p-1 rounded-[4px] bg-[#0a0a0a] border border-[#2D2D2D] mb-6 overflow-x-auto">
                        {[
                            { id: "overview" as const, label: "Overview", icon: <FiUsers className="w-4 h-4" /> },
                            { id: "members" as const, label: "Members", icon: <FiUsers className="w-4 h-4" /> },
                            { id: "projects" as const, label: "Projects", icon: <FiLink className="w-4 h-4" /> },
                            { id: "settings" as const, label: "Settings", icon: <FiSettings className="w-4 h-4" /> }
                        ].map(tab => (
                            <button key={tab.id} onClick={() => { setActiveTab(tab.id); if (tab.id === "settings") { setEditName(team.name); setEditDesc(team.description || ""); } }}
                                className={`flex items-center gap-2 px-4 py-2 rounded-[4px] text-[12px] font-semibold transition-all whitespace-nowrap ${activeTab === tab.id ? "bg-[#8b5cf6] text-white" : "text-[#797979] hover:text-[#E7E7E7] hover:bg-[#1A1A1A]"}`}>
                                {tab.icon} {tab.label}
                            </button>
                        ))}
                    </div>

                    <AnimatePresence mode="wait">
                        {activeTab === "overview" && (
                            <motion.div key="overview" initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0 }}>
                                <div className="grid grid-cols-1 sm:grid-cols-4 gap-3 mb-6">
                                    {[
                                        { label: "Team Size", value: team._count.members },
                                        { label: "Linked Projects", value: team.projects?.length || 0 },
                                        { label: "Created", value: new Date(team.createdAt).toLocaleDateString() },
                                        { label: "Your Role", value: myRole || "—" },
                                    ].map((s, i) => (
                                        <motion.div key={s.label} initial={{ opacity: 0, y: 15 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: i * 0.08 }}
                                            className="rounded-[4px] border border-[#2D2D2D] bg-[#0a0a0a] p-4 text-center">
                                            <div className="text-2xl font-bold text-[#E7E7E7]">{s.value}</div>
                                            <div className="text-[11px] text-[#797979] mt-1">{s.label}</div>
                                        </motion.div>
                                    ))}
                                </div>
                                <div className="rounded-[4px] border border-[#2D2D2D] bg-[#0a0a0a] p-5">
                                    <h3 className="text-[12px] font-bold text-[#797979] mb-4 uppercase tracking-wider">Role Distribution</h3>
                                    <div className="space-y-3">
                                        {(["LEADER", "MEMBER", "VIEWER"] as const).map(role => {
                                            const count = team.members.filter(m => m.role === role).length;
                                            const pct = team.members.length > 0 ? (count / team.members.length) * 100 : 0;
                                            const colors = { LEADER: "#8b5cf6", MEMBER: "#6366f1", VIEWER: "#64748b" };
                                            return (
                                                <div key={role}>
                                                    <div className="flex justify-between text-xs mb-1">
                                                        <span className="font-semibold uppercase tracking-wider" style={{ color: colors[role] }}>{role}</span>
                                                        <span className="text-[#797979] font-mono">{count} ({pct.toFixed(0)}%)</span>
                                                    </div>
                                                    <div className="h-2 rounded-full bg-[#1A1A1A] overflow-hidden">
                                                        <motion.div className="h-full rounded-full" style={{ background: colors[role] }}
                                                            initial={{ width: 0 }} animate={{ width: `${pct}%` }} transition={{ duration: 0.6, ease: "easeOut" }} />
                                                    </div>
                                                </div>
                                            );
                                        })}
                                    </div>
                                </div>
                            </motion.div>
                        )}

                        {activeTab === "projects" && (
                            <motion.div key="projects" initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0 }}>
                                <div className="space-y-2">
                                    {team.projects?.length > 0 ? team.projects.map((p, i) => (
                                        <motion.div key={p.project.id} initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: i * 0.04 }}
                                            className="flex items-center justify-between px-5 py-4 rounded-[4px] border border-[#2D2D2D] bg-[#0a0a0a] hover:border-[#8b5cf6]/20 transition-all cursor-pointer"
                                            onClick={() => router.push(`/projects/${p.project.id}`)}>
                                            <div className="flex items-center gap-3">
                                                <div className="w-10 h-10 rounded-[4px] flex items-center justify-center text-sm font-bold text-white shrink-0" style={{ background: p.project.color }}>
                                                    {p.project.name.charAt(0).toUpperCase()}
                                                </div>
                                                <div>
                                                    <div className="text-sm font-semibold text-[#E7E7E7]">{p.project.name}</div>
                                                    <div className="text-xs text-[#797979]">Owned by {p.project.owner.name} · {p.project._count.scans} scans</div>
                                                </div>
                                            </div>
                                            <div className="text-xs text-[#8b5cf6]">View Project →</div>
                                        </motion.div>
                                    )) : <div className="text-center py-10 text-[#797979] text-sm">No projects linked to this team yet. Link teams from inside a project.</div>}
                                </div>
                            </motion.div>
                        )}

                        {activeTab === "members" && (
                            <motion.div key="members" initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0 }}>
                                {isLeader && (
                                    <div className="rounded-[4px] border border-[#2D2D2D] bg-[#0a0a0a] p-5 mb-5">
                                        <h3 className="text-[12px] font-bold text-[#797979] mb-3 uppercase tracking-wider">Send Team Invitation</h3>
                                        <div className="flex gap-3 flex-wrap">
                                            <input type="email" value={inviteEmail} onChange={e => setInviteEmail(e.target.value)} placeholder="user@example.com"
                                                className="flex-1 min-w-[200px] px-4 py-2.5 rounded-[4px] bg-[#0D0D0D] border border-[#2D2D2D] text-sm text-[#E7E7E7] placeholder:text-[#797979] focus:outline-none focus:border-[#8b5cf6]/50 transition-all" />
                                            <select value={inviteRole} onChange={e => setInviteRole(e.target.value)}
                                                className="px-4 py-2.5 rounded-[4px] bg-[#0D0D0D] border border-[#2D2D2D] text-sm text-[#E7E7E7] focus:outline-none focus:border-[#8b5cf6]/50 transition-all">
                                                <option value="MEMBER">Member</option>
                                                <option value="VIEWER">Viewer</option>
                                            </select>
                                            <button onClick={() => inviteMutation.mutate()} disabled={!inviteEmail || inviteMutation.isPending}
                                                className="px-5 py-2.5 rounded-[4px] text-[12px] font-bold bg-[#8b5cf6] hover:bg-[#7c3aed] transition-all disabled:opacity-40 text-white">
                                                {inviteMutation.isPending ? "Sending…" : "Send Invite"}
                                            </button>
                                        </div>
                                        {inviteMutation.isError && <p className="text-xs text-red-400 mt-2">Failed to invite</p>}
                                        {inviteMutation.isSuccess && <p className="text-xs text-green-400 mt-2">Invitation sent successfully!</p>}
                                    </div>
                                )}

                                {team.invitations?.length > 0 && (
                                    <div className="mb-6">
                                        <h3 className="text-[11px] font-bold text-[#797979] mb-3 uppercase tracking-wider">Pending Invitations ({team.invitations.length})</h3>
                                        <div className="space-y-2">
                                            {team.invitations.map((inv) => (
                                                <div key={inv.id} className="flex items-center justify-between px-5 py-3 rounded-[4px] border border-yellow-500/20 bg-yellow-500/5">
                                                    <div className="flex items-center gap-3">
                                                        <div className="w-8 h-8 rounded-full border border-yellow-500/30 flex items-center justify-center text-xs text-yellow-500"></div>
                                                        <div>
                                                            <div className="text-sm font-semibold text-[#E7E7E7]">{inv.receiver.email}</div>
                                                            <div className="text-xs text-[#797979]">Invited as {inv.role}</div>
                                                        </div>
                                                    </div>
                                                    {isLeader && (
                                                        <button onClick={() => { if (confirm("Cancel this invitation?")) cancelInviteMutation.mutate(inv.id); }}
                                                            className="text-xs text-[#797979] hover:text-red-400 transition-colors">Cancel</button>
                                                    )}
                                                </div>
                                            ))}
                                        </div>
                                    </div>
                                )}

                                <h3 className="text-[11px] font-bold text-[#797979] mb-3 uppercase tracking-wider">Active Members ({team.members.length})</h3>
                                <div className="space-y-2">
                                    {team.members.map((m, i) => (
                                        <motion.div key={m.id} initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: i * 0.04 }}
                                            className="flex items-center justify-between px-5 py-4 rounded-[4px] border border-[#2D2D2D] bg-[#0a0a0a] hover:border-[#8b5cf6]/20 transition-all">
                                            <div className="flex items-center gap-3">
                                                <div className="w-10 h-10 rounded-full flex items-center justify-center text-sm font-bold text-white" style={{ background: team.color }}>
                                                    {m.user.name.charAt(0).toUpperCase()}
                                                </div>
                                                <div>
                                                    <div className="text-sm font-semibold text-[#E7E7E7]">{m.user.name}</div>
                                                    <div className="text-xs text-[#797979]">{m.user.email} · Joined {new Date(m.joinedAt).toLocaleDateString()}</div>
                                                </div>
                                            </div>
                                            <div className="flex items-center gap-3">
                                                {isLeader && m.role !== "LEADER" ? (
                                                    <select value={m.role} onChange={e => changeRoleMutation.mutate({ memberId: m.id, role: e.target.value })}
                                                        className="px-3 py-1.5 rounded-[4px] bg-[#0D0D0D] border border-[#2D2D2D] text-xs text-[#E7E7E7] focus:outline-none focus:border-[#8b5cf6]/50 transition-all">
                                                        <option value="MEMBER">Member</option>
                                                        <option value="VIEWER">Viewer</option>
                                                    </select>
                                                ) : (
                                                    <span className={`px-2.5 py-1 rounded-[4px] text-[10px] font-bold uppercase tracking-wider border ${ROLE_COLORS[m.role]}`}>{m.role}</span>
                                                )}
                                                {isLeader && m.role !== "LEADER" && (
                                                    <button onClick={() => { if (confirm(`Remove ${m.user.name}?`)) removeMutation.mutate(m.id); }}
                                                        className="text-xs text-[#797979] hover:text-red-400 px-2 py-1 rounded-[4px] hover:bg-red-500/10 transition-all">
                                                        <FiTrash2 className="w-4 h-4" />
                                                    </button>
                                                )}
                                            </div>
                                        </motion.div>
                                    ))}
                                </div>
                            </motion.div>
                        )}

                        {activeTab === "settings" && (
                            <motion.div key="settings" initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0 }}>
                                <div className="rounded-[4px] border border-[#2D2D2D] bg-[#0a0a0a] p-6 mb-6">
                                    <h3 className="text-[12px] font-bold text-[#797979] mb-4 uppercase tracking-wider">Team Settings</h3>
                                    <div className="space-y-4">
                                        <div>
                                            <label className="block text-[11px] font-semibold text-[#797979] mb-1.5 uppercase tracking-wider">Name</label>
                                            <input type="text" value={editName} onChange={e => setEditName(e.target.value)} disabled={!isLeader}
                                                className="w-full px-4 py-2.5 rounded-[4px] bg-[#0D0D0D] border border-[#2D2D2D] text-sm text-[#E7E7E7] focus:outline-none focus:border-[#8b5cf6]/50 transition-all disabled:opacity-50" />
                                        </div>
                                        <div>
                                            <label className="block text-[11px] font-semibold text-[#797979] mb-1.5 uppercase tracking-wider">Description</label>
                                            <textarea value={editDesc} onChange={e => setEditDesc(e.target.value)} rows={3} disabled={!isLeader}
                                                className="w-full px-4 py-2.5 rounded-[4px] bg-[#0D0D0D] border border-[#2D2D2D] text-sm text-[#E7E7E7] focus:outline-none focus:border-[#8b5cf6]/50 transition-all resize-none disabled:opacity-50" />
                                        </div>
                                        {isLeader && (
                                            <button onClick={() => updateMutation.mutate()} disabled={updateMutation.isPending}
                                                className="px-5 py-2.5 rounded-[4px] text-[12px] font-bold bg-[#8b5cf6] hover:bg-[#7c3aed] transition-all disabled:opacity-40 text-white">
                                                {updateMutation.isPending ? "Saving…" : "Save Changes"}
                                            </button>
                                        )}
                                    </div>
                                </div>

                                {team.owner.id === session?.user?.id && (
                                    <div className="rounded-[4px] border border-red-500/20 bg-red-500/5 p-6">
                                        <h3 className="text-[12px] font-bold text-red-400 mb-2 uppercase tracking-wider">Danger Zone</h3>
                                        <p className="text-xs text-[#797979] mb-4">Permanently delete this team. This action cannot be undone.</p>
                                        <button onClick={() => { if (confirm("Delete this team permanently?")) deleteMutation.mutate(); }}
                                            className="px-5 py-2.5 rounded-[4px] text-[12px] font-bold bg-red-600 hover:bg-red-500 transition-all text-white">Delete Team</button>
                                    </div>
                                )}
                            </motion.div>
                        )}
                    </AnimatePresence>
                </div>
            </main>
        </div>
    );
}
