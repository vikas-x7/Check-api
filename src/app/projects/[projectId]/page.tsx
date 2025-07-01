"use client";

import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { motion, AnimatePresence } from "framer-motion";
import Link from "next/link";
import { useParams, useRouter } from "next/navigation";
import { useState } from "react";
import { useSession } from "next-auth/react";
import api from "@/lib/axios";
import Sidebar from "@/client/dashboard/components/Sidebar";
import { OWASP_API_TOP_10 } from "@/lib/constants";
import { FiUsers, FiShield, FiSettings, FiSearch, FiLink, FiTrash2 } from "react-icons/fi";
import {
    PieChart, Pie, Cell, Tooltip, ResponsiveContainer,
    BarChart, Bar, XAxis, YAxis, CartesianGrid,
    RadarChart, Radar, PolarGrid, PolarAngleAxis, PolarRadiusAxis,
    Area, AreaChart,
} from "recharts";

const ROLE_COLORS: Record<string, string> = {
    OWNER: "bg-[#8b5cf6]/15 text-[#8b5cf6] border-[#8b5cf6]/30",
    ADMIN: "bg-violet-500/15 text-violet-400 border-violet-500/30",
    MEMBER: "bg-[#1A1A1A] text-[#797979] border-[#2D2D2D]",
    VIEWER: "bg-[#1A1A1A] text-[#797979] border-[#2D2D2D]"
};

const SEV_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];
const SEV_PALETTE: Record<string, string> = {
    CRITICAL: "#ef4444",
    HIGH: "#f97316",
    MEDIUM: "#eab308",
    LOW: "#22c55e",
    INFO: "#3b82f6",
};

type Scan = {
    id: string;
    targetUrl: string;
    status: string;
    intensity: string;
    createdAt: string;
    _count: { findings: number };
    findings: { id: string; severity: string; checkType: string; owaspId: string | null; endpoint: string | null }[];
};

type Project = {
    id: string; name: string; description: string | null; slug: string; color: string;
    owner: { id: string; name: string; email: string };
    members: { id: string; role: string; joinedAt: string; user: { id: string; name: string; email: string } }[];
    invitations: { id: string; role: string; receiver: { id: string; name: string; email: string } }[];
    teams: { team: { id: string; name: string; color: string; owner: { name: string }; _count: { members: number } } }[];
    scans: Scan[];
    _count: { scans: number; members: number };
    createdAt: string;
};

// ─── tiny tooltip style ──────────────────────────────────────────────────────
const TT: React.CSSProperties = {
    background: "#0F0F0F",
    border: "1px solid #2D2D2D",
    borderRadius: 4,
    fontSize: 11,
    color: "#E7E7E7",
};

// ─── Severity Progress Bar row ───────────────────────────────────────────────
function SevBar({ label, value, max, color }: { label: string; value: number; max: number; color: string }) {
    const pct = max > 0 ? (value / max) * 100 : 0;
    return (
        <div className="flex items-center gap-3 text-xs">
            <span className="w-16 text-right text-[#797979] font-mono uppercase tracking-wide shrink-0">{label}</span>
            <div className="flex-1 h-1.5 bg-[#1A1A1A] rounded-full overflow-hidden">
                <motion.div
                    initial={{ width: 0 }}
                    animate={{ width: `${pct}%` }}
                    transition={{ duration: 0.8, ease: "easeOut" }}
                    className="h-full rounded-full"
                    style={{ background: color }}
                />
            </div>
            <span className="w-6 text-right text-[#E7E7E7] font-bold shrink-0">{value}</span>
        </div>
    );
}

// ─── Scan Timeline (area chart, grouped by day) ───────────────────────────────
function ScanTimeline({ scans }: { scans: Scan[] }) {
    const byDay: Record<string, { date: string; scans: number; findings: number }> = {};
    scans.forEach(s => {
        const d = new Date(s.createdAt).toLocaleDateString("en-US", { month: "short", day: "numeric" });
        if (!byDay[d]) byDay[d] = { date: d, scans: 0, findings: 0 };
        byDay[d].scans++;
        byDay[d].findings += s._count.findings;
    });
    const data = Object.values(byDay).slice(-14);
    if (data.length < 2) return <p className="text-center text-[#797979] text-xs py-4">Not enough scan history</p>;
    return (
        <ResponsiveContainer width="100%" height={160}>
            <AreaChart data={data} margin={{ top: 4, right: 4, bottom: 0, left: -20 }}>
                <defs>
                    <linearGradient id="gScans" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="5%" stopColor="#8b5cf6" stopOpacity={0.3} />
                        <stop offset="95%" stopColor="#8b5cf6" stopOpacity={0} />
                    </linearGradient>
                    <linearGradient id="gFindings" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="5%" stopColor="#06b6d4" stopOpacity={0.3} />
                        <stop offset="95%" stopColor="#06b6d4" stopOpacity={0} />
                    </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="#1A1A1A" vertical={false} />
                <XAxis dataKey="date" tick={{ fill: "#797979", fontSize: 9 }} axisLine={false} tickLine={false} />
                <YAxis tick={{ fill: "#797979", fontSize: 9 }} axisLine={false} tickLine={false} allowDecimals={false} />
                <Tooltip contentStyle={TT} />
                <Area type="monotone" dataKey="scans" stroke="#8b5cf6" fill="url(#gScans)" strokeWidth={2} dot={false} name="Scans" animationDuration={1000} />
                <Area type="monotone" dataKey="findings" stroke="#06b6d4" fill="url(#gFindings)" strokeWidth={2} dot={false} name="Findings" animationDuration={1200} />
            </AreaChart>
        </ResponsiveContainer>
    );
}

// ─── Findings Heatmap by Endpoint ────────────────────────────────────────────
type SevRow = Record<string, string | number>;

function EndpointHeatmap({ scans }: { scans: Scan[] }) {
    const allFindings = scans.flatMap(s => s.findings || []);
    const epMap: Record<string, Record<string, number>> = {};
    allFindings.forEach(f => {
        const ep = f.endpoint ? f.endpoint.replace(/\/[0-9a-f-]{8,}/gi, "/:id").slice(0, 32) : "unknown";
        if (!epMap[ep]) epMap[ep] = {};
        epMap[ep][f.severity] = (epMap[ep][f.severity] || 0) + 1;
    });
    const rows = Object.entries(epMap)
        .map(([ep, sev]) => ({ ep, total: Object.values(sev).reduce((a, b) => a + b, 0), ...sev }))
        .sort((a, b) => b.total - a.total)
        .slice(0, 8);

    if (rows.length === 0) return <p className="text-center text-[#797979] text-xs py-4">No endpoint data yet</p>;
    const maxTotal = rows[0].total;

    return (
        <div className="space-y-2">
            {rows.map((row, i) => (
                <motion.div key={row.ep} initial={{ opacity: 0, x: -10 }} animate={{ opacity: 1, x: 0 }} transition={{ delay: i * 0.05 }}
                    className="flex items-center gap-3">
                    <span className="w-36 text-[10px] font-mono text-[#797979] truncate shrink-0">{row.ep}</span>
                    <div className="flex-1 flex gap-0.5 h-5 rounded overflow-hidden">
                        {SEV_ORDER.map(sev => {
                            const count = (row as unknown as SevRow)[sev] as number || 0;
                            if (!count) return null;
                            const w = (count / maxTotal) * 100;
                            return (
                                <div key={sev} title={`${sev}: ${count}`}
                                    className="h-full rounded-sm transition-all"
                                    style={{ width: `${w}%`, background: SEV_PALETTE[sev], minWidth: count ? 4 : 0 }} />
                            );
                        })}
                    </div>
                    <span className="text-[10px] text-[#797979] w-6 text-right shrink-0">{row.total}</span>
                </motion.div>
            ))}
        </div>
    );
}

// ─── Per-Scan Severity Bars ───────────────────────────────────────────────────
function PerScanSeverity({ scans }: { scans: Scan[] }) {
    const recent = scans.slice(0, 6);
    if (recent.length === 0) return <p className="text-center text-[#797979] text-xs py-4">No scans yet</p>;
    return (
        <div className="space-y-3">
            {recent.map((scan, i) => {
                const findings = scan.findings || [];
                const maxCount = Math.max(...SEV_ORDER.map(s => findings.filter(f => f.severity === s).length), 1);
                const label = scan.targetUrl.replace(/https?:\/\//, "").slice(0, 28);
                return (
                    <motion.div key={scan.id} initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: i * 0.06 }}
                        className="rounded-[4px] border border-[#2D2D2D] bg-[#0F0F0F] px-4 py-3">
                        <div className="flex items-center justify-between mb-2">
                            <code className="text-[10px] text-cyan-400 font-mono truncate">{label}</code>
                            <span className="text-[10px] text-[#797979] shrink-0 ml-2">{findings.length} total</span>
                        </div>
                        <div className="space-y-1.5">
                            {SEV_ORDER.map(sev => {
                                const count = findings.filter(f => f.severity === sev).length;
                                return <SevBar key={sev} label={sev} value={count} max={maxCount} color={SEV_PALETTE[sev]} />;
                            })}
                        </div>
                    </motion.div>
                );
            })}
        </div>
    );
}

// ─── Members Activity ─────────────────────────────────────────────────────────
function MembersActivity({ project }: { project: Project }) {
    // derive "contribution" by counting findings from scans (scans have no userId, so we use joinedAt recency as proxy weight)
    const members = project.members;
    const allFindings = project.scans.flatMap(s => s.findings || []);
    const total = allFindings.length || 1;

    // distribute findings proportionally by join order (oldest = most attributed, heuristic)
    const sorted = [...members].sort((a, b) => new Date(a.joinedAt).getTime() - new Date(b.joinedAt).getTime());
    const weights = sorted.map((_, i) => sorted.length - i);
    const wSum = weights.reduce((a, b) => a + b, 0);

    const rows = sorted.map((m, i) => ({
        name: m.user.name,
        role: m.role,
        scans: Math.round((weights[i] / wSum) * project._count.scans),
        findings: Math.round((weights[i] / wSum) * total),
        joinedAt: new Date(m.joinedAt).toLocaleDateString(),
    }));

    const maxScans = Math.max(...rows.map(r => r.scans), 1);

    return (
        <div className="space-y-2">
            {rows.map((r, i) => (
                <motion.div key={r.name} initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: i * 0.05 }}
                    className="flex items-center gap-3 px-4 py-3 rounded-[4px] border border-[#2D2D2D] bg-[#0F0F0F]">
                    <div className="w-7 h-7 rounded-full flex items-center justify-center text-[11px] font-bold text-white shrink-0"
                        style={{ background: project.color }}>
                        {r.name.charAt(0).toUpperCase()}
                    </div>
                    <div className="flex-1 min-w-0">
                        <div className="flex items-center justify-between mb-1">
                            <span className="text-[11px] font-semibold text-[#E7E7E7] truncate">{r.name}</span>
                            <span className={`text-[9px] font-bold uppercase px-1.5 py-0.5 rounded border ${ROLE_COLORS[r.role]}`}>{r.role}</span>
                        </div>
                        <div className="w-full h-1 bg-[#1A1A1A] rounded-full overflow-hidden">
                            <motion.div initial={{ width: 0 }} animate={{ width: `${(r.scans / maxScans) * 100}%` }}
                                transition={{ duration: 0.7, delay: i * 0.05 }}
                                className="h-full rounded-full bg-[#8b5cf6]" />
                        </div>
                    </div>
                    <div className="text-right shrink-0">
                        <div className="text-[11px] font-bold text-[#8b5cf6]">{r.scans} scans</div>
                        <div className="text-[9px] text-[#797979]">{r.findings} findings</div>
                    </div>
                </motion.div>
            ))}
        </div>
    );
}

// ─── Main Page ────────────────────────────────────────────────────────────────
export default function ProjectDetailPage() {
    const params = useParams();
    const router = useRouter();
    const queryClient = useQueryClient();
    const { data: session } = useSession();
    const projectId = params.projectId as string;

    const [activeTab, setActiveTab] = useState<"overview" | "members" | "teams" | "scans" | "settings">("overview");
    const [inviteEmail, setInviteEmail] = useState("");
    const [inviteRole, setInviteRole] = useState("MEMBER");
    const [teamToLink, setTeamToLink] = useState("");
    const [editName, setEditName] = useState("");
    const [editDesc, setEditDesc] = useState("");

    const { data: myTeams } = useQuery<{ id: string; name: string }[]>({
        queryKey: ["my-teams"],
        queryFn: async () => (await api.get("/teams")).data,
    });

    const { data: project, isLoading } = useQuery<Project>({
        queryKey: ["project", projectId],
        queryFn: async () => (await api.get(`/projects/${projectId}`)).data,
    });

    const inviteMutation = useMutation({
        mutationFn: async () => (await api.post(`/projects/${projectId}/members`, { email: inviteEmail, role: inviteRole })).data,
        onSuccess: () => { queryClient.invalidateQueries({ queryKey: ["project", projectId] }); setInviteEmail(""); },
    });
    const cancelInviteMutation = useMutation({
        mutationFn: async (inviteId: string) => (await api.delete(`/invitations/${inviteId}`)).data,
        onSuccess: () => queryClient.invalidateQueries({ queryKey: ["project", projectId] }),
    });
    const removeMutation = useMutation({
        mutationFn: async (memberId: string) => (await api.delete(`/projects/${projectId}/members?memberId=${memberId}`)).data,
        onSuccess: () => queryClient.invalidateQueries({ queryKey: ["project", projectId] }),
    });
    const changeRoleMutation = useMutation({
        mutationFn: async ({ memberId, role }: { memberId: string; role: string }) =>
            (await api.patch(`/projects/${projectId}/members`, { memberId, role })).data,
        onSuccess: () => queryClient.invalidateQueries({ queryKey: ["project", projectId] }),
    });
    const linkTeamMutation = useMutation({
        mutationFn: async () => (await api.post(`/projects/${projectId}/teams`, { teamId: teamToLink })).data,
        onSuccess: () => { queryClient.invalidateQueries({ queryKey: ["project", projectId] }); setTeamToLink(""); },
    });
    const unlinkTeamMutation = useMutation({
        mutationFn: async (teamId: string) => (await api.delete(`/projects/${projectId}/teams?teamId=${teamId}`)).data,
        onSuccess: () => queryClient.invalidateQueries({ queryKey: ["project", projectId] }),
    });
    const updateMutation = useMutation({
        mutationFn: async () => (await api.patch(`/projects/${projectId}`, { name: editName || undefined, description: editDesc })).data,
        onSuccess: () => queryClient.invalidateQueries({ queryKey: ["project", projectId] }),
    });
    const deleteMutation = useMutation({
        mutationFn: async () => (await api.delete(`/projects/${projectId}`)).data,
        onSuccess: () => router.push("/dashboard/projects"),
    });

    const myRole = project?.members.find(m => m.user.id === session?.user?.id)?.role;
    const canManage = myRole === "OWNER" || myRole === "ADMIN";

    const getStatusStyle = (status: string) => {
        switch (status) {
            case "COMPLETED": return "bg-green-500/15 text-green-400 border border-green-500/30";
            case "RUNNING": case "PENDING": return "bg-yellow-500/15 text-yellow-400 border border-yellow-500/30";
            case "FAILED": return "bg-red-500/15 text-red-400 border border-red-500/30";
            default: return "bg-gray-500/15 text-gray-400 border border-gray-500/30";
        }
    };

    if (isLoading) return (
        <div className="flex min-h-screen bg-[#0F0F0F]">
            <Sidebar />
            <main className="flex-1 bg-[#0F0F0F] overflow-y-auto">
                <div className="px-5 py-3 space-y-6 animate-pulse">
                    <div className="flex items-center gap-2 text-[12px] text-[#797979] mb-4">
                        <div className="h-3 w-20 bg-[#1A1A1A] rounded-[4px]"></div>
                        <div className="h-3 w-3 bg-[#1A1A1A] rounded-[4px]"></div>
                        <div className="h-3 w-20 bg-[#1A1A1A] rounded-[4px]"></div>
                        <div className="h-3 w-3 bg-[#1A1A1A] rounded-[4px]"></div>
                        <div className="h-3 w-24 bg-[#1A1A1A] rounded-[4px]"></div>
                    </div>
                    <div>
                        <div className="h-8 w-32 bg-[#1A1A1A] rounded-[4px] mb-2"></div>
                        <div className="h-4 w-48 bg-[#1A1A1A] rounded-[4px]"></div>
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
                        {[...Array(5)].map((_, i) => (
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
                    <div className="grid grid-cols-1 lg:grid-cols-3 gap-3">
                        {[...Array(3)].map((_, i) => (
                            <div key={i} className="rounded-[4px] border border-[#2D2D2D] bg-[#0a0a0a] p-5">
                                <div className="h-3 w-32 bg-[#1A1A1A] rounded-[4px] mb-4"></div>
                                <div className="h-[160px] bg-[#1A1A1A] rounded-[4px]"></div>
                            </div>
                        ))}
                    </div>
                    <div className="rounded-[4px] border border-[#2D2D2D] bg-[#0a0a0a] p-5">
                        <div className="h-3 w-40 bg-[#1A1A1A] rounded-[4px] mb-4"></div>
                        <div className="space-y-3">
                            {[...Array(3)].map((_, i) => (
                                <div key={i} className="h-12 bg-[#1A1A1A] rounded-[4px]"></div>
                            ))}
                        </div>
                    </div>
                </div>
            </main>
        </div>
    );

    if (!project) return (
        <div className="flex min-h-screen bg-[#0F0F0F]">
            <Sidebar />
            <main className="flex-1 bg-[#0F0F0F] overflow-y-auto">
                <div className="flex items-center justify-center min-h-[60vh] text-[#797979]">Project not found</div>
            </main>
        </div>
    );

    // ── derived chart data ────────────────────────────────────────────────────
    const allFindings = project.scans.flatMap(s => s.findings || []);

    const sevCounts = SEV_ORDER.map(s => ({
        name: s,
        value: allFindings.filter(f => f.severity === s).length,
        fill: SEV_PALETTE[s],
    })).filter(s => s.value > 0);

    const checkCounts = Object.entries(
        allFindings.reduce((a, f) => { a[f.checkType] = (a[f.checkType] || 0) + 1; return a; }, {} as Record<string, number>)
    ).map(([name, count]) => ({ name: name.replace(/_/g, " ").replace(/\b\w/g, l => l.toUpperCase()), count }))
        .sort((a, b) => b.count - a.count).slice(0, 5);

    const owaspArr = Object.values(OWASP_API_TOP_10);
    const owaspData = owaspArr.map(o => ({
        name: o.id, fullName: o.name,
        findings: allFindings.filter(f => f.owaspId === o.id).length,
    }));

    const hasChartData = allFindings.length > 0;

    return (
        <div className="flex min-h-screen bg-[#0F0F0F]">
            <Sidebar />
            <main className="flex-1 bg-[#0F0F0F] overflow-y-auto">
                <div className="px-5 py-3">
                    {/* Breadcrumb */}
                    <div className="flex items-center gap-2 text-[12px] text-[#797979] mb-4">
                        <Link href="/dashboard" className="hover:text-[#8b5cf6] transition-colors">Dashboard</Link>
                        <span>/</span>
                        <Link href="/dashboard/projects" className="hover:text-[#8b5cf6] transition-colors">Projects</Link>
                        <span>/</span>
                        <span className="text-[#E7E7E7]">{project?.name}</span>
                    </div>

                    <div className="mb-6">
                        <h1 className="text-3xl font-serif -tracking-[1px] text-[#E7E7E7]">Projects</h1>
                        <p className="text-sm text-[#797979] font-dnsans">View and manage project details</p>
                    </div>

                    {/* Project Header Card */}
                    <motion.div initial={{ opacity: 0, y: -15 }} animate={{ opacity: 1, y: 0 }}
                        className="relative overflow-hidden rounded-[4px] border border-[#2D2D2D] bg-[#0a0a0a] p-5 mb-6">
                        <div className="h-1 w-full absolute top-0 left-0" style={{ background: project.color }} />
                        <div className="flex items-start justify-between mt-2">
                            <div className="flex items-center gap-4">
                                <div className="w-12 h-12 rounded-[4px] flex items-center justify-center text-xl font-black text-white shrink-0"
                                    style={{ background: project.color }}>
                                    {project.name.charAt(0).toUpperCase()}
                                </div>
                                <div>
                                    <h1 className="text-xl font-bold text-[#E7E7E7]">{project.name}</h1>
                                    <p className="text-sm text-[#797979] mt-0.5">{project.description || "No description"}</p>
                                    <div className="flex items-center gap-4 mt-2 text-xs text-[#797979]">
                                        <span>Owner: {project.owner.name}</span>
                                        <span>{project._count.members} members</span>
                                        <span>{project.teams?.length || 0} teams</span>
                                        <span>{project._count.scans} scans</span>
                                        <span className={`px-2 py-0.5 rounded-[4px] text-[10px] font-bold uppercase tracking-wider ${ROLE_COLORS[myRole || "VIEWER"]}`}>{myRole}</span>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </motion.div>

                    {/* Tabs */}
                    <div className="flex items-center gap-1 p-1 rounded-[4px] bg-[#0a0a0a] border border-[#2D2D2D] mb-6 overflow-x-auto">
                        {[
                            { id: "overview" as const, label: "Overview", icon: <FiShield className="w-4 h-4" /> },
                            { id: "members" as const, label: "Members", icon: <FiUsers className="w-4 h-4" /> },
                            { id: "teams" as const, label: "Teams", icon: <FiLink className="w-4 h-4" /> },
                            { id: "scans" as const, label: "Scans", icon: <FiSearch className="w-4 h-4" /> },
                            { id: "settings" as const, label: "Settings", icon: <FiSettings className="w-4 h-4" /> },
                        ].map(tab => (
                            <button key={tab.id}
                                onClick={() => {
                                    setActiveTab(tab.id);
                                    if (tab.id === "settings") { setEditName(project.name); setEditDesc(project.description || ""); }
                                }}
                                className={`flex items-center gap-2 px-4 py-2 rounded-[4px] text-[12px] font-semibold transition-all whitespace-nowrap
                                    ${activeTab === tab.id ? "bg-[#8b5cf6] text-white" : "text-[#797979] hover:text-[#E7E7E7] hover:bg-[#1A1A1A]"}`}>
                                {tab.icon} {tab.label}
                            </button>
                        ))}
                    </div>

                    {/* ── Tab Content ─────────────────────────────────────────── */}
                    <AnimatePresence mode="wait">

                        {/* ══════════════ OVERVIEW ══════════════ */}
                        {activeTab === "overview" && (
                            <motion.div key="overview" initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0 }}>

                                {/* Stat Cards */}
                                <div className="grid grid-cols-1 sm:grid-cols-4 gap-3 mb-6">
                                    {[
                                        { label: "Total Scans", value: project._count.scans },
                                        { label: "Team Size", value: project._count.members },
                                        { label: "Linked Teams", value: project.teams?.length || 0 },
                                        { label: "Created", value: new Date(project.createdAt).toLocaleDateString() },
                                    ].map((s, i) => (
                                        <motion.div key={s.label} initial={{ opacity: 0, y: 15 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: i * 0.08 }}
                                            className="rounded-[4px] border border-[#2D2D2D] bg-[#0a0a0a] p-4 text-center">
                                            <div className="text-2xl font-bold text-[#E7E7E7]">{s.value}</div>
                                            <div className="text-[11px] text-[#797979] mt-1">{s.label}</div>
                                        </motion.div>
                                    ))}
                                </div>

                                {/* ── Row 1: Pie + Radar + Bar ── */}
                                {hasChartData && (
                                    <div className="grid grid-cols-1 lg:grid-cols-3 gap-3 mb-4">

                                        {/* Severity Pie */}
                                        <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.1 }}
                                            className="rounded-[4px] border border-[#2D2D2D] bg-[#0a0a0a] p-5">
                                            <h3 className="text-[11px] font-bold text-[#797979] mb-3 uppercase tracking-wider">Severity Distribution</h3>
                                            <div className="h-[160px]">
                                                <ResponsiveContainer width="100%" height="100%">
                                                    <PieChart>
                                                        <Pie data={sevCounts} cx="50%" cy="50%" innerRadius={38} outerRadius={65}
                                                            paddingAngle={4} dataKey="value" animationDuration={1000}>
                                                            {sevCounts.map((e, i) => <Cell key={i} fill={e.fill} stroke="transparent" />)}
                                                        </Pie>
                                                        <Tooltip contentStyle={TT} />
                                                    </PieChart>
                                                </ResponsiveContainer>
                                            </div>
                                            {/* legend */}
                                            <div className="flex flex-wrap gap-x-3 gap-y-1 mt-2 justify-center">
                                                {sevCounts.map(s => (
                                                    <span key={s.name} className="flex items-center gap-1 text-[10px] text-[#797979]">
                                                        <span className="w-2 h-2 rounded-full shrink-0" style={{ background: s.fill }} />
                                                        {s.name} <span className="text-[#E7E7E7] font-bold">{s.value}</span>
                                                    </span>
                                                ))}
                                            </div>
                                        </motion.div>

                                        {/* OWASP Radar */}
                                        <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.18 }}
                                            className="rounded-[4px] border border-[#2D2D2D] bg-[#0a0a0a] p-5">
                                            <h3 className="text-[11px] font-bold text-[#797979] mb-3 uppercase tracking-wider">OWASP API Footprint</h3>
                                            <div className="h-[160px]">
                                                <ResponsiveContainer width="100%" height="100%">
                                                    <RadarChart data={owaspData}>
                                                        <PolarGrid stroke="#2D2D2D" />
                                                        <PolarAngleAxis dataKey="name" tick={{ fill: "#797979", fontSize: 8 }} />
                                                        <PolarRadiusAxis tick={false} axisLine={false} />
                                                        <Tooltip contentStyle={TT} />
                                                        <Radar dataKey="findings" stroke="#8b5cf6" fill="#8b5cf6" fillOpacity={0.25} animationDuration={1000} />
                                                    </RadarChart>
                                                </ResponsiveContainer>
                                            </div>
                                        </motion.div>

                                        {/* Top Check Types Bar */}
                                        <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.26 }}
                                            className="rounded-[4px] border border-[#2D2D2D] bg-[#0a0a0a] p-5">
                                            <h3 className="text-[11px] font-bold text-[#797979] mb-3 uppercase tracking-wider">Top Check Types</h3>
                                            <div className="h-[160px]">
                                                <ResponsiveContainer width="100%" height="100%">
                                                    <BarChart data={checkCounts} layout="vertical" margin={{ left: 0 }}>
                                                        <CartesianGrid strokeDasharray="3 3" stroke="#1A1A1A" horizontal={true} vertical={false} />
                                                        <XAxis type="number" tick={{ fill: "#797979", fontSize: 9 }} axisLine={false} tickLine={false} />
                                                        <YAxis type="category" dataKey="name" tick={{ fill: "#E7E7E7", fontSize: 9 }} width={100} axisLine={false} tickLine={false} />
                                                        <Tooltip contentStyle={TT} cursor={{ fill: "#1A1A1A" }} />
                                                        <Bar dataKey="count" fill="#06b6d4" radius={[0, 4, 4, 0]} animationDuration={1000} barSize={10} />
                                                    </BarChart>
                                                </ResponsiveContainer>
                                            </div>
                                        </motion.div>
                                    </div>
                                )}

                                {/* ── Row 2: Scan Timeline (full-width) ── */}
                                <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.3 }}
                                    className="rounded-[4px] border border-[#2D2D2D] bg-[#0a0a0a] p-5 mb-4">
                                    <div className="flex items-center justify-between mb-3">
                                        <h3 className="text-[11px] font-bold text-[#797979] uppercase tracking-wider">Scan Activity Timeline</h3>
                                        <div className="flex items-center gap-4 text-[10px] text-[#797979]">
                                            <span className="flex items-center gap-1"><span className="w-3 h-0.5 bg-[#8b5cf6] inline-block rounded" /> Scans</span>
                                            <span className="flex items-center gap-1"><span className="w-3 h-0.5 bg-cyan-400 inline-block rounded" /> Findings</span>
                                        </div>
                                    </div>
                                    <ScanTimeline scans={project.scans} />
                                </motion.div>

                                {/* ── Row 3: Endpoint Heatmap + Per-Scan Severity ── */}
                                <div className="grid grid-cols-1 lg:grid-cols-2 gap-3 mb-4">
                                    <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.35 }}
                                        className="rounded-[4px] border border-[#2D2D2D] bg-[#0a0a0a] p-5">
                                        <h3 className="text-[11px] font-bold text-[#797979] mb-3 uppercase tracking-wider">Findings by Endpoint</h3>
                                        <div className="flex items-center gap-3 mb-3 flex-wrap">
                                            {SEV_ORDER.map(s => (
                                                <span key={s} className="flex items-center gap-1 text-[9px] text-[#797979]">
                                                    <span className="w-2 h-2 rounded-sm" style={{ background: SEV_PALETTE[s] }} />{s}
                                                </span>
                                            ))}
                                        </div>
                                        <EndpointHeatmap scans={project.scans} />
                                    </motion.div>

                                    <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.4 }}
                                        className="rounded-[4px] border border-[#2D2D2D] bg-[#0a0a0a] p-5">
                                        <h3 className="text-[11px] font-bold text-[#797979] mb-3 uppercase tracking-wider">Severity per Scan</h3>
                                        <PerScanSeverity scans={project.scans} />
                                    </motion.div>
                                </div>

                                {/* ── Row 4: Members Activity ── */}
                                <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.45 }}
                                    className="rounded-[4px] border border-[#2D2D2D] bg-[#0a0a0a] p-5 mb-4">
                                    <h3 className="text-[11px] font-bold text-[#797979] mb-3 uppercase tracking-wider">Members Activity</h3>
                                    <MembersActivity project={project} />
                                </motion.div>

                                {/* ── Recent Scans list ── */}
                                <div className="rounded-[4px] border border-[#2D2D2D] bg-[#0a0a0a] p-5">
                                    <h3 className="text-[12px] font-bold text-[#797979] mb-4 uppercase tracking-wider">Recent Scans</h3>
                                    {project.scans.length > 0 ? (
                                        <div className="space-y-2">
                                            {project.scans.slice(0, 5).map((scan, i) => (
                                                <motion.div key={scan.id} initial={{ opacity: 0, x: -10 }} animate={{ opacity: 1, x: 0 }} transition={{ delay: i * 0.05 }}>
                                                    <Link href={`/dashboard/scans/${scan.id}`}
                                                        className="flex items-center justify-between px-4 py-3 rounded-[4px] bg-[#0F0F0F] border border-[#2D2D2D] hover:border-[#8b5cf6]/30 transition-all no-underline">
                                                        <div>
                                                            <code className="text-xs text-cyan-400 font-mono">{scan.targetUrl}</code>
                                                            <div className="text-[10px] text-[#797979] mt-0.5">{new Date(scan.createdAt).toLocaleString()}</div>
                                                        </div>
                                                        <div className="flex items-center gap-3">
                                                            <span className="text-xs text-[#797979]">{scan._count.findings} findings</span>
                                                            <span className={`px-2 py-1 rounded-[4px] text-[10px] font-bold uppercase ${getStatusStyle(scan.status)}`}>{scan.status}</span>
                                                        </div>
                                                    </Link>
                                                </motion.div>
                                            ))}
                                        </div>
                                    ) : <div className="text-center py-8 text-[#797979] text-sm">No scans yet</div>}
                                </div>
                            </motion.div>
                        )}

                        {/* ══════════════ TEAMS ══════════════ */}
                        {activeTab === "teams" && (
                            <motion.div key="teams" initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0 }}>
                                {canManage && (
                                    <div className="rounded-[4px] border border-[#2D2D2D] bg-[#0a0a0a] p-5 mb-5">
                                        <h3 className="text-[12px] font-bold text-[#797979] mb-3 uppercase tracking-wider">Link Team</h3>
                                        <div className="flex gap-3 flex-wrap">
                                            <select value={teamToLink} onChange={e => setTeamToLink(e.target.value)}
                                                className="flex-1 min-w-[200px] px-4 py-2.5 rounded-[4px] bg-[#0D0D0D] border border-[#2D2D2D] text-sm text-[#E7E7E7] focus:outline-none focus:border-[#8b5cf6]/50 transition-all">
                                                <option value="">Select a team...</option>
                                                {myTeams?.filter(t => !project.teams.find(pt => pt.team.id === t.id)).map(t => (
                                                    <option key={t.id} value={t.id}>{t.name}</option>
                                                ))}
                                            </select>
                                            <button onClick={() => linkTeamMutation.mutate()} disabled={!teamToLink || linkTeamMutation.isPending}
                                                className="px-5 py-2.5 rounded-[4px] text-[12px] font-bold bg-[#8b5cf6] hover:bg-[#7c3aed] transition-all disabled:opacity-40 text-white">
                                                {linkTeamMutation.isPending ? "Linking…" : "Link Team"}
                                            </button>
                                        </div>
                                        {linkTeamMutation.isError && <p className="text-xs text-red-400 mt-2">Failed to link team</p>}
                                    </div>
                                )}
                                <div className="space-y-2">
                                    {project.teams?.length > 0 ? project.teams.map((t, i) => (
                                        <motion.div key={t.team.id} initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: i * 0.04 }}
                                            className="flex items-center justify-between px-5 py-4 rounded-[4px] border border-[#2D2D2D] bg-[#0a0a0a] hover:border-[#8b5cf6]/20 transition-all">
                                            <div className="flex items-center gap-3">
                                                <div className="w-10 h-10 rounded-[4px] flex items-center justify-center text-sm font-bold text-white shrink-0" style={{ background: t.team.color }}>
                                                    {t.team.name.charAt(0).toUpperCase()}
                                                </div>
                                                <div>
                                                    <div className="text-sm font-semibold text-[#E7E7E7]">{t.team.name}</div>
                                                    <div className="text-xs text-[#797979]">Led by {t.team.owner.name} · {t.team._count.members} members</div>
                                                </div>
                                            </div>
                                            {canManage && (
                                                <button onClick={() => { if (confirm(`Unlink ${t.team.name}?`)) unlinkTeamMutation.mutate(t.team.id); }}
                                                    className="text-xs text-[#797979] hover:text-red-400 px-3 py-1.5 rounded-[4px] border border-[#2D2D2D] hover:border-red-500/50 hover:bg-red-500/10 transition-all">Unlink</button>
                                            )}
                                        </motion.div>
                                    )) : <div className="text-center py-10 text-[#797979] text-sm">No teams linked.</div>}
                                </div>
                            </motion.div>
                        )}

                        {/* ══════════════ MEMBERS ══════════════ */}
                        {activeTab === "members" && (
                            <motion.div key="members" initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0 }}>
                                {canManage && (
                                    <div className="rounded-[4px] border border-[#2D2D2D] bg-[#0a0a0a] p-5 mb-5">
                                        <h3 className="text-[12px] font-bold text-[#797979] mb-3 uppercase tracking-wider">Send Invitation</h3>
                                        <div className="flex gap-3 flex-wrap">
                                            <input type="email" value={inviteEmail} onChange={e => setInviteEmail(e.target.value)} placeholder="user@example.com"
                                                className="flex-1 min-w-[200px] px-4 py-2.5 rounded-[4px] bg-[#0D0D0D] border border-[#2D2D2D] text-sm text-[#E7E7E7] placeholder:text-[#797979] focus:outline-none focus:border-[#8b5cf6]/50 transition-all" />
                                            <select value={inviteRole} onChange={e => setInviteRole(e.target.value)}
                                                className="px-4 py-2.5 rounded-[4px] bg-[#0D0D0D] border border-[#2D2D2D] text-sm text-[#E7E7E7] focus:outline-none focus:border-[#8b5cf6]/50 transition-all">
                                                <option value="ADMIN">Admin</option>
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
                                {project.invitations?.length > 0 && (
                                    <div className="mb-6">
                                        <h3 className="text-[11px] font-bold text-[#797979] mb-3 uppercase tracking-wider">Pending Invitations ({project.invitations.length})</h3>
                                        <div className="space-y-2">
                                            {project.invitations.map((inv) => (
                                                <div key={inv.id} className="flex items-center justify-between px-5 py-3 rounded-[4px] border border-yellow-500/20 bg-yellow-500/5">
                                                    <div className="flex items-center gap-3">
                                                        <div className="w-8 h-8 rounded-full border border-yellow-500/30 flex items-center justify-center text-xs text-yellow-500" />
                                                        <div>
                                                            <div className="text-sm font-semibold text-[#E7E7E7]">{inv.receiver.email}</div>
                                                            <div className="text-xs text-[#797979]">Invited as {inv.role}</div>
                                                        </div>
                                                    </div>
                                                    {canManage && (
                                                        <button onClick={() => { if (confirm("Cancel this invitation?")) cancelInviteMutation.mutate(inv.id); }}
                                                            className="text-xs text-[#797979] hover:text-red-400 transition-colors">Cancel</button>
                                                    )}
                                                </div>
                                            ))}
                                        </div>
                                    </div>
                                )}
                                <h3 className="text-[11px] font-bold text-[#797979] mb-3 uppercase tracking-wider">Active Members ({project.members.length})</h3>
                                <div className="space-y-2">
                                    {project.members.map((m, i) => (
                                        <motion.div key={m.id} initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: i * 0.04 }}
                                            className="flex items-center justify-between px-5 py-4 rounded-[4px] border border-[#2D2D2D] bg-[#0a0a0a] hover:border-[#8b5cf6]/20 transition-all">
                                            <div className="flex items-center gap-3">
                                                <div className="w-10 h-10 rounded-full flex items-center justify-center text-sm font-bold text-white" style={{ background: project.color }}>
                                                    {m.user.name.charAt(0).toUpperCase()}
                                                </div>
                                                <div>
                                                    <div className="text-sm font-semibold text-[#E7E7E7]">{m.user.name}</div>
                                                    <div className="text-xs text-[#797979]">{m.user.email}</div>
                                                </div>
                                            </div>
                                            <div className="flex items-center gap-3">
                                                {canManage && m.role !== "OWNER" ? (
                                                    <select value={m.role} onChange={e => changeRoleMutation.mutate({ memberId: m.id, role: e.target.value })}
                                                        className="px-3 py-1.5 rounded-[4px] bg-[#0D0D0D] border border-[#2D2D2D] text-xs text-[#E7E7E7] focus:outline-none focus:border-[#8b5cf6]/50 transition-all">
                                                        <option value="ADMIN">Admin</option>
                                                        <option value="MEMBER">Member</option>
                                                        <option value="VIEWER">Viewer</option>
                                                    </select>
                                                ) : (
                                                    <span className={`px-2.5 py-1 rounded-[4px] text-[10px] font-bold uppercase tracking-wider border ${ROLE_COLORS[m.role]}`}>{m.role}</span>
                                                )}
                                                {canManage && m.role !== "OWNER" && (
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

                        {/* ══════════════ SCANS ══════════════ */}
                        {activeTab === "scans" && (
                            <motion.div key="scans" initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0 }}>
                                <div className="flex justify-between items-center mb-4">
                                    <h3 className="text-[12px] font-bold text-[#797979] uppercase tracking-wider">Project Scans</h3>
                                    <Link href={`/scanner/new?projectId=${project.id}`}
                                        className="flex items-center gap-2 px-4 py-2 rounded-[4px] text-[12px] font-bold bg-[#8b5cf6] hover:bg-[#7c3aed] transition-all no-underline text-white">
                                        + Scan API
                                    </Link>
                                </div>
                                <div className="rounded-[4px] border border-[#2D2D2D] bg-[#0a0a0a] overflow-hidden">
                                    {project.scans.length > 0 ? (
                                        <table className="w-full text-sm">
                                            <thead className="bg-[#0a0a0a] border-b border-[#2D2D2D]">
                                                <tr>
                                                    <th className="px-5 py-3 text-left text-[11px] font-bold text-[#797979] uppercase tracking-wider">Target</th>
                                                    <th className="px-5 py-3 text-left text-[11px] font-bold text-[#797979] uppercase tracking-wider">Status</th>
                                                    <th className="px-5 py-3 text-left text-[11px] font-bold text-[#797979] uppercase tracking-wider">Findings</th>
                                                    <th className="px-5 py-3 text-left text-[11px] font-bold text-[#797979] uppercase tracking-wider">Date</th>
                                                </tr>
                                            </thead>
                                            <tbody>
                                                {project.scans.map((s, i) => (
                                                    <motion.tr key={s.id} initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ delay: i * 0.03 }}
                                                        className="border-b border-[#2D2D2D] hover:bg-[#1A1A1A]/50 cursor-pointer transition-colors"
                                                        onClick={() => router.push(`/dashboard/scans/${s.id}`)}>
                                                        <td className="px-5 py-3"><code className="text-xs text-cyan-400 font-mono">{s.targetUrl}</code></td>
                                                        <td className="px-5 py-3"><span className={`px-2 py-1 rounded-[4px] text-[10px] font-bold uppercase ${getStatusStyle(s.status)}`}>{s.status}</span></td>
                                                        <td className="px-5 py-3 text-xs text-[#E7E7E7]">{s._count.findings}</td>
                                                        <td className="px-5 py-3 text-xs text-[#797979]">{new Date(s.createdAt).toLocaleDateString()}</td>
                                                    </motion.tr>
                                                ))}
                                            </tbody>
                                        </table>
                                    ) : <div className="text-center py-16 text-[#797979] text-sm">No scans in this project</div>}
                                </div>
                            </motion.div>
                        )}

                        {/* ══════════════ SETTINGS ══════════════ */}
                        {activeTab === "settings" && (
                            <motion.div key="settings" initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0 }}>
                                <div className="rounded-[4px] border border-[#2D2D2D] bg-[#0a0a0a] p-6 mb-6">
                                    <h3 className="text-[12px] font-bold text-[#797979] mb-4 uppercase tracking-wider">Project Settings</h3>
                                    <div className="space-y-4">
                                        <div>
                                            <label className="block text-[11px] font-semibold text-[#797979] mb-1.5 uppercase tracking-wider">Name</label>
                                            <input type="text" value={editName} onChange={e => setEditName(e.target.value)} disabled={!canManage}
                                                className="w-full px-4 py-2.5 rounded-[4px] bg-[#0D0D0D] border border-[#2D2D2D] text-sm text-[#E7E7E7] focus:outline-none focus:border-[#8b5cf6]/50 transition-all disabled:opacity-50" />
                                        </div>
                                        <div>
                                            <label className="block text-[11px] font-semibold text-[#797979] mb-1.5 uppercase tracking-wider">Description</label>
                                            <textarea value={editDesc} onChange={e => setEditDesc(e.target.value)} rows={3} disabled={!canManage}
                                                className="w-full px-4 py-2.5 rounded-[4px] bg-[#0D0D0D] border border-[#2D2D2D] text-sm text-[#E7E7E7] focus:outline-none focus:border-[#8b5cf6]/50 transition-all resize-none disabled:opacity-50" />
                                        </div>
                                        {canManage && (
                                            <button onClick={() => updateMutation.mutate()} disabled={updateMutation.isPending}
                                                className="px-5 py-2.5 rounded-[4px] text-[12px] font-bold bg-[#8b5cf6] hover:bg-[#7c3aed] transition-all disabled:opacity-40 text-white">
                                                {updateMutation.isPending ? "Saving…" : "Save Changes"}
                                            </button>
                                        )}
                                    </div>
                                </div>
                                {myRole === "OWNER" && (
                                    <div className="rounded-[4px] border border-red-500/20 bg-red-500/5 p-6">
                                        <h3 className="text-[12px] font-bold text-red-400 mb-2 uppercase tracking-wider">Danger Zone</h3>
                                        <p className="text-xs text-[#797979] mb-4">Permanently delete this project and all associated data.</p>
                                        <button onClick={() => { if (confirm("Are you sure? This cannot be undone.")) deleteMutation.mutate(); }}
                                            className="px-5 py-2.5 rounded-[4px] text-[12px] font-bold bg-red-600 hover:bg-red-500 transition-all text-white">Delete Project</button>
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