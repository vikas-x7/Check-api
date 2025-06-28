"use client";
import { motion } from "framer-motion";
import {
    PieChart, Pie, Cell, Tooltip, ResponsiveContainer,
    BarChart, Bar, XAxis, YAxis, CartesianGrid,
    RadarChart, Radar, PolarGrid, PolarAngleAxis, PolarRadiusAxis,
    AreaChart, Area,
    Treemap,
    ScatterChart, Scatter, ZAxis,
    Legend,
} from "recharts";
import { FindingResult } from "@/types";
import { SEVERITY_COLORS, OWASP_API_TOP_10 } from "@/lib/constants";

type Props = { findings: FindingResult[]; riskScore: number; grade: { grade: string; color: string; label: string } };

// --- Data Builders ---

function buildSeverityCounts(findings: FindingResult[]) {
    return ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"].map(s => ({
        name: s, value: findings.filter(f => f.severity === s).length,
        fill: SEVERITY_COLORS[s as keyof typeof SEVERITY_COLORS] || "#6b7280",
    })).filter(s => s.value > 0);
}

function buildCheckTypes(findings: FindingResult[]) {
    return Object.entries(findings.reduce((a, f) => { a[f.checkType] = (a[f.checkType] || 0) + 1; return a; }, {} as Record<string, number>))
        .map(([name, count]) => ({ name: name.replace(/_/g, " ").replace(/\b\w/g, l => l.toUpperCase()), count }))
        .sort((a, b) => b.count - a.count);
}

function buildOwaspRadar(findings: FindingResult[]) {
    const owaspArr = Object.values(OWASP_API_TOP_10);
    return owaspArr.map(o => ({
        name: o.id, fullName: o.name,
        findings: findings.filter(f => f.owaspId === o.id).length,
        fullMark: Math.max(5, ...owaspArr.map(x => findings.filter(f => f.owaspId === x.id).length)),
    }));
}

function buildCumulativeTimeline(findings: FindingResult[]) {
    const severity = findings.map((f, i) => ({
        index: i + 1,
        critical: f.severity === "CRITICAL" ? 1 : 0,
        high: f.severity === "HIGH" ? 1 : 0,
        medium: f.severity === "MEDIUM" ? 1 : 0,
        low: f.severity === "LOW" || f.severity === "INFO" ? 1 : 0,
    }));
    return severity.reduce((acc, entry, i) => {
        const prev = i > 0 ? acc[i - 1] : { index: 0, critical: 0, high: 0, medium: 0, low: 0 };
        acc.push({ index: entry.index, critical: prev.critical + entry.critical, high: prev.high + entry.high, medium: prev.medium + entry.medium, low: prev.low + entry.low });
        return acc;
    }, [] as { index: number; critical: number; high: number; medium: number; low: number }[]);
}

function buildEndpoints(findings: FindingResult[]) {
    return Object.entries(findings.reduce((a, f) => { const k = f.endpoint || "unknown"; a[k] = (a[k] || 0) + 1; return a; }, {} as Record<string, number>))
        .sort((a, b) => b[1] - a[1]).slice(0, 8).map(([name, count]) => ({ name: name.length > 22 ? name.slice(0, 20) + "..." : name, count }));
}

function buildMethodDistribution(findings: FindingResult[]) {
    return Object.entries(findings.reduce((a, f) => { const m = (f.method || "unknown").toUpperCase(); a[m] = (a[m] || 0) + 1; return a; }, {} as Record<string, number>))
        .map(([name, count]) => ({ name, count })).sort((a, b) => b.count - a.count);
}

function buildSeverityByCheck(findings: FindingResult[]) {
    const matrix: Record<string, Record<string, number>> = {};
    findings.forEach(f => {
        const check = f.checkType.replace(/_/g, " ").replace(/\b\w/g, l => l.toUpperCase());
        if (!matrix[check]) matrix[check] = {};
        matrix[check][f.severity] = (matrix[check][f.severity] || 0) + 1;
    });
    return Object.entries(matrix).map(([check, sevs]) => ({
        check,
        CRITICAL: sevs["CRITICAL"] || 0,
        HIGH: sevs["HIGH"] || 0,
        MEDIUM: sevs["MEDIUM"] || 0,
        LOW: sevs["LOW"] || 0,
        INFO: sevs["INFO"] || 0,
    }));
}

function buildAttackSurface(findings: FindingResult[]) {
    const groups: Record<string, Record<string, number>> = {};
    findings.forEach(f => {
        const check = f.checkType.replace(/_/g, " ").replace(/\b\w/g, l => l.toUpperCase());
        const ep = f.endpoint || "unknown";
        if (!groups[check]) groups[check] = {};
        groups[check][ep] = (groups[check][ep] || 0) + 1;
    });
    return Object.entries(groups).map(([name, eps]) => ({
        name,
        children: Object.entries(eps).map(([ep, count]) => ({
            name: ep.length > 18 ? ep.slice(0, 16) + "..." : ep,
            size: count,
        })),
    }));
}

function buildOwaspCompliance(findings: FindingResult[]) {
    const owaspArr = Object.values(OWASP_API_TOP_10);
    return owaspArr.map(o => {
        const f = findings.filter(fi => fi.owaspId === o.id);
        const crits = f.filter(fi => fi.severity === "CRITICAL" || fi.severity === "HIGH").length;
        return {
            id: o.id, name: o.name, total: f.length, critical: crits,
            status: f.length === 0 ? "secure" : crits > 0 ? "critical" : "warning",
            score: f.length === 0 ? 100 : Math.max(0, 100 - crits * 25 - (f.length - crits) * 10),
        };
    });
}

function buildBubbleData(findings: FindingResult[]) {
    const sevWeight: Record<string, number> = { CRITICAL: 5, HIGH: 4, MEDIUM: 3, LOW: 2, INFO: 1 };
    const checks = buildCheckTypes(findings);
    return checks.map((c, i) => {
        const relevant = findings.filter(f => f.checkType.replace(/_/g, " ").replace(/\b\w/g, l => l.toUpperCase()) === c.name);
        const avgSev = relevant.reduce((a, f) => a + (sevWeight[f.severity] || 0), 0) / Math.max(relevant.length, 1);
        return { x: i + 1, y: avgSev, z: c.count, name: c.name };
    });
}

// --- Tooltip Styles ---
const tooltipStyle = { background: "#0F0F0F", border: "1px solid #2D2D2D", borderRadius: 4, fontSize: 12, color: "#E7E7E7" };

// eslint-disable-next-line @typescript-eslint/no-explicit-any
const TreemapContent = (props: any) => {
    const { x, y, width, height, name } = props;
    if (width < 40 || height < 20) return null;
    return (
        <g>
            <rect x={x} y={y} width={width} height={height} rx={4} fill="#8b5cf6" fillOpacity={0.35} stroke="#8b5cf6" strokeWidth={1} strokeOpacity={0.5} />
            <text x={x + width / 2} y={y + height / 2} textAnchor="middle" dominantBaseline="middle" fill="#E7E7E7" fontSize={Math.min(10, width / 6)}>
                {name}
            </text>
        </g>
    );
};


export default function OverviewTab({ findings, riskScore, grade }: Props) {
    const severityCounts = buildSeverityCounts(findings);
    const checkTypes = buildCheckTypes(findings);
    const owaspData = buildOwaspRadar(findings);
    const cumulativeTimeline = buildCumulativeTimeline(findings);
    const topFindings = findings.filter(f => f.severity === "CRITICAL" || f.severity === "HIGH").slice(0, 6);
    const endpoints = buildEndpoints(findings);
    const methodDist = buildMethodDistribution(findings);
    const sevByCheck = buildSeverityByCheck(findings);
    const attackSurface = buildAttackSurface(findings);
    const owaspCompliance = buildOwaspCompliance(findings);
    const bubbleData = buildBubbleData(findings);

    const uniqueEndpoints = new Set(findings.map(f => f.endpoint)).size;
    const uniqueChecks = new Set(findings.map(f => f.checkType)).size;
    const avgFindingsPerEndpoint = uniqueEndpoints > 0 ? (findings.length / uniqueEndpoints).toFixed(1) : "0";

    return (
        <div className="space-y-4">

            {/* ========== ROW 1: Risk Grade + Severity Donut + Severity Bars ========== */}
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
                {/* Risk Grade Circle */}
                <motion.div initial={{ opacity: 0, scale: 0.8 }} animate={{ opacity: 1, scale: 1 }} transition={{ delay: 0.1, duration: 0.5 }}
                    className="border border-[#2D2D2D] rounded-[4px] p-6 flex flex-col items-center justify-center">
                    <h3 className="text-sm font-bold text-[#797979] mb-4 uppercase tracking-wider">Security Grade</h3>
                    <div className="relative w-36 h-36">
                        <svg viewBox="0 0 120 120" className="w-full h-full -rotate-90">
                            <circle cx="60" cy="60" r="50" fill="none" stroke="rgba(100,116,139,0.2)" strokeWidth="10" />
                            <motion.circle cx="60" cy="60" r="50" fill="none" stroke={grade.color} strokeWidth="10" strokeLinecap="round" strokeDasharray={`${2 * Math.PI * 50}`}
                                initial={{ strokeDashoffset: 2 * Math.PI * 50 }}
                                animate={{ strokeDashoffset: 2 * Math.PI * 50 * (1 - riskScore / 100) }}
                                transition={{ duration: 1.5, ease: "easeOut", delay: 0.3 }}
                            />
                        </svg>
                        <div className="absolute inset-0 flex flex-col items-center justify-center">
                            <span className="text-4xl font-black" style={{ color: grade.color }}>{grade.grade}</span>
                            <span className="text-[10px] text-[#797979] font-medium">{riskScore}/100</span>
                        </div>
                    </div>
                    <span className="mt-3 text-sm font-bold" style={{ color: grade.color }}>{grade.label}</span>
                    <div className="mt-4 grid grid-cols-3 gap-3 w-full">
                        <div className="text-center bg-[#0a0a0a] rounded-[4px] py-2">
                            <div className="text-base font-black text-[#E7E7E7]">{findings.length}</div>
                            <div className="text-[9px] text-[#797979] uppercase">Findings</div>
                        </div>
                        <div className="text-center bg-[#0a0a0a] rounded-[4px] py-2">
                            <div className="text-base font-black text-[#06b6d4]">{uniqueEndpoints}</div>
                            <div className="text-[9px] text-[#797979] uppercase">Endpoints</div>
                        </div>
                        <div className="text-center bg-[#0a0a0a] rounded-[4px] py-2">
                            <div className="text-base font-black text-[#f59e0b]">{uniqueChecks}</div>
                            <div className="text-[9px] text-[#797979] uppercase">Checks</div>
                        </div>
                    </div>
                </motion.div>

                {/* Severity Distribution Donut */}
                <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.2 }}
                    className="border border-[#2D2D2D] rounded-[4px] p-6">
                    <h3 className="text-sm font-bold text-[#797979] mb-3 uppercase tracking-wider">Severity Distribution</h3>
                    <ResponsiveContainer width="100%" height={200}>
                        <PieChart>
                            <Pie data={severityCounts} cx="50%" cy="50%" innerRadius={50} outerRadius={80} paddingAngle={3} dataKey="value" animationDuration={1200}>
                                {severityCounts.map((e, i) => <Cell key={i} fill={e.fill} stroke="transparent" />)}
                            </Pie>
                            <Tooltip contentStyle={tooltipStyle} />
                        </PieChart>
                    </ResponsiveContainer>
                    <div className="flex flex-wrap justify-center gap-3 mt-2">
                        {severityCounts.map(s => (
                            <div key={s.name} className="flex items-center gap-1.5 text-xs text-[#797979]">
                                <span className="w-2.5 h-2.5 rounded-full" style={{ background: s.fill }} />
                                {s.name} ({s.value})
                            </div>
                        ))}
                    </div>
                </motion.div>

                {/* Severity Breakdown Bars */}
                <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.3 }}
                    className="border border-[#2D2D2D] rounded-[4px] p-6">
                    <h3 className="text-sm font-bold text-[#797979] mb-4 uppercase tracking-wider">Severity Breakdown</h3>
                    <div className="space-y-4">
                        {["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"].map((sev, i) => {
                            const count = findings.filter(f => f.severity === sev).length;
                            const pct = findings.length > 0 ? (count / findings.length) * 100 : 0;
                            const color = SEVERITY_COLORS[sev as keyof typeof SEVERITY_COLORS] || "#6b7280";
                            return (
                                <div key={sev}>
                                    <div className="flex justify-between items-center mb-1">
                                        <span className="text-xs font-semibold uppercase tracking-wide" style={{ color }}>{sev}</span>
                                        <span className="text-xs text-[#797979] font-mono">{count} ({pct.toFixed(0)}%)</span>
                                    </div>
                                    <div className="h-2 rounded-[4px] bg-[#0a0a0a] overflow-hidden">
                                        <motion.div className="h-full rounded-[4px]" style={{ background: color }}
                                            initial={{ width: 0 }} animate={{ width: `${pct}%` }}
                                            transition={{ delay: 0.4 + i * 0.1, duration: 0.6, ease: "easeOut" }} />
                                    </div>
                                </div>
                            );
                        })}
                    </div>
                </motion.div>
            </div>

            {/* ========== ROW 2: Check Types Bar + Cumulative Findings ========== */}
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                <motion.div initial={{ opacity: 0, x: -20 }} animate={{ opacity: 1, x: 0 }} transition={{ delay: 0.4 }}
                    className="border border-[#2D2D2D] rounded-[4px] p-6">
                    <h3 className="text-sm font-bold text-[#797979] mb-3 uppercase tracking-wider">Findings by Check Type</h3>
                    {checkTypes.length > 0 ? (
                        <ResponsiveContainer width="100%" height={Math.max(220, checkTypes.length * 32)}>
                            <BarChart data={checkTypes} layout="vertical" margin={{ left: 10 }}>
                                <CartesianGrid strokeDasharray="3 3" stroke="#2D2D2D" />
                                <XAxis type="number" tick={{ fill: "#797979", fontSize: 11 }} />
                                <YAxis type="category" dataKey="name" tick={{ fill: "#E7E7E7", fontSize: 10 }} width={140} />
                                <Tooltip contentStyle={tooltipStyle} />
                                <Bar dataKey="count" fill="#8b5cf6" radius={[0, 4, 4, 0]} animationDuration={1000} />
                            </BarChart>
                        </ResponsiveContainer>
                    ) : <div className="flex items-center justify-center h-52 text-[#797979] text-sm">No findings to display</div>}
                </motion.div>

                <motion.div initial={{ opacity: 0, x: 20 }} animate={{ opacity: 1, x: 0 }} transition={{ delay: 0.5 }}
                    className="border border-[#2D2D2D] rounded-[4px] p-6">
                    <h3 className="text-sm font-bold text-[#797979] mb-3 uppercase tracking-wider">Cumulative Findings Discovery</h3>
                    {cumulativeTimeline.length > 0 ? (
                        <ResponsiveContainer width="100%" height={260}>
                            <AreaChart data={cumulativeTimeline}>
                                <CartesianGrid strokeDasharray="3 3" stroke="#2D2D2D" />
                                <XAxis dataKey="index" tick={{ fill: "#797979", fontSize: 10 }} label={{ value: "Finding #", position: "insideBottom", offset: -4, fill: "#797979", fontSize: 10 }} />
                                <YAxis tick={{ fill: "#797979", fontSize: 10 }} />
                                <Tooltip contentStyle={tooltipStyle} />
                                <Legend wrapperStyle={{ fontSize: 10, color: "#797979" }} />
                                <Area type="monotone" dataKey="critical" stackId="1" stroke="#ef4444" fill="#ef4444" fillOpacity={0.4} animationDuration={1200} />
                                <Area type="monotone" dataKey="high" stackId="1" stroke="#f97316" fill="#f97316" fillOpacity={0.3} animationDuration={1200} />
                                <Area type="monotone" dataKey="medium" stackId="1" stroke="#eab308" fill="#eab308" fillOpacity={0.2} animationDuration={1200} />
                                <Area type="monotone" dataKey="low" stackId="1" stroke="#22c55e" fill="#22c55e" fillOpacity={0.15} animationDuration={1200} />
                            </AreaChart>
                        </ResponsiveContainer>
                    ) : <div className="flex items-center justify-center h-52 text-[#797979] text-sm">No findings</div>}
                </motion.div>
            </div>

            {/* ========== ROW 3: Severity x Check Heatmap (Stacked Bar) + HTTP Method Distribution ========== */}
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
                <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.55 }}
                    className="border border-[#2D2D2D] rounded-[4px] p-6 lg:col-span-2">
                    <h3 className="text-sm font-bold text-[#797979] mb-3 uppercase tracking-wider">Severity by Security Check</h3>
                    {sevByCheck.length > 0 ? (
                        <ResponsiveContainer width="100%" height={Math.max(240, sevByCheck.length * 34)}>
                            <BarChart data={sevByCheck} layout="vertical" margin={{ left: 10 }}>
                                <CartesianGrid strokeDasharray="3 3" stroke="#2D2D2D" />
                                <XAxis type="number" tick={{ fill: "#797979", fontSize: 10 }} />
                                <YAxis type="category" dataKey="check" tick={{ fill: "#E7E7E7", fontSize: 10 }} width={140} />
                                <Tooltip contentStyle={tooltipStyle} />
                                <Legend wrapperStyle={{ fontSize: 10, color: "#797979" }} />
                                <Bar dataKey="CRITICAL" stackId="a" fill="#ef4444" radius={0} animationDuration={1000} />
                                <Bar dataKey="HIGH" stackId="a" fill="#f97316" radius={0} animationDuration={1000} />
                                <Bar dataKey="MEDIUM" stackId="a" fill="#eab308" radius={0} animationDuration={1000} />
                                <Bar dataKey="LOW" stackId="a" fill="#22c55e" radius={0} animationDuration={1000} />
                                <Bar dataKey="INFO" stackId="a" fill="#3b82f6" radius={[0, 4, 4, 0]} animationDuration={1000} />
                            </BarChart>
                        </ResponsiveContainer>
                    ) : <div className="flex items-center justify-center h-52 text-[#797979] text-sm">No data</div>}
                </motion.div>

                <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.6 }}
                    className="border border-[#2D2D2D] rounded-[4px] p-6">
                    <h3 className="text-sm font-bold text-[#797979] mb-3 uppercase tracking-wider">HTTP Method Breakdown</h3>
                    {methodDist.length > 0 ? (
                        <ResponsiveContainer width="100%" height={220}>
                            <PieChart>
                                <Pie data={methodDist} cx="50%" cy="50%" outerRadius={75} dataKey="count" nameKey="name" animationDuration={1200} label={({ name, percent }) => `${name} ${((percent || 0) * 100).toFixed(0)}%`}>
                                    {methodDist.map((_, i) => <Cell key={i} fill={["#8b5cf6", "#06b6d4", "#f59e0b", "#ef4444", "#22c55e", "#3b82f6"][i % 6]} stroke="transparent" />)}
                                </Pie>
                                <Tooltip contentStyle={tooltipStyle} />
                            </PieChart>
                        </ResponsiveContainer>
                    ) : <div className="flex items-center justify-center h-52 text-[#797979] text-sm">No data</div>}
                    <div className="mt-3 text-center text-xs text-[#797979]">
                        {methodDist.length} unique HTTP verb{methodDist.length !== 1 ? "s" : ""} tested
                    </div>
                </motion.div>
            </div>

            {/* ========== ROW 4: OWASP Radar + Attack Surface Treemap ========== */}
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.65 }}
                    className="border border-[#2D2D2D] rounded-[4px] p-6">
                    <h3 className="text-sm font-bold text-[#797979] mb-3 uppercase tracking-wider">OWASP API Top 10 Radar</h3>
                    <ResponsiveContainer width="100%" height={300}>
                        <RadarChart data={owaspData}>
                            <PolarGrid stroke="#2D2D2D" />
                            <PolarAngleAxis dataKey="name" tick={{ fill: "#E7E7E7", fontSize: 9 }} />
                            <PolarRadiusAxis tick={{ fill: "#797979", fontSize: 9 }} />
                            <Radar dataKey="findings" stroke="#8b5cf6" fill="#8b5cf6" fillOpacity={0.3} animationDuration={1500} />
                        </RadarChart>
                    </ResponsiveContainer>
                </motion.div>

                <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.7 }}
                    className="border border-[#2D2D2D] rounded-[4px] p-6">
                    <h3 className="text-sm font-bold text-[#797979] mb-3 uppercase tracking-wider">Attack Surface Treemap</h3>
                    {attackSurface.length > 0 ? (
                        <ResponsiveContainer width="100%" height={300}>
                            <Treemap data={attackSurface} dataKey="size" aspectRatio={4 / 3} stroke="#1A1A1A" animationDuration={800}
                                content={<TreemapContent />} />
                        </ResponsiveContainer>
                    ) : <div className="flex items-center justify-center h-72 text-[#797979] text-sm">No data</div>}
                </motion.div>
            </div>

            {/* ========== ROW 5: Risk Bubble Scatter + OWASP Compliance Scorecard ========== */}
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                <motion.div initial={{ opacity: 0, x: -20 }} animate={{ opacity: 1, x: 0 }} transition={{ delay: 0.75 }}
                    className="border border-[#2D2D2D] rounded-[4px] p-6">
                    <h3 className="text-sm font-bold text-[#797979] mb-3 uppercase tracking-wider">Risk Intensity Bubble Map</h3>
                    {bubbleData.length > 0 ? (
                        <ResponsiveContainer width="100%" height={280}>
                            <ScatterChart margin={{ bottom: 10 }}>
                                <CartesianGrid strokeDasharray="3 3" stroke="#2D2D2D" />
                                <XAxis type="number" dataKey="x" name="Check #" tick={{ fill: "#797979", fontSize: 10 }} label={{ value: "Check Type Index", position: "insideBottom", offset: -4, fill: "#797979", fontSize: 10 }} />
                                <YAxis type="number" dataKey="y" name="Avg Severity" tick={{ fill: "#797979", fontSize: 10 }} domain={[0, 5]} label={{ value: "Avg Severity", angle: -90, position: "insideLeft", fill: "#797979", fontSize: 10 }} />
                                <ZAxis type="number" dataKey="z" range={[60, 600]} name="Count" />
                                <Tooltip contentStyle={tooltipStyle} formatter={(value, name) => [value, name === "z" ? "Findings" : name === "y" ? "Avg Severity" : name]} />
                                <Scatter data={bubbleData} fill="#8b5cf6" fillOpacity={0.6} stroke="#8b5cf6" animationDuration={1200} />
                            </ScatterChart>
                        </ResponsiveContainer>
                    ) : <div className="flex items-center justify-center h-72 text-[#797979] text-sm">No data</div>}
                </motion.div>

                <motion.div initial={{ opacity: 0, x: 20 }} animate={{ opacity: 1, x: 0 }} transition={{ delay: 0.8 }}
                    className="border border-[#2D2D2D] rounded-[4px] p-6">
                    <h3 className="text-sm font-bold text-[#797979] mb-3 uppercase tracking-wider">OWASP Compliance Scorecard</h3>
                    <div className="space-y-2 max-h-[320px] overflow-y-auto pr-2">
                        {owaspCompliance.map((o, i) => (
                            <motion.div key={o.id} initial={{ opacity: 0, x: 10 }} animate={{ opacity: 1, x: 0 }} transition={{ delay: 0.85 + i * 0.04 }}
                                className={`px-4 py-3 rounded-[4px] border transition-all duration-200
                                    ${o.status === "secure" ? "border-green-500/20 bg-green-500/5" : ""}
                                    ${o.status === "warning" ? "border-yellow-500/20 bg-yellow-500/5" : ""}
                                    ${o.status === "critical" ? "border-red-500/20 bg-red-500/5" : ""}`}>
                                <div className="flex items-center justify-between mb-1.5">
                                    <div className="flex items-center gap-2">
                                        <span className="text-xs font-mono font-bold text-[#8b5cf6]">{o.id}</span>
                                        <span className="text-xs text-[#E7E7E7] truncate max-w-[180px]">{o.name}</span>
                                    </div>
                                    <div className="flex items-center gap-2">
                                        <span className="text-xs font-mono text-[#797979]">{o.total} issues</span>
                                        <span className={`px-1.5 py-0.5 rounded text-[9px] font-bold uppercase tracking-wider
                                            ${o.status === "secure" ? "bg-green-500/15 text-green-400" : ""}
                                            ${o.status === "warning" ? "bg-yellow-500/15 text-yellow-400" : ""}
                                            ${o.status === "critical" ? "bg-red-500/15 text-red-400" : ""}`}>
                                            {o.score}%
                                        </span>
                                    </div>
                                </div>
                                <div className="h-1.5 rounded bg-[#0a0a0a] overflow-hidden">
                                    <motion.div className="h-full rounded"
                                        style={{ background: o.status === "secure" ? "#22c55e" : o.status === "warning" ? "#eab308" : "#ef4444" }}
                                        initial={{ width: 0 }} animate={{ width: `${o.score}%` }}
                                        transition={{ delay: 0.9 + i * 0.04, duration: 0.5 }} />
                                </div>
                            </motion.div>
                        ))}
                    </div>
                </motion.div>
            </div>

            {/* ========== ROW 6: Endpoint Rankings + Top Critical + Quick Stats ========== */}
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
                <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.85 }}
                    className="border border-[#2D2D2D] rounded-[4px] p-6">
                    <h3 className="text-sm font-bold text-[#797979] mb-3 uppercase tracking-wider">Most Vulnerable Endpoints</h3>
                    <div className="space-y-2.5">
                        {endpoints.length > 0 ? endpoints.map((ep, i) => (
                            <motion.div key={ep.name} initial={{ opacity: 0, x: -10 }} animate={{ opacity: 1, x: 0 }} transition={{ delay: 0.9 + i * 0.05 }}
                                className="flex items-center justify-between px-3 py-2 rounded-[4px] bg-[#0a0a0a] border border-[#2D2D2D] hover:border-[#8b5cf6]/30 transition-colors duration-200">
                                <div className="flex items-center gap-2">
                                    <span className="text-[10px] font-bold text-[#797979] w-4">{i + 1}.</span>
                                    <code className="text-xs text-[#06b6d4] font-mono truncate max-w-[160px]">{ep.name}</code>
                                </div>
                                <span className="text-xs font-bold text-[#E7E7E7] bg-[#1A1A1A] px-2 py-0.5 rounded-[4px]">{ep.count}</span>
                            </motion.div>
                        )) : <div className="text-[#797979] text-sm text-center py-8">No endpoints</div>}
                    </div>
                </motion.div>

                <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.9 }}
                    className="border border-[#2D2D2D] rounded-[4px] p-6">
                    <h3 className="text-sm font-bold text-[#797979] mb-3 uppercase tracking-wider">Top Critical Findings</h3>
                    <div className="space-y-2">
                        {topFindings.length > 0 ? topFindings.map((f, i) => {
                            const color = f.severity === "CRITICAL" ? "red" : "orange";
                            return (
                                <motion.div key={i} initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ delay: 0.95 + i * 0.06 }}
                                    className={`px-3 py-2.5 rounded-[4px] border bg-[#0a0a0a] hover:bg-[#1A1A1A] transition-colors duration-200
                                        ${color === "red" ? "border-red-500/30" : "border-orange-500/30"}`}>
                                    <div className="flex items-center gap-2 mb-0.5">
                                        <span className={`w-1.5 h-1.5 rounded-full ${color === "red" ? "bg-red-500" : "bg-orange-500"}`} />
                                        <span className="text-xs font-bold text-[#E7E7E7] truncate">{f.title.length > 35 ? f.title.slice(0, 33) + "..." : f.title}</span>
                                    </div>
                                    <span className="text-[10px] text-[#797979]">{f.owaspId}  ·  {f.endpoint}</span>
                                </motion.div>
                            );
                        }) : <div className="text-[#797979] text-sm text-center py-8">No critical findings</div>}
                    </div>
                </motion.div>

                {/* Quick Stats Summary */}
                <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.95 }}
                    className="border border-[#2D2D2D] rounded-[4px] p-6">
                    <h3 className="text-sm font-bold text-[#797979] mb-4 uppercase tracking-wider">Analysis Summary</h3>
                    <div className="space-y-4">
                        {[
                            { label: "Total Findings", value: String(findings.length), color: "#E7E7E7" },
                            { label: "Unique Endpoints Tested", value: String(uniqueEndpoints), color: "#06b6d4" },
                            { label: "Security Checks Run", value: String(uniqueChecks), color: "#f59e0b" },
                            { label: "Avg Findings per Endpoint", value: avgFindingsPerEndpoint, color: "#8b5cf6" },
                            { label: "OWASP Categories Hit", value: String(owaspCompliance.filter(o => o.total > 0).length) + "/10", color: "#ef4444" },
                            { label: "OWASP Pass Rate", value: Math.round(owaspCompliance.filter(o => o.status === "secure").length / 10 * 100) + "%", color: "#22c55e" },
                            { label: "Critical + High", value: String(findings.filter(f => f.severity === "CRITICAL" || f.severity === "HIGH").length), color: "#f97316" },
                            { label: "Medium + Low + Info", value: String(findings.filter(f => f.severity === "MEDIUM" || f.severity === "LOW" || f.severity === "INFO").length), color: "#3b82f6" },
                        ].map(({ label, value, color }, i) => (
                            <motion.div key={label} initial={{ opacity: 0, x: 10 }} animate={{ opacity: 1, x: 0 }} transition={{ delay: 1 + i * 0.04 }}
                                className="flex justify-between items-center py-2 border-b border-[#2D2D2D] last:border-b-0">
                                <span className="text-xs text-[#797979] font-medium">{label}</span>
                                <span className="text-sm font-bold font-mono" style={{ color }}>{value}</span>
                            </motion.div>
                        ))}
                    </div>
                </motion.div>
            </div>
        </div>
    );
}
