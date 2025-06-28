"use client";
import { motion } from "framer-motion";
import { FindingResult } from "@/types";
import { OWASP_API_TOP_10 } from "@/lib/constants";
import { RadarChart, Radar, PolarGrid, PolarAngleAxis, PolarRadiusAxis, ResponsiveContainer } from "recharts";
import { FiCheck, FiAlertTriangle, FiX } from "react-icons/fi";

export default function OwaspTab({ findings }: { findings: FindingResult[] }) {
    const owaspArr = Object.values(OWASP_API_TOP_10);
    const owaspData = owaspArr.map(o => {
        const f = findings.filter(fi => fi.owaspId === o.id);
        return { ...o, findings: f.length, status: f.length === 0 ? "pass" as const : f.some(fi => fi.severity === "CRITICAL" || fi.severity === "HIGH") ? "fail" as const : "warning" as const };
    });

    const radarData = owaspData.map(o => ({
        name: o.id, findings: o.findings,
        fullMark: Math.max(5, ...owaspData.map(x => x.findings)),
    }));

    const passCount = owaspData.filter(o => o.status === "pass").length;
    const failCount = owaspData.filter(o => o.status === "fail").length;
    const warnCount = owaspData.filter(o => o.status === "warning").length;

    return (
        <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ duration: 0.3 }}>
            {/* Summary bar */}
            <div className="grid grid-cols-3 gap-3 mb-6">
                {[
                    { label: "Passed", count: passCount, icon: <FiCheck className="w-5 h-5" />, color: "green" },
                    { label: "Warnings", count: warnCount, icon: <FiAlertTriangle className="w-5 h-5" />, color: "amber" },
                    { label: "Failed", count: failCount, icon: <FiX className="w-5 h-5" />, color: "red" },
                ].map((s, i) => (
                    <motion.div key={s.label} initial={{ opacity: 0, y: 15 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: i * 0.1 }}
                        className={`border rounded-[4px] p-4 text-center
                            ${s.color === "green" ? "border-green-500/30 bg-green-500/5" : ""}
                            ${s.color === "amber" ? "border-yellow-500/30 bg-yellow-500/5" : ""}
                            ${s.color === "red" ? "border-red-500/30 bg-red-500/5" : ""}`}>
                        <div className="mb-1" style={{ color: s.color === "green" ? "#22c55e" : s.color === "amber" ? "#eab308" : "#ef4444" }}>{s.icon}</div>
                        <div className="text-2xl font-black text-[#E7E7E7]">{s.count}</div>
                        <div className="text-xs text-[#797979] font-medium">{s.label}</div>
                    </motion.div>
                ))}
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                {/* Radar */}
                <motion.div initial={{ opacity: 0, x: -20 }} animate={{ opacity: 1, x: 0 }} transition={{ delay: 0.3 }}
                    className="border border-[#2D2D2D] rounded-[4px] p-6">
                    <h3 className="text-sm font-bold text-[#797979] mb-3 uppercase tracking-wider">OWASP Coverage Radar</h3>
                    <ResponsiveContainer width="100%" height={300}>
                        <RadarChart data={radarData}>
                            <PolarGrid stroke="#2D2D2D" />
                            <PolarAngleAxis dataKey="name" tick={{ fill: "#E7E7E7", fontSize: 10 }} />
                            <PolarRadiusAxis tick={{ fill: "#797979", fontSize: 9 }} />
                            <Radar dataKey="findings" stroke="#8b5cf6" fill="#8b5cf6" fillOpacity={0.35} animationDuration={1500} />
                        </RadarChart>
                    </ResponsiveContainer>
                </motion.div>

                {/* Detail list */}
                <motion.div initial={{ opacity: 0, x: 20 }} animate={{ opacity: 1, x: 0 }} transition={{ delay: 0.4 }}
                    className="border border-[#2D2D2D] rounded-[4px] p-6">
                    <h3 className="text-sm font-bold text-[#797979] mb-3 uppercase tracking-wider">Coverage Details</h3>
                    <div className="space-y-2">
                        {owaspData.map((o, i) => (
                            <motion.div key={o.id} initial={{ opacity: 0, x: 10 }} animate={{ opacity: 1, x: 0 }} transition={{ delay: 0.5 + i * 0.05 }}
                                className={`flex items-center justify-between px-4 py-3 rounded-[4px] border transition-all duration-200 hover:bg-[#1A1A1A]/50
                                    ${o.status === "pass" ? "border-green-500/20 bg-green-500/5" : ""}
                                    ${o.status === "warning" ? "border-yellow-500/20 bg-yellow-500/5" : ""}
                                    ${o.status === "fail" ? "border-red-500/20 bg-red-500/5" : ""}`}>
                                <div className="flex items-center gap-3 min-w-0">
                                    <span className="text-xs font-mono font-bold text-[#8b5cf6] shrink-0">{o.id}</span>
                                    <span className="text-xs text-[#E7E7E7] truncate">{o.name}</span>
                                </div>
                                <div className="flex items-center gap-2 shrink-0">
                                    <span className="text-xs font-mono text-[#797979]">{o.findings}</span>
                                    <span className={`px-2 py-0.5 rounded-[4px] text-[10px] font-bold uppercase tracking-wider
                                        ${o.status === "pass" ? "bg-green-500/15 text-green-400" : ""}
                                        ${o.status === "warning" ? "bg-yellow-500/15 text-yellow-400" : ""}
                                        ${o.status === "fail" ? "bg-red-500/15 text-red-400" : ""}`}>
                                        {o.status}
                                    </span>
                                </div>
                            </motion.div>
                        ))}
                    </div>
                </motion.div>
            </div>
        </motion.div>
    );
}
