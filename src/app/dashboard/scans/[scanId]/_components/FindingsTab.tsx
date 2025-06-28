"use client";
import { motion, AnimatePresence } from "framer-motion";
import { FindingResult, Evidence } from "@/types";
import { SEVERITY_COLORS } from "@/lib/constants";
import { useState } from "react";
import { FiSearch, FiGrid, FiList, FiChevronDown } from "react-icons/fi";

const FormattedText = ({ text, type }: { text: string; type: "remediation" | "description" }) => {
    const parts = text.split(/```(\w*)\n([\s\S]*?)```/);
    if (parts.length === 1) {
        return <div className={`text-sm leading-relaxed whitespace-pre-wrap ${type === "remediation" ? "text-green-300" : "text-[#E7E7E7]"}`}>{text}</div>;
    }

    const elements = [];
    for (let i = 0; i < parts.length; i++) {
        if (i % 3 === 0) {
            if (parts[i].trim()) {
                elements.push(<div key={i} className={`text-sm leading-relaxed whitespace-pre-wrap ${type === "remediation" ? "text-green-300" : "text-[#E7E7E7]"}`}>{parts[i]}</div>);
            }
        } else if (i % 3 === 1) {
            // Language hint (unused visually right now)
        } else if (i % 3 === 2) {
            elements.push(
                <div key={i} className="my-3 rounded-[6px] bg-[#000000] border border-[#2D2D2D] p-4 overflow-x-auto shadow-inner">
                    <pre className="text-[13px] font-mono text-[#86efac] leading-relaxed">{parts[i]}</pre>
                </div>
            );
        }
    }
    return <div className="space-y-2">{elements}</div>;
};

const EvidenceViewer = ({ evidence }: { evidence: Evidence }) => {
    const [activeTab, setActiveTab] = useState<"request" | "response">("request");

    // Attempt parse payload safely
    let reqBody = evidence.request.body;
    if (reqBody && typeof reqBody !== "string") {
        try {
            reqBody = JSON.stringify(reqBody, null, 2);
        } catch { /* empty */ }
    }

    let resBody = evidence.response.body;
    if (resBody && typeof resBody !== "string") {
        try {
            resBody = JSON.stringify(resBody, null, 2);
        } catch { /* empty */ }
    }

    return (
        <div className="rounded-[8px] bg-[#0F0F0F] border border-[#2D2D2D] overflow-hidden flex flex-col shadow-sm">
            <div className="flex bg-[#141414] border-b border-[#2D2D2D]">
                <button
                    onClick={() => setActiveTab("request")}
                    className={`flex-1 px-4 py-2.5 text-xs font-bold tracking-wider uppercase transition-colors ${activeTab === "request" ? "bg-[#1A1A1A] text-white border-b-2 border-[#8b5cf6]" : "text-[#797979] hover:text-[#E7E7E7] hover:bg-[#1A1A1A]"}`}>
                    Request
                </button>
                <div className="w-px bg-[#2D2D2D]"></div>
                <button
                    onClick={() => setActiveTab("response")}
                    className={`flex-1 px-4 py-2.5 text-xs font-bold tracking-wider uppercase transition-colors ${activeTab === "response" ? "bg-[#1A1A1A] text-white border-b-2 border-[#8b5cf6]" : "text-[#797979] hover:text-[#E7E7E7] hover:bg-[#1A1A1A]"}`}>
                    Response
                </button>
            </div>

            <div className="p-5 overflow-auto max-h-96">
                {activeTab === "request" && (
                    <div className="text-[13px] font-mono space-y-4">
                        <div className="flex gap-3 items-center border-b border-[#2D2D2D] pb-3">
                            <span className="text-[#3b82f6] font-extrabold text-sm">{evidence.request.method.toUpperCase()}</span>
                            <span className="text-[#E7E7E7] break-all">{evidence.request.url}</span>
                        </div>

                        {Object.keys(evidence.request.headers || {}).length > 0 && (
                            <div className="space-y-1">
                                {Object.entries(evidence.request.headers).map(([k, v]) => (
                                    <div key={k} className="flex gap-2 break-all">
                                        <span className="text-[#a1a1aa] whitespace-nowrap">{k}:</span>
                                        <span className="text-[#d4d4d8]">{v}</span>
                                    </div>
                                ))}
                            </div>
                        )}

                        {!!reqBody && (
                            <div className="pt-3 border-t border-[#2D2D2D]">
                                <pre className="text-[#f472b6] mt-2 whitespace-pre-wrap font-mono text-[13px]">{String(reqBody)}</pre>
                            </div>
                        )}

                        {evidence.payload && (
                            <div className="mt-4 p-3 bg-red-500/10 border border-red-500/20 rounded-[4px]">
                                <div className="text-xs text-red-400 font-bold uppercase mb-1">Injected Payload</div>
                                <code className="text-red-300 break-all">{evidence.payload}</code>
                            </div>
                        )}
                    </div>
                )}

                {activeTab === "response" && (
                    <div className="text-[13px] font-mono space-y-4">
                        <div className="flex gap-3 items-center border-b border-[#2D2D2D] pb-3">
                            <span className={`font-extrabold text-sm ${evidence.response.status >= 400 ? "text-red-400" : "text-green-400"}`}>
                                HTTP {evidence.response.status}
                            </span>
                            {evidence.response.responseTime !== undefined && (
                                <span className="text-[#797979]">({evidence.response.responseTime}ms)</span>
                            )}
                        </div>

                        {Object.keys(evidence.response.headers || {}).length > 0 && (
                            <div className="space-y-1">
                                {Object.entries(evidence.response.headers).map(([k, v]) => (
                                    <div key={k} className="flex gap-2 break-all">
                                        <span className="text-[#a1a1aa] whitespace-nowrap">{k}:</span>
                                        <span className="text-[#d4d4d8]">{v}</span>
                                    </div>
                                ))}
                            </div>
                        )}

                        {!!resBody && (
                            <div className="pt-3 border-t border-[#2D2D2D]">
                                <pre className="text-[#34d399] mt-2 whitespace-pre-wrap font-mono text-[13px] leading-relaxed">{String(resBody)}</pre>
                            </div>
                        )}
                    </div>
                )}
            </div>
        </div>
    );
};

type Props = {
    findings: FindingResult[];
    searchQuery: string;
    setSearchQuery: (q: string) => void;
    severityFilter: string | null;
    setSeverityFilter: (s: string | null) => void;
    viewMode: "cards" | "table";
    setViewMode: (m: "cards" | "table") => void;
};

export default function FindingsTab({ findings, searchQuery, setSearchQuery, severityFilter, setSeverityFilter, viewMode, setViewMode }: Props) {
    const [expandedId, setExpandedId] = useState<number | null>(null);

    const filtered = findings.filter(f => {
        if (severityFilter && f.severity !== severityFilter) return false;
        if (searchQuery) {
            const q = searchQuery.toLowerCase();
            return f.title.toLowerCase().includes(q) || f.description.toLowerCase().includes(q) || (f.endpoint || "").toLowerCase().includes(q);
        }
        return true;
    });

    const severities = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"] as const;

    return (
        <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ duration: 0.3 }}>
            {/* Toolbar */}
            <div className="flex flex-col sm:flex-row gap-3 mb-5">
                <div className="relative flex-1">
                    <span className="absolute left-3 top-1/2 -translate-y-1/2 text-[#797979]">
                        <FiSearch className="w-4 h-4" />
                    </span>
                    <input type="text" placeholder="Search findings…" value={searchQuery} onChange={e => setSearchQuery(e.target.value)}
                        className="w-full pl-10 pr-4 py-2.5 rounded-[4px] bg-[#0a0a0a] border border-[#2D2D2D] text-sm text-[#E7E7E7] placeholder:text-[#797979] focus:outline-none focus:border-[#8b5cf6]/50 focus:ring-1 focus:ring-[#8b5cf6]/20 transition-all duration-200" />
                </div>

                <div className="flex items-center gap-2 flex-wrap">
                    {severities.map(s => {
                        const count = findings.filter(f => f.severity === s).length;
                        if (count === 0) return null;
                        const active = severityFilter === s;
                        return (
                            <button key={s} onClick={() => setSeverityFilter(active ? null : s)}
                                className={`px-3 py-1.5 rounded-[4px] text-xs font-bold border transition-all duration-200
                                        ${active ? "bg-[#8b5cf6] border-[#8b5cf6] text-white" : "bg-[#1A1A1A] border-[#2D2D2D] text-[#797979] hover:text-[#E7E7E7] hover:border-[#8b5cf6]/50"}`}>
                                {s} ({count})
                            </button>
                        );
                    })}
                    <div className="flex rounded-[4px] border border-[#2D2D2D] overflow-hidden ml-2">
                        <button onClick={() => setViewMode("cards")} className={`px-3 py-1.5 text-xs font-semibold transition-colors flex items-center gap-1.5 ${viewMode === "cards" ? "bg-[#8b5cf6] text-white" : "bg-[#1A1A1A] text-[#797979]"}`}>
                            <FiGrid className="w-3.5 h-3.5" />
                        </button>
                        <button onClick={() => setViewMode("table")} className={`px-3 py-1.5 text-xs font-semibold transition-colors flex items-center gap-1.5 ${viewMode === "table" ? "bg-[#8b5cf6] text-white" : "bg-[#1A1A1A] text-[#797979]"}`}>
                            <FiList className="w-3.5 h-3.5" />
                        </button>
                    </div>
                </div>
            </div>

            {/* Results count */}
            <div className="text-xs text-[#797979] mb-3">Showing {filtered.length} of {findings.length} findings</div>

            {viewMode === "cards" ? (
                <div className="space-y-3">
                    <AnimatePresence mode="popLayout">
                        {filtered.map((f, i) => {
                            const color = SEVERITY_COLORS[f.severity as keyof typeof SEVERITY_COLORS] || "#6b7280";
                            const expanded = expandedId === i;
                            return (
                                <motion.div key={`${f.checkType}-${f.endpoint}-${i}`}
                                    layout initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: -12 }}
                                    transition={{ delay: Math.min(i * 0.03, 0.5), duration: 0.3 }}
                                    className="border border-[#2D2D2D] rounded-[4px] bg-[#0F0F0F] overflow-hidden hover:border-[#8b5cf6]/30 transition-all duration-200 group">
                                    <button onClick={() => setExpandedId(expanded ? null : i)} className="w-full text-left px-5 py-4 flex items-start gap-4 focus:outline-none">
                                        <div className="flex flex-col items-center gap-1 pt-0.5">
                                            <span className="w-3 h-3 rounded-full shadow-lg" style={{ background: color, boxShadow: `0 0 8px ${color}40` }} />
                                            <span className="text-[9px] font-bold uppercase tracking-widest" style={{ color }}>{f.severity}</span>
                                        </div>
                                        <div className="flex-1 min-w-0">
                                            <div className="flex items-center gap-2 flex-wrap mb-1">
                                                <span className="text-sm font-bold text-[#E7E7E7] group-hover:text-white transition-colors">{f.title}</span>
                                            </div>
                                            <div className="flex items-center gap-3 text-[11px] text-[#797979]">
                                                <span className="px-2 py-0.5 rounded bg-[#0a0a0a] text-[#E7E7E7] font-mono">{f.method} {f.endpoint}</span>
                                                <span className="px-1.5 py-0.5 rounded bg-[#1A1A1A] text-[#797979]">{f.checkType.replace(/_/g, " ")}</span>
                                            </div>
                                        </div>
                                        <motion.span animate={{ rotate: expanded ? 180 : 0 }} className="text-[#797979] text-xs mt-1">
                                            <FiChevronDown className="w-4 h-4" />
                                        </motion.span>
                                    </button>

                                    <AnimatePresence>
                                        {expanded && (
                                            <motion.div initial={{ height: 0, opacity: 0 }} animate={{ height: "auto", opacity: 1 }} exit={{ height: 0, opacity: 0 }} transition={{ duration: 0.25 }}
                                                className="border-t border-[#2D2D2D] overflow-hidden bg-[#0A0A0A]">
                                                <div className="px-5 py-6 space-y-8">

                                                    {/* Description */}
                                                    <div>
                                                        <h4 className="flex items-center gap-2 text-xs font-bold text-[#797979] uppercase tracking-widest mb-3 border-b border-[#2D2D2D] pb-3">
                                                            <FiList className="w-4 h-4 text-[#8b5cf6]" /> Description
                                                        </h4>
                                                        <FormattedText text={f.description} type="description" />
                                                    </div>

                                                    {/* Evidence */}
                                                    {f.evidence && (
                                                        <div>
                                                            <h4 className="flex items-center gap-2 text-xs font-bold text-[#797979] uppercase tracking-widest mb-3 border-b border-[#2D2D2D] pb-3">
                                                                <FiSearch className="w-4 h-4 text-[#8b5cf6]" /> Evidence & Probes
                                                            </h4>
                                                            {f.evidence.description && (
                                                                <p className="text-sm text-[#a1a1aa] mb-3 italic">
                                                                    {f.evidence.description}
                                                                </p>
                                                            )}
                                                            <EvidenceViewer evidence={f.evidence} />
                                                        </div>
                                                    )}

                                                    {/* Remediation */}
                                                    {f.remediation && (
                                                        <div>
                                                            <h4 className="flex items-center gap-2 text-xs font-bold text-[#797979] uppercase tracking-widest mb-3 border-b border-[#2D2D2D] pb-3">
                                                                Remediation Guidance
                                                            </h4>
                                                            <div className="rounded-[8px] bg-[#0d1510] border border-[#22c55e]/30 px-5 pt-5 pb-3 shadow-sm">
                                                                <FormattedText text={f.remediation} type="remediation" />
                                                            </div>
                                                        </div>
                                                    )}

                                                    {/* Metadata Footer */}
                                                    <div className="pt-5 mt-2 border-t border-[#2D2D2D] flex flex-wrap gap-4 text-[11px] text-[#797979]">
                                                        <span className="flex gap-1.5 items-center bg-[#141414] px-3 py-1.5 rounded-[4px] border border-[#2D2D2D]">
                                                            OWASP Category: <strong className="text-[#E7E7E7]">{f.owaspMapping}</strong>
                                                        </span>
                                                        <span className="flex gap-1.5 items-center bg-[#141414] px-3 py-1.5 rounded-[4px] border border-[#2D2D2D]">
                                                            OWASP ID: <strong className="text-[#E7E7E7]">{f.owaspId}</strong>
                                                        </span>
                                                    </div>

                                                </div>
                                            </motion.div>
                                        )}
                                    </AnimatePresence>
                                </motion.div>
                            );
                        })}
                    </AnimatePresence>
                </div>
            ) : (
                <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="border border-[#2D2D2D] rounded-[4px] overflow-hidden bg-[#0a0a0a]">
                    <div className="overflow-x-auto">
                        <table className="w-full text-sm">
                            <thead className="bg-[#141414]">
                                <tr className="border-b border-[#2D2D2D]">
                                    <th className="px-5 py-4 text-left text-xs font-bold text-[#797979] uppercase tracking-wider">Severity</th>
                                    <th className="px-5 py-4 text-left text-xs font-bold text-[#797979] uppercase tracking-wider">Title</th>
                                    <th className="px-5 py-4 text-left text-xs font-bold text-[#797979] uppercase tracking-wider hidden md:table-cell">Endpoint</th>
                                    <th className="px-5 py-4 text-left text-xs font-bold text-[#797979] uppercase tracking-wider hidden lg:table-cell">OWASP</th>
                                    <th className="px-5 py-4 text-left text-xs font-bold text-[#797979] uppercase tracking-wider hidden lg:table-cell">Type</th>
                                </tr>
                            </thead>
                            <tbody>
                                {filtered.map((f, i) => {
                                    const color = SEVERITY_COLORS[f.severity as keyof typeof SEVERITY_COLORS] || "#6b7280";
                                    return (
                                        <motion.tr key={i} initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ delay: Math.min(i * 0.02, 0.5) }}
                                            className="border-b border-[#2D2D2D] hover:bg-[#1A1A1A]/80 transition-colors cursor-pointer" onClick={() => setExpandedId(expandedId === i ? null : i)}>
                                            <td className="px-5 py-3.5">
                                                <span className="inline-flex items-center gap-2 text-[11px] font-bold uppercase tracking-wider" style={{ color }}>
                                                    <span className="w-2 h-2 rounded-full" style={{ background: color, boxShadow: `0 0 6px ${color}80` }} />{f.severity}
                                                </span>
                                            </td>
                                            <td className="px-5 py-3.5 text-[#E7E7E7] font-medium text-[13px]">{f.title}</td>
                                            <td className="px-5 py-3.5 hidden md:table-cell"><code className="text-[12px] bg-[#1a1a1a] px-2 py-0.5 rounded text-[#06b6d4] border border-[#2d2d2d] font-mono">{f.method} {f.endpoint}</code></td>
                                            <td className="px-5 py-3.5 text-[#797979] text-xs hidden lg:table-cell">{f.owaspId}</td>
                                            <td className="px-5 py-3.5 text-[#797979] text-xs hidden lg:table-cell">{f.checkType.replace(/_/g, " ")}</td>
                                        </motion.tr>
                                    );
                                })}
                            </tbody>
                        </table>
                    </div>
                </motion.div>
            )}

            {filtered.length === 0 && (
                <div className="text-center py-20 text-[#797979]">
                    <FiSearch className="mx-auto w-12 h-12 mb-4 opacity-30" />
                    <div className="text-sm font-medium">No findings match your filters</div>
                    <button onClick={() => { setSearchQuery(""); setSeverityFilter(null); }} className="mt-4 text-[#8b5cf6] text-xs hover:underline">Clear Filters</button>
                </div>
            )}
        </motion.div>
    );
}
