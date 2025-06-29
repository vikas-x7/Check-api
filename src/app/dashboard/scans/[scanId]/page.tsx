"use client";

import { useQuery, useMutation } from "@tanstack/react-query";
import { useParams, useRouter } from "next/navigation";
import api from "@/lib/axios";
import { jsPDF } from "jspdf";
import autoTable from "jspdf-autotable";
import { useState } from "react";
import { FindingResult } from "@/types";
import { motion, AnimatePresence } from "framer-motion";
import Link from "next/link";
import { FiArrowLeft, FiDownload, FiFileText, FiRefreshCw } from "react-icons/fi";


import StatCards from "./_components/StatCards";
import OverviewTab from "./_components/OverviewTab";
import FindingsTab from "./_components/FindingsTab";
import OwaspTab from "./_components/OwaspTab";

type ScanRecord = {
    id: string;
    targetUrl: string;
    status: "PENDING" | "RUNNING" | "COMPLETED" | "FAILED";
    progress?: number;
    intensity?: string;
    openApiSpec?: object;
    authConfig?: { type: string; value?: string; headerName?: string };
    findings?: FindingResult[];
    startedAt?: string;
    completedAt?: string;
};

function calcRiskScore(findings: FindingResult[]) {
    const w = { CRITICAL: 10, HIGH: 7, MEDIUM: 4, LOW: 2, INFO: 0.5 };
    return Math.min(100, Math.round(findings.reduce((a, f) => a + (w[f.severity as keyof typeof w] || 0), 0)));
}

function riskGrade(score: number) {
    if (score >= 80) return { grade: "F", color: "#ef4444", label: "Critical Risk" };
    if (score >= 60) return { grade: "D", color: "#f97316", label: "High Risk" };
    if (score >= 40) return { grade: "C", color: "#eab308", label: "Moderate Risk" };
    if (score >= 20) return { grade: "B", color: "#3b82f6", label: "Low Risk" };
    return { grade: "A", color: "#10b981", label: "Secure" };
}

const TABS = [
    { id: "overview" as const, label: "Overview" },
    { id: "findings" as const, label: "Findings" },
    { id: "owasp" as const, label: "OWASP" },
    { id: "details" as const, label: "Details" },
] as const;

type TabId = typeof TABS[number]["id"];

function ScanResultSkeleton() {
    return (
        <div className="px-5 py-3 space-y-6 animate-pulse">
            <div className="flex items-center justify-between mb-6">
                <div className="flex items-center gap-4">
                    <div className="w-9 h-9 bg-[#1A1A1A] rounded-[4px]"></div>
                    <div>
                        <div className="flex items-center gap-3 mb-2">
                            <div className="h-7 w-32 bg-[#1A1A1A] rounded-[4px]"></div>
                            <div className="h-5 w-20 bg-[#1A1A1A] rounded-[4px]"></div>
                        </div>
                        <div className="h-3 w-48 bg-[#1A1A1A] rounded-[4px]"></div>
                    </div>
                </div>
                <div className="flex items-center gap-2">
                    <div className="h-9 w-20 bg-[#1A1A1A] rounded-[4px]"></div>
                    <div className="h-9 w-24 bg-[#1A1A1A] rounded-[4px]"></div>
                    <div className="h-9 w-16 bg-[#1A1A1A] rounded-[4px]"></div>
                </div>
            </div>
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                {[...Array(4)].map((_, i) => (
                    <div key={i} className="rounded-[4px] border border-[#2D2D2D] bg-[#0a0a0a] p-4">
                        <div className="h-8 w-8 bg-[#1A1A1A] rounded-[4px] mb-3"></div>
                        <div className="h-6 w-12 bg-[#1A1A1A] rounded-[4px] mb-2"></div>
                        <div className="h-3 w-16 bg-[#1A1A1A] rounded-[4px]"></div>
                    </div>
                ))}
            </div>
            <div className="flex items-center gap-1 p-1 rounded-[4px] bg-[#0a0a0a] border border-[#2D2D2D] mb-6">
                {[...Array(4)].map((_, i) => (
                    <div key={i} className="h-9 w-24 bg-[#1A1A1A] rounded-[4px]"></div>
                ))}
            </div>
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
                <div className="lg:col-span-2 h-[300px] rounded-[4px] border border-[#2D2D2D] bg-[#0a0a0a] p-6">
                    <div className="h-4 w-48 bg-[#1A1A1A] rounded-[4px] mb-2"></div>
                    <div className="h-3 w-64 bg-[#1A1A1A] rounded-[4px] mb-6"></div>
                    <div className="h-[220px] w-full bg-[#1A1A1A] rounded-[4px]"></div>
                </div>
                <div className="h-[300px] rounded-[4px] border border-[#2D2D2D] bg-[#0a0a0a] p-6">
                    <div className="h-4 w-40 bg-[#1A1A1A] rounded-[4px] mb-2"></div>
                    <div className="h-3 w-32 bg-[#1A1A1A] rounded-[4px] mb-6"></div>
                    <div className="w-32 h-32 bg-[#1A1A1A] rounded-full mx-auto"></div>
                </div>
            </div>
        </div>
    );
}

export default function ScanResultsPage() {
    const params = useParams();
    const router = useRouter();
    const scanId = params.scanId as string;

    const [activeTab, setActiveTab] = useState<TabId>("overview");
    const [severityFilter, setSeverityFilter] = useState<string | null>(null);
    const [searchQuery, setSearchQuery] = useState("");
    const [viewMode, setViewMode] = useState<"cards" | "table">("cards");

    const { data: scan, isLoading } = useQuery<ScanRecord>({
        queryKey: ["scan", scanId],
        queryFn: async () => { const res = await api.get(`/scans/${scanId}`); return res.data; },
        refetchInterval: (query) => {
            const s = query.state.data as ScanRecord | undefined;
            return s?.status === "RUNNING" || s?.status === "PENDING" ? 3000 : false;
        },
    });

    const reportMutation = useMutation({
        mutationFn: async () => { const res = await api.post("/reports", { scanId, format: "JSON" }); return res.data; },
    });

    const findings = scan?.findings || [];
    const riskScore = calcRiskScore(findings);
    const grade = riskGrade(riskScore);

    const counts = {
        critical: findings.filter(f => f.severity === "CRITICAL").length,
        high: findings.filter(f => f.severity === "HIGH").length,
        medium: findings.filter(f => f.severity === "MEDIUM").length,
        low: findings.filter(f => f.severity === "LOW").length,
        info: findings.filter(f => f.severity === "INFO").length,
        total: findings.length,
    };

    const duration = (() => {
        if (!scan?.startedAt) return "—";
        const end = scan.completedAt ? new Date(scan.completedAt) : new Date();
        const ms = end.getTime() - new Date(scan.startedAt).getTime();
        return ms > 60000 ? `${(ms / 60000).toFixed(1)}m` : `${(ms / 1000).toFixed(1)}s`;
    })();

    const exportPDF = () => {
        const doc = new jsPDF();
        doc.setFillColor(15, 23, 42);
        doc.rect(0, 0, 210, 40, "F");
        doc.setTextColor(99, 102, 241);
        doc.setFontSize(20);
        doc.setFont("helvetica", "bold");
        doc.text("SecuriScan Security Report", 14, 20);
        doc.setTextColor(148, 163, 184);
        doc.setFontSize(9);
        doc.text(`Generated: ${new Date().toLocaleString()}`, 14, 28);
        doc.text(`Scan ID: ${scanId}`, 14, 34);

        autoTable(doc, {
            startY: 48,
            head: [["Target", "Status", "Intensity", "Duration", "Risk Grade", "Findings"]],
            body: [[scan!.targetUrl, scan!.status, scan!.intensity || "—", duration, `${grade.grade} (${riskScore}/100)`, String(findings.length)]],
            theme: "grid",
            headStyles: { fillColor: [99, 102, 241], textColor: 255, fontStyle: "bold", fontSize: 9 },
            bodyStyles: { fontSize: 8 },
        });

        const lastY1 = (doc as unknown as { lastAutoTable: { finalY: number } }).lastAutoTable.finalY + 8;
        autoTable(doc, {
            startY: lastY1,
            head: [["Severity", "Count", "Percentage"]],
            body: (["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"] as const).map(s => {
                const c = counts[s.toLowerCase() as keyof typeof counts];
                return [s, String(c), `${findings.length > 0 ? ((c / findings.length) * 100).toFixed(0) : 0}%`];
            }),
            theme: "grid",
            headStyles: { fillColor: [30, 41, 59], textColor: 255, fontSize: 9 },
            bodyStyles: { fontSize: 8 },
        });

        const lastY2 = (doc as unknown as { lastAutoTable: { finalY: number } }).lastAutoTable.finalY + 8;
        autoTable(doc, {
            startY: lastY2,
            head: [["#", "Severity", "Title", "OWASP", "Endpoint"]],
            body: findings.map((f, i) => [String(i + 1), f.severity, f.title, f.owaspId, f.endpoint || "—"]),
            theme: "striped",
            headStyles: { fillColor: [30, 41, 59], textColor: 255, fontSize: 8 },
            bodyStyles: { fontSize: 7 },
            columnStyles: { 0: { cellWidth: 10 }, 1: { cellWidth: 18 }, 4: { cellWidth: 35 } },
        });

        findings.forEach((f, i) => {
            doc.addPage();
            doc.setFontSize(12); doc.setFont("helvetica", "bold"); doc.setTextColor(99, 102, 241);
            doc.text(`Finding ${i + 1}: ${f.title}`, 14, 20);
            doc.setFontSize(8); doc.setTextColor(100);
            doc.text(`Severity: ${f.severity} | OWASP: ${f.owaspId} | Endpoint: ${f.endpoint || "—"}`, 14, 28);
            doc.setFontSize(9); doc.setTextColor(50);
            const desc = doc.splitTextToSize(f.description, 180);
            doc.text(desc, 14, 36);
            const afterDesc = 36 + desc.length * 4 + 6;
            doc.setFont("helvetica", "bold"); doc.setTextColor(16, 185, 129);
            doc.text("Remediation:", 14, afterDesc);
            doc.setFont("helvetica", "normal"); doc.setTextColor(50);
            const rem = doc.splitTextToSize(f.remediation, 180);
            doc.text(rem, 14, afterDesc + 6);
        });

        const pageCount = doc.getNumberOfPages();
        for (let i = 1; i <= pageCount; i++) {
            doc.setPage(i);
            doc.setFontSize(7); doc.setTextColor(150);
            doc.text(`Page ${i} of ${pageCount} — SecuriScan Confidential`, 14, 290);
        }

        doc.save(`securiscan-report-${scanId.slice(0, 8)}.pdf`);
    };

    const isRunning = scan?.status === "RUNNING" || scan?.status === "PENDING";

    if (isLoading) {
        return <ScanResultSkeleton />;
    }

    if (isRunning && scan) {
        return (
            <div className="px-5 py-3">
                <div className="flex items-center gap-4 mb-8">
                    <Link href="/dashboard/result" className="w-9 h-9 rounded-[4px] bg-[#1A1A1A] border border-[#2D2D2D] flex items-center justify-center text-[#797979] hover:text-[#E7E7E7] hover:bg-[#252525] transition-all">
                        <FiArrowLeft className="w-4 h-4" />
                    </Link>
                    <div>
                        <h1 className="text-2xl font-serif -tracking-[1px] text-[#E7E7E7]">Scan In Progress</h1>
                        <code className="text-[12px] text-[#797979] font-mono">{scan.targetUrl}</code>
                    </div>
                </div>
                <div className="max-w-lg mx-auto text-center py-16">
                    <div className="w-20 h-20 rounded-full border-4 border-[#2D2D2D] border-t-[#8b5cf6] animate-spin mx-auto mb-6" />
                    <h2 className="text-xl font-serif -tracking-[1px] text-[#E7E7E7] mb-2">
                        {scan.status === "PENDING" ? "Preparing Scan…" : "Scanning Target…"}
                    </h2>
                    <p className="text-sm text-[#797979] mb-6">
                        Security checks are running against your API endpoints. Results will appear automatically.
                    </p>
                    {scan.progress != null && (
                        <div className="mb-4">
                            <div className="flex justify-between text-[11px] text-[#797979] mb-1.5">
                                <span>Progress</span>
                                <span className="font-mono">{scan.progress}%</span>
                            </div>
                            <div className="h-2 bg-[#1A1A1A] rounded-full overflow-hidden border border-[#2D2D2D]">
                                <div
                                    className="h-full bg-[#8b5cf6] rounded-full transition-all duration-500"
                                    style={{ width: `${scan.progress}%` }}
                                />
                            </div>
                        </div>
                    )}
                    <span className="inline-flex items-center gap-2 px-3 py-1.5 rounded-[4px] text-[11px] font-semibold uppercase tracking-wider bg-yellow-500/15 text-yellow-400 border border-yellow-500/30">
                        <span className="w-1.5 h-1.5 rounded-full bg-yellow-400 animate-pulse" />
                        {scan.status}
                    </span>
                </div>
            </div>
        );
    }

    if (!scan) {
        return (
            <div className="flex items-center justify-center min-h-screen">
                <div className="text-center">
                    <div className="text-4xl mb-3"></div>
                    <p className="text-[#797979] text-sm">Scan not found</p>
                    <Link href="/dashboard" className="mt-4 inline-flex items-center gap-2 px-4 py-2 rounded-[4px] bg-[#1A1A1A] border border-[#2D2D2D] text-[#E7E7E7] text-sm no-underline hover:bg-[#252525] transition-all">
                        <FiArrowLeft /> Back to Dashboard
                    </Link>
                </div>
            </div>
        );
    }


    const getStatusStyle = (status: string) => {
        switch (status) {
            case "COMPLETED":
                return "bg-green-500/15 text-green-400 border border-green-500/30";
            case "RUNNING":
            case "PENDING":
                return "bg-yellow-500/15 text-yellow-400 border border-yellow-500/30";
            case "FAILED":
                return "bg-red-500/15 text-red-400 border border-red-500/30";
            default:
                return "bg-gray-500/15 text-gray-400 border border-gray-500/30";
        }
    };

    return (
        <div className="px-5 py-3">
            {/* Header */}
            <div className="flex items-center justify-between mb-6">
                <div className="flex items-center gap-4">
                    <Link href="/dashboard" className="w-9 h-9 rounded-[4px] bg-[#1A1A1A] border border-[#2D2D2D] flex items-center justify-center text-[#797979] hover:text-[#E7E7E7] hover:bg-[#252525] transition-all">
                        <FiArrowLeft className="w-4 h-4" />
                    </Link>
                    <div>
                        <div className="flex items-center gap-3">
                            <h1 className="text-2xl font-serif -tracking-[1px] text-[#E7E7E7]">
                                Scan Results
                            </h1>
                            <span className={`inline-flex items-center px-2.5 py-0.5 rounded-[4px] text-[11px] font-semibold uppercase tracking-wider ${getStatusStyle(scan.status)}`}>
                                {isRunning && <span className="w-1.5 h-1.5 rounded-full bg-yellow-400 animate-pulse mr-1.5" />}
                                {scan.status}
                            </span>
                            {scan.intensity && (
                                <span className="px-2.5 py-0.5 rounded-[4px] text-[10px] font-bold bg-[#8b5cf6]/15 text-[#8b5cf6] border border-[#8b5cf6]/30 uppercase tracking-widest">
                                    {scan.intensity}
                                </span>
                            )}
                        </div>
                        <div className="flex items-center gap-4 text-[12px] text-[#797979] mt-1">
                            <code className="px-2 py-0.5 rounded bg-[#0a0a0a] text-[#E7E7E7] font-mono text-[11px]">{scan.targetUrl}</code>
                            <span> {duration}</span>
                        </div>
                    </div>
                </div>

                <div className="flex items-center gap-2">
                    <button
                        onClick={() => router.push(`/scanner/new?rescanFrom=${scan.id}&targetUrl=${encodeURIComponent(scan.targetUrl)}&intensity=${scan.intensity || "MEDIUM"}`)}
                        className="px-4 py-2 rounded-[4px] text-[12px] font-semibold bg-[#1A1A1A] border border-[#2D2D2D] hover:bg-[#252525] text-[#E7E7E7] transition-all flex items-center gap-2"
                    >
                        <FiRefreshCw className="w-3.5 h-3.5" />
                        Rescan
                    </button>
                    <button
                        onClick={exportPDF}
                        disabled={findings.length === 0}
                        className="px-4 py-2 rounded-[4px] text-[12px] font-semibold bg-[#8b5cf6] hover:bg-[#7c3aed] disabled:opacity-40 disabled:cursor-not-allowed text-white transition-all flex items-center gap-2"
                    >
                        <FiDownload className="w-3.5 h-3.5" />
                        Export PDF
                    </button>
                    <button
                        onClick={() => reportMutation.mutate()}
                        disabled={reportMutation.isPending || findings.length === 0}
                        className="px-4 py-2 rounded-[4px] text-[12px] font-semibold bg-[#1A1A1A] border border-[#2D2D2D] hover:bg-[#252525] text-[#E7E7E7] transition-all flex items-center gap-2"
                    >
                        <FiFileText className="w-3.5 h-3.5" />
                        JSON
                    </button>
                </div>
            </div>

            {/* Stat Cards */}
            <div className="mb-6">
                <StatCards counts={counts} riskScore={riskScore} grade={grade} />
            </div>

            {/* Tabs */}
            <div className="flex items-center gap-1 p-1 rounded-[4px] bg-[#0a0a0a] border border-[#2D2D2D] mb-6 overflow-x-auto">
                {TABS.map(tab => (
                    <button
                        key={tab.id}
                        onClick={() => setActiveTab(tab.id)}
                        className={`relative px-5 py-2.5 rounded-[4px] text-sm font-semibold transition-all duration-200 whitespace-nowrap
                                    ${activeTab === tab.id ? "bg-[#8b5cf6] text-white" : "text-[#797979] hover:text-[#E7E7E7] hover:bg-[#1A1A1A]"}`}
                    >
                        {tab.label}
                        {tab.id === "findings" && findings.length > 0 && (
                            <span className={`ml-2 text-[10px] px-1.5 py-0.5 rounded-full font-bold ${activeTab === "findings" ? "bg-white/20" : "bg-[#2D2D2D]"}`}>
                                {findings.length}
                            </span>
                        )}
                    </button>
                ))}
            </div>

            {/* Tab Content */}
            <AnimatePresence mode="wait">
                {activeTab === "overview" && (
                    <motion.div key="overview" initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: -10 }} transition={{ duration: 0.2 }}>
                        <OverviewTab findings={findings} riskScore={riskScore} grade={grade} />
                    </motion.div>
                )}
                {activeTab === "findings" && (
                    <motion.div key="findings" initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: -10 }} transition={{ duration: 0.2 }}>
                        <FindingsTab findings={findings} searchQuery={searchQuery} setSearchQuery={setSearchQuery}
                            severityFilter={severityFilter} setSeverityFilter={setSeverityFilter}
                            viewMode={viewMode} setViewMode={setViewMode} />
                    </motion.div>
                )}
                {activeTab === "owasp" && (
                    <motion.div key="owasp" initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: -10 }} transition={{ duration: 0.2 }}>
                        <OwaspTab findings={findings} />
                    </motion.div>
                )}
                {activeTab === "details" && (
                    <motion.div key="details" initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: -10 }} transition={{ duration: 0.2 }}>
                        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                            <div className="border border-[#2D2D2D] rounded-[4px] p-5">
                                <h3 className="text-sm font-bold text-[#797979] mb-4 uppercase tracking-wider">Scan Configuration</h3>
                                <div className="space-y-3">
                                    {[
                                        { label: "Scan ID", value: scan.id },
                                        { label: "Target URL", value: scan.targetUrl },
                                        { label: "Status", value: scan.status },
                                        { label: "Intensity", value: scan.intensity || "—" },
                                        { label: "Started", value: scan.startedAt ? new Date(scan.startedAt).toLocaleString() : "—" },
                                        { label: "Completed", value: scan.completedAt ? new Date(scan.completedAt).toLocaleString() : "—" },
                                        { label: "Duration", value: duration },
                                        { label: "Total Findings", value: String(findings.length) },
                                    ].map(({ label, value }) => (
                                        <div key={label} className="flex justify-between items-center py-2 border-b border-[#2D2D2D]">
                                            <span className="text-xs text-[#797979] font-medium">{label}</span>
                                            <span className="text-xs text-[#E7E7E7] font-mono">{value}</span>
                                        </div>
                                    ))}
                                </div>
                            </div>

                            <div className="border border-[#2D2D2D] rounded-[4px] p-5">
                                <h3 className="text-sm font-bold text-[#797979] mb-4 uppercase tracking-wider">Authentication Config</h3>
                                {scan.authConfig ? (
                                    <div className="rounded-[4px] bg-[#0a0a0a] border border-[#2D2D2D] p-4">
                                        <pre className="text-xs text-[#8b5cf6] font-mono whitespace-pre-wrap">{JSON.stringify(scan.authConfig, null, 2)}</pre>
                                    </div>
                                ) : (
                                    <div className="text-center py-8 text-[#797979] text-sm">No authentication configured</div>
                                )}

                                <h3 className="text-sm font-bold text-[#797979] mt-6 mb-4 uppercase tracking-wider">Scan Metadata</h3>
                                <div className="grid grid-cols-2 gap-3">
                                    <div className="rounded-[4px] bg-[#1A1A1A] p-3 text-center">
                                        <div className="text-lg font-black text-[#E7E7E7]">{findings.length}</div>
                                        <div className="text-[10px] text-[#797979]">Findings</div>
                                    </div>
                                    <div className="rounded-[4px] bg-[#1A1A1A] p-3 text-center">
                                        <div className="text-lg font-black" style={{ color: grade.color }}>{grade.grade}</div>
                                        <div className="text-[10px] text-[#797979]">Risk Grade</div>
                                    </div>
                                    <div className="rounded-[4px] bg-[#1A1A1A] p-3 text-center">
                                        <div className="text-lg font-black text-[#06b6d4]">{new Set(findings.map(f => f.endpoint)).size}</div>
                                        <div className="text-[10px] text-[#797979]">Endpoints Hit</div>
                                    </div>
                                    <div className="rounded-[4px] bg-[#1A1A1A] p-3 text-center">
                                        <div className="text-lg font-black text-[#f59e0b]">{new Set(findings.map(f => f.checkType)).size}</div>
                                        <div className="text-[10px] text-[#797979]">Check Types</div>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </motion.div>
                )}
            </AnimatePresence>
        </div>
    );
}
