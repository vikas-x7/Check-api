"use client";

import { useState } from "react";
import { useParams } from "next/navigation";
import Link from "next/link";
import { motion, AnimatePresence } from "framer-motion";
import { FiArrowLeft, FiBookOpen, FiShield, FiAlertTriangle, FiCode, FiCheckCircle } from "react-icons/fi";
import { knowledgeItems } from "@/app/knowledge/data";

const TABS = [
    { id: "overview" as const, label: "Overview" },
    { id: "prevention" as const, label: "Prevention" },
    { id: "code" as const, label: "Code Examples" },
] as const;

type TabId = typeof TABS[number]["id"];

export default function KnowledgeDetailPage() {
    const params = useParams();
    const id = params.id as string;
    const [activeTab, setActiveTab] = useState<TabId>("overview");
    const [showSecure, setShowSecure] = useState(false);

    const item = knowledgeItems.find(v => v.id === id) || null;

    if (!item) {
        return (
            <div className="flex flex-col items-center justify-center min-h-screen bg-[#0F0F0F]">
                <div className="text-center">
                    <FiAlertTriangle className="w-12 h-12 text-[#797979] mx-auto mb-4" />
                    <p className="text-[#797979] text-sm mb-4">Knowledge item not found</p>
                    <Link href="/dashboard/knowledge" className="inline-flex items-center gap-2 px-4 py-2 rounded-[4px] bg-[#1A1A1A] border border-[#2D2D2D] text-[#E7E7E7] text-sm no-underline hover:bg-[#252525] transition-all">
                        <FiArrowLeft /> Back to Knowledge Base
                    </Link>
                </div>
            </div>
        );
    }

    const hasCodeExamples = item.vulnerableCode && item.secureCode;
    const hasHowToPrevent = item.howToPrevent && item.howToPrevent.length > 0;
    const hasBestPractices = item.bestPractices && item.bestPractices.length > 0;

    const getSeverityStyle = (severity?: string) => {
        switch (severity) {
            case "Critical":
                return "bg-red-500/15 text-red-400 border-red-500/30";
            case "High":
                return "bg-orange-500/15 text-orange-400 border-orange-500/30";
            case "Medium":
                return "bg-yellow-500/15 text-yellow-400 border-yellow-500/30";
            case "Low":
                return "bg-blue-500/15 text-blue-400 border-blue-500/30";
            default:
                return "bg-gray-500/15 text-gray-400 border-gray-500/30";
        }
    };

    return (
        <div className="px-5 py-3">
            {/* Header */}
            <div className="flex items-center justify-between mb-6">
                <div className="flex items-center gap-4">
                    <Link href="/dashboard/knowledge" className="w-9 h-9 rounded-[4px] bg-[#1A1A1A] border border-[#2D2D2D] flex items-center justify-center text-[#797979] hover:text-[#E7E7E7] hover:bg-[#252525] transition-all">
                        <FiArrowLeft className="w-4 h-4" />
                    </Link>
                    <div>
                        <div className="flex items-center gap-3">
                            <h1 className="text-2xl font-serif -tracking-[1px] text-[#E7E7E7]">
                                {item.title}
                            </h1>
                            {item.severity && (
                                <span className={`inline-flex items-center px-2.5 py-0.5 rounded-[4px] text-[11px] font-semibold uppercase tracking-wider ${getSeverityStyle(item.severity)}`}>
                                    {item.severity}
                                </span>
                            )}
                        </div>
                        <div className="flex items-center gap-2 text-[12px] text-[#797979] mt-1">
                            <FiBookOpen className="w-3 h-3" />
                            <span className="capitalize">{item.category.replace('-', ' ')}</span>
                        </div>
                    </div>
                </div>
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
                    </button>
                ))}
            </div>

            {/* Tab Content */}
            <AnimatePresence mode="wait">
                {activeTab === "overview" && (
                    <motion.div
                        key="overview"
                        initial={{ opacity: 0, y: 10 }}
                        animate={{ opacity: 1, y: 0 }}
                        exit={{ opacity: 0, y: -10 }}
                        transition={{ duration: 0.2 }}
                    >
                        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
                            <div className="lg:col-span-2 space-y-6">
                                {/* Description */}
                                <div className="border border-[#2D2D2D] rounded-[4px] bg-[#0F0F0F] p-6">
                                    <h3 className="text-sm font-bold text-[#E7E7E7] mb-4 flex items-center gap-2">
                                        <FiBookOpen className="w-4 h-4 text-[#8b5cf6]" />
                                        Description
                                    </h3>
                                    <p className="text-sm text-[#797979] leading-relaxed">{item.longDescription}</p>
                                </div>

                                {/* Core Concept */}
                                <div className="border border-[#2D2D2D] rounded-[4px] bg-[#0F0F0F] p-6">
                                    <h3 className="text-sm font-bold text-[#E7E7E7] mb-4 flex items-center gap-2">
                                        <FiShield className="w-4 h-4 text-[#8b5cf6]" />
                                        Core Concept
                                    </h3>
                                    <p className="text-sm text-[#797979] leading-relaxed">{item.explanation}</p>
                                </div>

                                {/* Attack Scenario */}
                                {item.attackScenario && (
                                    <div className="border border-[#2D2D2D] rounded-[4px] bg-[#0F0F0F] p-6">
                                        <h3 className="text-sm font-bold text-[#E7E7E7] mb-4 flex items-center gap-2">
                                            <FiAlertTriangle className="w-4 h-4 text-red-500" />
                                            Attack Scenario
                                        </h3>
                                        <div className="p-4 rounded-[4px] bg-red-500/5 border border-red-500/20">
                                            <p className="text-sm text-[#797979] italic leading-relaxed">{item.attackScenario}</p>
                                        </div>
                                    </div>
                                )}
                            </div>

                            <div className="space-y-6">
                                {/* Quick Info */}
                                <div className="border border-[#2D2D2D] rounded-[4px] bg-[#0F0F0F] p-6">
                                    <h3 className="text-sm font-bold text-[#E7E7E7] mb-4">Quick Info</h3>
                                    <div className="space-y-3">
                                        <div className="flex justify-between items-center py-2 border-b border-[#2D2D2D]">
                                            <span className="text-xs text-[#797979]">Category</span>
                                            <span className="text-xs text-[#E7E7E7] capitalize">{item.category.replace('-', ' ')}</span>
                                        </div>
                                        {item.severity && (
                                            <div className="flex justify-between items-center py-2 border-b border-[#2D2D2D]">
                                                <span className="text-xs text-[#797979]">Severity</span>
                                                <span className={`text-xs px-2 py-0.5 rounded-[4px] ${getSeverityStyle(item.severity)}`}>{item.severity}</span>
                                            </div>
                                        )}
                                        <div className="flex justify-between items-center py-2 border-b border-[#2D2D2D]">
                                            <span className="text-xs text-[#797979]">Has Code Examples</span>
                                            <span className={`text-xs ${hasCodeExamples ? 'text-green-400' : 'text-gray-500'}`}>
                                                {hasCodeExamples ? 'Yes' : 'No'}
                                            </span>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </motion.div>
                )}

                {activeTab === "prevention" && (
                    <motion.div
                        key="prevention"
                        initial={{ opacity: 0, y: 10 }}
                        animate={{ opacity: 1, y: 0 }}
                        exit={{ opacity: 0, y: -10 }}
                        transition={{ duration: 0.2 }}
                    >
                        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                            {/* How to Prevent */}
                            {hasHowToPrevent && (
                                <div className="border border-[#2D2D2D] rounded-[4px] bg-[#0F0F0F] p-6">
                                    <h3 className="text-sm font-bold text-[#E7E7E7] mb-4 flex items-center gap-2">
                                        <FiCheckCircle className="w-4 h-4 text-green-500" />
                                        How to Prevent
                                    </h3>
                                    <ul className="space-y-3">
                                        {item.howToPrevent?.map((step, idx) => (
                                            <li key={idx} className="flex items-start gap-3 p-3 rounded-[4px] bg-[#0a0a0a] border border-[#2D2D2D]">
                                                <div className="w-5 h-5 rounded-full bg-green-500/10 flex items-center justify-center shrink-0 text-green-400 text-xs font-bold">
                                                    {idx + 1}
                                                </div>
                                                <span className="text-xs text-[#797979] leading-relaxed">{step}</span>
                                            </li>
                                        ))}
                                    </ul>
                                </div>
                            )}

                            {/* Best Practices */}
                            {hasBestPractices && (
                                <div className="border border-[#2D2D2D] rounded-[4px] bg-[#0F0F0F] p-6">
                                    <h3 className="text-sm font-bold text-[#E7E7E7] mb-4 flex items-center gap-2">
                                        <FiShield className="w-4 h-4 text-blue-500" />
                                        Best Practices
                                    </h3>
                                    <ul className="space-y-3">
                                        {item.bestPractices?.map((practice, idx) => (
                                            <li key={idx} className="flex items-start gap-3 p-3 rounded-[4px] bg-[#0a0a0a] border border-[#2D2D2D]">
                                                <div className="w-5 h-5 rounded-full bg-blue-500/10 flex items-center justify-center shrink-0 text-blue-400 text-xs font-bold">
                                                    ✓
                                                </div>
                                                <span className="text-xs text-[#797979] leading-relaxed">{practice}</span>
                                            </li>
                                        ))}
                                    </ul>
                                </div>
                            )}

                            {!hasHowToPrevent && !hasBestPractices && (
                                <div className="col-span-2 border border-[#2D2D2D] rounded-[4px] bg-[#0F0F0F] p-6 text-center">
                                    <p className="text-sm text-[#797979]">No prevention guidelines available for this item.</p>
                                </div>
                            )}
                        </div>
                    </motion.div>
                )}

                {activeTab === "code" && (
                    <motion.div
                        key="code"
                        initial={{ opacity: 0, y: 10 }}
                        animate={{ opacity: 1, y: 0 }}
                        exit={{ opacity: 0, y: -10 }}
                        transition={{ duration: 0.2 }}
                    >
                        {hasCodeExamples ? (
                            <div className="border border-[#2D2D2D] rounded-[4px] bg-[#0F0F0F] overflow-hidden">
                                <div className="p-4 border-b border-[#2D2D2D] bg-[#1A1A1A]">
                                    <div className="flex items-center justify-between">
                                        <div className="flex items-center gap-2">
                                            <div className="flex gap-1.5">
                                                <div className="w-3 h-3 rounded-full bg-red-500/80" />
                                                <div className="w-3 h-3 rounded-full bg-yellow-500/80" />
                                                <div className="w-3 h-3 rounded-full bg-green-500/80" />
                                            </div>
                                            <span className="text-xs text-[#797979] font-mono ml-2">server.ts</span>
                                        </div>
                                        <div className="flex items-center bg-[#0a0a0a] rounded-[4px] p-1 border border-[#2D2D2D]">
                                            <button
                                                onClick={() => setShowSecure(false)}
                                                className={`px-3 py-1.5 rounded-[4px] text-xs font-semibold transition-all ${!showSecure ? "bg-red-500/20 text-red-400" : "text-[#797979] hover:text-[#E7E7E7]"}`}
                                            >
                                                Vulnerable
                                            </button>
                                            <button
                                                onClick={() => setShowSecure(true)}
                                                className={`px-3 py-1.5 rounded-[4px] text-xs font-semibold transition-all ${showSecure ? "bg-green-500/20 text-green-400" : "text-[#797979] hover:text-[#E7E7E7]"}`}
                                            >
                                                Secure
                                            </button>
                                        </div>
                                    </div>
                                </div>
                                <div className="p-6 bg-[#1a1d24] overflow-x-auto">
                                    <AnimatePresence mode="wait">
                                        <motion.pre
                                            key={showSecure ? "secure" : "vuln"}
                                            initial={{ opacity: 0, x: showSecure ? 20 : -20 }}
                                            animate={{ opacity: 1, x: 0 }}
                                            exit={{ opacity: 0, x: showSecure ? -20 : 20 }}
                                            transition={{ duration: 0.2 }}
                                            className="text-xs font-mono leading-relaxed"
                                        >
                                            <code className={showSecure ? "text-green-400" : "text-red-400"}>
                                                {showSecure ? item.secureCode : item.vulnerableCode}
                                            </code>
                                        </motion.pre>
                                    </AnimatePresence>
                                </div>
                            </div>
                        ) : (
                            <div className="border border-[#2D2D2D] rounded-[4px] bg-[#0F0F0F] p-6 text-center">
                                <FiCode className="w-8 h-8 text-[#797979] mx-auto mb-3" />
                                <p className="text-sm text-[#797979]">No code examples available for this item.</p>
                            </div>
                        )}
                    </motion.div>
                )}
            </AnimatePresence>
        </div>
    );
}