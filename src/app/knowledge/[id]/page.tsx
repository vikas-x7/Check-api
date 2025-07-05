"use client";

import { motion, AnimatePresence } from "framer-motion";
import { useState } from "react";
import Link from "next/link";
import { useParams, useRouter } from "next/navigation";
import Navbar from "@/client/home/components/Navbar";
import { knowledgeItems } from "../data";

export default function KnowledgeDetailPage() {
    const params = useParams();
    const router = useRouter();
    const id = params.id as string;
    const [showSecure, setShowSecure] = useState(false);

    const item = knowledgeItems.find(v => v.id === id) || null;

    if (!item) {
        if (typeof window !== "undefined") {
            router.push("/knowledge");
        }
        return (
            <div className="min-h-screen bg-slate-950 flex justify-center items-center">
                <div className="w-12 h-12 border-4 border-indigo-500 border-t-transparent rounded-full animate-spin"></div>
            </div>
        );
    }

    if (!item) return (
        <div className="min-h-screen bg-slate-950 flex justify-center items-center">
            <div className="w-12 h-12 border-4 border-indigo-500 border-t-transparent rounded-full animate-spin"></div>
        </div>
    );

    const hasCodeExamples = item.vulnerableCode && item.secureCode;
    const hasAttackScenario = item.attackScenario && item.howToPrevent;
    const hasBestPractices = item.bestPractices && item.bestPractices.length > 0;

    return (
        <div className="min-h-screen bg-slate-950 text-slate-200 selection:bg-indigo-500/30">
            <Navbar />

            <div className="max-w-7xl mx-auto px-6 py-12">
                <Link href="/knowledge" className="inline-flex items-center gap-2 px-4 py-2 rounded-xl text-sm font-bold bg-slate-900 border border-slate-800 hover:bg-slate-800 text-slate-400 hover:text-white transition-all mb-10 no-underline">
                    ← Back to Knowledge Hub
                </Link>

                <motion.div initial={{ opacity: 0, y: -20 }} animate={{ opacity: 1, y: 0 }} className="relative rounded-3xl overflow-hidden border border-slate-800 bg-slate-900/50 mb-12">
                    <div className={`absolute top-0 inset-x-0 h-2 bg-gradient-to-r ${item.color}`} />
                    <div className="px-8 py-14 md:px-14 flex flex-col md:flex-row gap-8 items-center bg-gradient-to-br from-slate-950/80 via-slate-900/90 to-slate-950 backdrop-blur-sm">

                        <div className={`w-32 h-32 md:w-40 md:h-40 rounded-[2rem] flex flex-col items-center justify-center bg-gradient-to-br ${item.color} shadow-2xl shrink-0 border-4 border-slate-900/50 relative overflow-hidden`}>
                            <div className="absolute inset-x-0 bottom-0 h-1/2 bg-gradient-to-t from-black/40 to-transparent" />
                        </div>

                        <div className="flex-1 text-center md:text-left">
                            <div className="flex flex-wrap items-center justify-center md:justify-start gap-4 mb-4">
                                <span className="px-4 py-1 rounded-lg text-sm font-black text-slate-400 bg-slate-800/80 tracking-widest uppercase">{item.category.replace('-', ' ')}</span>
                                {item.severity && (
                                    <span className={`px-4 py-1.5 rounded-lg text-xs font-bold uppercase tracking-wider border shadow-md ${item.severity === "Critical" ? "bg-red-500/10 text-red-400 border-red-500/20"
                                        : item.severity === "High" ? "bg-orange-500/10 text-orange-400 border-orange-500/20"
                                            : item.severity === "Medium" ? "bg-yellow-500/10 text-yellow-400 border-yellow-500/20"
                                                : "bg-blue-500/10 text-blue-400 border-blue-500/20"}`}>
                                        {item.severity} RISK
                                    </span>
                                )}
                            </div>
                            <h1 className="text-4xl md:text-5xl font-black text-white leading-tight mb-4">{item.title}</h1>
                            <p className="text-lg md:text-xl text-slate-400 max-w-2xl leading-relaxed">{item.shortDescription}</p>
                        </div>

                    </div>
                </motion.div>

                <div className="grid grid-cols-1 lg:grid-cols-12 gap-8 lg:gap-12">

                    <div className="lg:col-span-5 space-y-8">
                        <motion.section initial={{ opacity: 0, x: -20 }} animate={{ opacity: 1, x: 0 }} transition={{ delay: 0.1 }} className="p-8 rounded-3xl bg-slate-900/40 border border-slate-800/50 hover:bg-slate-900/60 transition-colors">
                            <h2 className="text-2xl font-black text-slate-200 mb-6 flex items-center gap-3">
                                Detailed Overview
                            </h2>
                            <p className="text-base text-slate-400 leading-loose">
                                {item.longDescription}
                            </p>
                            <div className="mt-8 p-6 rounded-2xl bg-indigo-500/5 border-l-4 border-indigo-500">
                                <h4 className="text-xs font-bold text-indigo-400 uppercase tracking-widest mb-3">Core Concept</h4>
                                <p className="text-sm text-slate-300 leading-relaxed font-medium">
                                    {item.explanation}
                                </p>
                            </div>
                        </motion.section>

                        {hasAttackScenario && (
                            <motion.section initial={{ opacity: 0, x: -20 }} animate={{ opacity: 1, x: 0 }} transition={{ delay: 0.2 }} className="p-8 rounded-3xl bg-slate-900/40 border border-slate-800/50 hover:bg-slate-900/60 transition-colors">
                                <h2 className="text-2xl font-black text-slate-200 mb-6 flex items-center gap-3">
                                    Attack Scenario
                                </h2>
                                <p className="text-base text-slate-400 italic bg-black/20 p-6 rounded-2xl border border-slate-800/50 leading-relaxed">
                                    {item.attackScenario}
                                </p>
                            </motion.section>
                        )}

                        {item.howToPrevent && item.howToPrevent.length > 0 && (
                            <motion.section initial={{ opacity: 0, x: -20 }} animate={{ opacity: 1, x: 0 }} transition={{ delay: 0.3 }} className="p-8 rounded-3xl bg-slate-900/40 border border-slate-800/50 hover:bg-slate-900/60 transition-colors">
                                <h2 className="text-2xl font-black text-slate-200 mb-6 flex items-center gap-3">
                                    How to Prevent
                                </h2>
                                <ul className="space-y-4">
                                    {item.howToPrevent.map((step, idx) => (
                                        <li key={idx} className="flex items-start gap-4 p-4 rounded-xl bg-slate-950/50 border border-slate-800/50">
                                            <div className="w-6 h-6 rounded-full bg-emerald-500/10 flex items-center justify-center shrink-0 border border-emerald-500/20 text-emerald-400 font-black text-xs">
                                                {idx + 1}
                                            </div>
                                            <span className="text-sm text-slate-300 leading-relaxed font-medium">{step}</span>
                                        </li>
                                    ))}
                                </ul>
                            </motion.section>
                        )}

                        {hasBestPractices && (
                            <motion.section initial={{ opacity: 0, x: -20 }} animate={{ opacity: 1, x: 0 }} transition={{ delay: 0.35 }} className="p-8 rounded-3xl bg-slate-900/40 border border-slate-800/50 hover:bg-slate-900/60 transition-colors">
                                <h2 className="text-2xl font-black text-slate-200 mb-6 flex items-center gap-3">
                                    Best Practices
                                </h2>
                                <ul className="space-y-4">
                                    {item.bestPractices?.map((practice, idx) => (
                                        <li key={idx} className="flex items-start gap-4 p-4 rounded-xl bg-slate-950/50 border border-slate-800/50">
                                            <div className="w-6 h-6 rounded-full bg-blue-500/10 flex items-center justify-center shrink-0 border border-blue-500/20 text-blue-400 font-black text-xs">
                                                ✓
                                            </div>
                                            <span className="text-sm text-slate-300 leading-relaxed font-medium">{practice}</span>
                                        </li>
                                    ))}
                                </ul>
                            </motion.section>
                        )}
                    </div>

                    {hasCodeExamples && (
                        <div className="lg:col-span-7">
                            <motion.div initial={{ opacity: 0, scale: 0.95 }} animate={{ opacity: 1, scale: 1 }} transition={{ delay: 0.4 }} className="sticky top-24">
                                <div className="bg-[#0f1115] border border-slate-800 rounded-[2.5rem] overflow-hidden shadow-2xl flex flex-col h-[700px]">

                                    <div className="p-6 pb-0 border-b border-slate-800/80 bg-slate-900/50">
                                        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 mb-6">
                                            <h3 className="text-sm font-black uppercase tracking-widest text-slate-400 flex items-center gap-3">
                                                Code Playground
                                            </h3>

                                            <div className="flex items-center bg-black/40 rounded-xl p-1.5 border border-slate-800 shadow-inner">
                                                <button
                                                    onClick={() => setShowSecure(false)}
                                                    className={`px-5 py-2 rounded-lg text-xs font-black transition-all ${!showSecure ? "bg-red-500/20 text-red-400 shadow-[0_0_15px_rgba(239,68,68,0.2)]" : "text-slate-500 hover:text-slate-300 hover:bg-white/5"}`}
                                                >
                                                     Vulnerable
                                                </button>
                                                <button
                                                    onClick={() => setShowSecure(true)}
                                                    className={`px-5 py-2 rounded-lg text-xs font-black transition-all ${showSecure ? "bg-emerald-500/20 text-emerald-400 shadow-[0_0_15px_rgba(16,185,129,0.2)]" : "text-slate-500 hover:text-slate-300 hover:bg-white/5"}`}
                                                >
                                                     Mitigated
                                                </button>
                                            </div>
                                        </div>

                                        <div className="flex items-center px-5 h-12 bg-[#1a1d24] border border-b-0 border-slate-800/80 rounded-t-2xl relative">
                                            <div className="flex gap-2 relative z-10">
                                                <div className="w-3 h-3 rounded-full bg-red-500/80 shadow-[0_0_8px_rgba(239,68,68,0.5)]" />
                                                <div className="w-3 h-3 rounded-full bg-amber-500/80 shadow-[0_0_8px_rgba(245,158,11,0.5)]" />
                                                <div className="w-3 h-3 rounded-full bg-emerald-500/80 shadow-[0_0_8px_rgba(16,185,129,0.5)]" />
                                            </div>
                                            <div className="absolute inset-x-0 mx-auto text-center font-mono text-[10px] text-slate-500 font-bold uppercase tracking-widest pointer-events-none">
                                                server.ts
                                            </div>
                                        </div>
                                    </div>

                                    <div className="p-6 md:p-8 flex-1 overflow-auto bg-[#1a1d24] relative border-x border-b border-slate-800/80 rounded-b-2xl mx-6 mb-6 mt-[-1px]">
                                        <AnimatePresence mode="wait">
                                            <motion.pre
                                                key={showSecure ? "secure" : "vuln"}
                                                initial={{ opacity: 0, x: showSecure ? 30 : -30, filter: "blur(4px)" }}
                                                animate={{ opacity: 1, x: 0, filter: "blur(0px)" }}
                                                exit={{ opacity: 0, x: showSecure ? -30 : 30, filter: "blur(4px)" }}
                                                transition={{ duration: 0.3, type: "spring", bounce: 0 }}
                                                className="text-sm font-mono leading-loose tracking-wide overflow-x-auto"
                                            >
                                                <code className={showSecure ? "text-emerald-400/90" : "text-red-400/90"}>
                                                    {showSecure ? item.secureCode : item.vulnerableCode}
                                                </code>
                                            </motion.pre>
                                        </AnimatePresence>
                                    </div>

                                </div>
                            </motion.div>
                        </div>
                    )}

                </div>
            </div>
        </div>
    );
}
