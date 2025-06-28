"use client";
import { motion } from "framer-motion";
import { useState, useEffect } from "react";
import { FiTarget, FiSearch, FiAlertCircle, FiAlertTriangle, FiMinus, FiInfo } from "react-icons/fi";

function Counter({ value, duration = 1200 }: { value: number; duration?: number }) {
    const [d, setD] = useState(0);
    useEffect(() => {
        let s = 0;
        const step = Math.max(1, Math.ceil(value / (duration / 16)));
        const t = setInterval(() => { s = Math.min(s + step, value); setD(s); if (s >= value) clearInterval(t); }, 16);
        return () => clearInterval(t);
    }, [value, duration]);
    return <>{d}</>;
}

type Counts = { critical: number; high: number; medium: number; low: number; info: number; total: number };

export default function StatCards({ counts, riskScore, grade }: { counts: Counts; riskScore: number; grade: { grade: string; color: string; label: string } }) {
    const cards = [
        { label: "Risk Score", value: riskScore, icon: <FiTarget className="w-5 h-5" />, color: grade.color },
        { label: "Total Findings", value: counts.total, icon: <FiSearch className="w-5 h-5" />, color: "#797979" },
        { label: "Critical", value: counts.critical, icon: <FiAlertCircle className="w-5 h-5" />, color: "#ef4444" },
        { label: "High", value: counts.high, icon: <FiAlertTriangle className="w-5 h-5" />, color: "#f97316" },
        { label: "Medium", value: counts.medium, icon: <FiMinus className="w-5 h-5" />, color: "#eab308" },
        { label: "Low / Info", value: counts.low + counts.info, icon: <FiInfo className="w-5 h-5" />, color: "#22c55e" },
    ];

    return (
        <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-2">
            {cards.map((c, i) => (
                <motion.div
                    key={c.label}
                    initial={{ opacity: 0, y: 20 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ delay: i * 0.08, duration: 0.3 }}
                    className="border border-[#2D2D2D] px-4 py-3.5 rounded-[4px] hover:bg-[#1A1A1A] transition-colors group"
                >
                    <div className="flex items-start justify-between mb-2">
                        <div 
                            className="w-10 h-10 rounded-[4px] bg-[#1A1A1A] flex items-center justify-center group-hover:bg-[#252525] transition-colors"
                            style={{ color: c.color }}
                        >
                            {c.icon}
                        </div>
                    </div>
                    <div className="text-[22px] font-bold text-[#E7E7E7] mb-0.5">
                        <Counter value={c.value} />
                    </div>
                    <div className="text-[11px] text-[#797979] uppercase tracking-wide">{c.label}</div>
                    {c.label === "Risk Score" && (
                        <div className="mt-2 text-[10px] font-bold px-2 py-0.5 rounded-[4px] bg-[#1A1A1A] inline-block" style={{ color: grade.color }}>
                            Grade {grade.grade} · {grade.label}
                        </div>
                    )}
                </motion.div>
            ))}
        </div>
    );
}
