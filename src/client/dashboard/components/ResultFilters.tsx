"use client";

import { useState, useEffect, useCallback } from "react";
import { FiSearch, FiFilter, FiX } from "react-icons/fi";

export interface ResultFilters {
    search: string;
    status: string | null;
    intensity: string | null;
    minFindings: number | null;
    maxFindings: number | null;
}

const STATUS_OPTIONS = [
    { label: "All", value: null },
    { label: "Completed", value: "COMPLETED", color: "text-green-400 bg-green-500/10 border-green-500/30" },
    { label: "Running", value: "RUNNING", color: "text-yellow-400 bg-yellow-500/10 border-yellow-500/30" },
    { label: "Pending", value: "PENDING", color: "text-yellow-400 bg-yellow-500/10 border-yellow-500/30" },
    { label: "Failed", value: "FAILED", color: "text-red-400 bg-red-500/10 border-red-500/30" },
];

const INTENSITY_OPTIONS = [
    { label: "All", value: null },
    { label: "Light", value: "LIGHT", color: "text-blue-400 bg-blue-500/10 border-blue-500/30" },
    { label: "Medium", value: "MEDIUM", color: "text-yellow-400 bg-yellow-500/10 border-yellow-500/30" },
    { label: "Aggressive", value: "AGGRESSIVE", color: "text-red-400 bg-red-500/10 border-red-500/30" },
];

const FINDING_RANGES = [
    { label: "All", min: null, max: null },
    { label: "Clean (0)", min: 0, max: 0 },
    { label: "Low (1–10)", min: 1, max: 10 },
    { label: "Medium (11–50)", min: 11, max: 50 },
    { label: "High (51+)", min: 51, max: null },
];

export default function ResultFiltersBar({
    onChange,
}: {
    onChange: (filters: ResultFilters) => void;
}) {
    const [searchTerm, setSearchTerm] = useState("");
    const [selectedStatus, setSelectedStatus] = useState<string | null>(null);
    const [selectedIntensity, setSelectedIntensity] = useState<string | null>(null);
    const [selectedRange, setSelectedRange] = useState(0);

    const onChangeStable = useCallback(onChange, []); // eslint-disable-line react-hooks/exhaustive-deps

    useEffect(() => {
        const timer = setTimeout(() => {
            const range = FINDING_RANGES[selectedRange];
            onChangeStable({
                search: searchTerm,
                status: selectedStatus,
                intensity: selectedIntensity,
                minFindings: range.min,
                maxFindings: range.max,
            });
        }, 400);
        return () => clearTimeout(timer);
    }, [searchTerm, selectedStatus, selectedIntensity, selectedRange, onChangeStable]);

    const hasActiveFilters = selectedStatus !== null || selectedIntensity !== null || selectedRange !== 0 || searchTerm !== "";

    const clearAll = () => {
        setSearchTerm("");
        setSelectedStatus(null);
        setSelectedIntensity(null);
        setSelectedRange(0);
    };

    const pillBase = "px-3 py-1.5 rounded-[4px] text-[11px] font-semibold uppercase tracking-wider border cursor-pointer transition-all duration-150";
    const pillInactive = "border-[#2D2D2D] text-[#797979] bg-transparent hover:bg-[#1A1A1A] hover:text-[#E7E7E7]";
    const pillActive = "border-[#8b5cf6]/50 text-[#E7E7E7] bg-[#8b5cf6]/15";

    return (
        <div className="space-y-3 w-full">
            {/* Top Row: Search + Clear */}
            <div className="flex items-center gap-3">
                <div className="relative flex-1 min-w-[200px]">
                    <FiSearch className="absolute left-3 top-1/2 -translate-y-1/2 text-[#797979] w-4 h-4" />
                    <input
                        type="text"
                        placeholder="Search by target URL…"
                        value={searchTerm}
                        onChange={(e) => setSearchTerm(e.target.value)}
                        className="w-full bg-[#0a0a0a] border border-[#2D2D2D] rounded-[4px] pl-10 pr-4 py-2 text-[13px] text-[#E7E7E7] placeholder:text-[#797979] focus:outline-none focus:border-[#8b5cf6]/50 transition-all"
                    />
                </div>
                {hasActiveFilters && (
                    <button
                        onClick={clearAll}
                        className="flex items-center gap-1.5 px-3 py-2 rounded-[4px] text-[11px] font-semibold text-red-400 bg-red-500/10 border border-red-500/20 hover:bg-red-500/20 transition-all"
                    >
                        <FiX className="w-3.5 h-3.5" />
                        Clear All
                    </button>
                )}
            </div>

            {/* Filter Rows */}
            <div className="flex flex-wrap items-center gap-x-6 gap-y-2">
                {/* Status Filter */}
                <div className="flex items-center gap-2">
                    <span className="text-[10px] uppercase tracking-widest text-[#797979] font-bold mr-1">Status</span>
                    {STATUS_OPTIONS.map((opt) => (
                        <button
                            key={opt.label}
                            onClick={() => setSelectedStatus(opt.value)}
                            className={`${pillBase} ${selectedStatus === opt.value ? (opt.color ? opt.color : pillActive) : pillInactive}`}
                        >
                            {opt.label}
                        </button>
                    ))}
                </div>

                {/* Intensity Filter */}
                <div className="flex items-center gap-2">
                    <span className="text-[10px] uppercase tracking-widest text-[#797979] font-bold mr-1">Intensity</span>
                    {INTENSITY_OPTIONS.map((opt) => (
                        <button
                            key={opt.label}
                            onClick={() => setSelectedIntensity(opt.value)}
                            className={`${pillBase} ${selectedIntensity === opt.value ? (opt.color ? opt.color : pillActive) : pillInactive}`}
                        >
                            {opt.label}
                        </button>
                    ))}
                </div>

                {/* Findings Range Filter */}
                <div className="flex items-center gap-2">
                    <FiFilter className="text-[#797979] w-3.5 h-3.5 shrink-0" />
                    <span className="text-[10px] uppercase tracking-widest text-[#797979] font-bold mr-1">Findings</span>
                    {FINDING_RANGES.map((range, i) => (
                        <button
                            key={i}
                            onClick={() => setSelectedRange(i)}
                            className={`${pillBase} ${selectedRange === i ? pillActive : pillInactive}`}
                        >
                            {range.label}
                        </button>
                    ))}
                </div>
            </div>
        </div>
    );
}
