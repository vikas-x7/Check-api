"use client";

import { useState, useCallback } from "react";
import { useDashboard } from "@/client/dashboard/hooks/useDashboard";
import RecentScansTable from "@/client/dashboard/components/RecentScansTable";
import ResultFiltersBar, { ResultFilters } from "@/client/dashboard/components/ResultFilters";

function ResultSkeleton() {
  return (
    <div className="flex flex-col h-screen w-full overflow-hidden animate-pulse">
      <div className="flex-none bg-[#0F0F0F]/80 backdrop-blur-md px-5 py-4 z-20 border-b border-[#2D2D2D]">
        <div className="h-7 w-32 bg-[#1A1A1A] rounded-[4px] mb-2"></div>
        <div className="h-4 w-64 bg-[#1A1A1A] rounded-[4px]"></div>
      </div>
      <div className="flex-none px-5 py-4 border-b border-[#2D2D2D]">
        <div className="h-10 w-full bg-[#1A1A1A] rounded-[4px] mb-3"></div>
        <div className="flex gap-2">
          {[...Array(6)].map((_, i) => (
            <div key={i} className="h-7 w-20 bg-[#1A1A1A] rounded-[4px]"></div>
          ))}
        </div>
      </div>
      <div className="flex-1 bg-[#0A0A0A]">
        <div className="h-64"></div>
      </div>
    </div>
  );
}

export default function ResultPage() {
  const { data: stats, isLoading } = useDashboard();
  const [filters, setFilters] = useState<ResultFilters>({
    search: "",
    status: null,
    intensity: null,
    minFindings: null,
    maxFindings: null,
  });

  const handleFilterChange = useCallback((f: ResultFilters) => {
    setFilters(f);
  }, []);

  if (isLoading) {
    return <ResultSkeleton />;
  }

  return (
    <div className="flex flex-col h-screen w-full overflow-hidden relative">
      {/* Fixed Top Bar */}
      <div className="flex-none bg-[#0F0F0F]/90 backdrop-blur-md px-5 py-4 z-20 border-b border-[#2D2D2D]">
        <h1 className="text-[24px] font-serif -tracking-[1px] text-[#E7E7E7]">
          Results
        </h1>
        <p className="text-sm text-[#797979] mt-1">
          All scanned API results, security findings, and scan history
        </p>
      </div>

      {/* Filters Section */}
      <div className="flex-none px-5 py-4 border-b border-[#2D2D2D] bg-[#0F0F0F]">
        <ResultFiltersBar onChange={handleFilterChange} />
      </div>

      {/* Scrollable Table Area */}
      <div className="flex-1 overflow-y-auto">
        <div className="w-full min-h-full bg-[#0A0A0A]">
          {stats && <RecentScansTable stats={stats} filters={filters} />}
        </div>
      </div>
    </div>
  );
}
