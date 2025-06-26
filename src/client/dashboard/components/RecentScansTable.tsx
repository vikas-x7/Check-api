import Link from "next/link";
import { DashboardStats } from "@/types";
import { FiSearch, FiRefreshCw, FiExternalLink, FiDownload, FiTrash2 } from "react-icons/fi";
import { useInfiniteQuery } from "@tanstack/react-query";
import { useEffect, useRef } from "react";
import api from "@/lib/axios";

interface Filters {
  search?: string;
  status?: string | null;
  intensity?: string | null;
  minFindings?: number | null;
  maxFindings?: number | null;
}

export default function RecentScansTable({ stats, filters = {} }: { stats: DashboardStats; filters?: Filters }) {
  const fetchScans = async ({ pageParam = null }: { pageParam: string | null }) => {
    const res = await api.get('/scans', {
      params: {
        limit: 10,
        cursor: pageParam,
        ...(filters.search ? { search: filters.search } : {}),
        ...(filters.status ? { status: filters.status } : {}),
        ...(filters.intensity ? { intensity: filters.intensity } : {}),
        ...(filters.minFindings != null ? { minFindings: filters.minFindings } : {}),
        ...(filters.maxFindings != null ? { maxFindings: filters.maxFindings } : {}),
      }
    });
    return res.data;
  };

  const hasFilters = !!(filters.search || filters.status || filters.intensity || filters.minFindings != null || filters.maxFindings != null);

  const {
    data,
    fetchNextPage,
    hasNextPage,
    isFetchingNextPage,
    isLoading
  } = useInfiniteQuery({
    queryKey: ["scans", "infinite", filters.search, filters.status, filters.intensity, filters.minFindings, filters.maxFindings],
    queryFn: fetchScans,
    initialPageParam: null as string | null,
    getNextPageParam: (lastPage) => lastPage.nextCursor,
    ...(hasFilters ? {} : {
      initialData: {
        pages: [{ scans: stats?.recentScans || [], nextCursor: stats?.recentScans?.length === 10 ? stats.recentScans[9].id : null }],
        pageParams: [null],
      },
    }),
  });

  const observerRef = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    if (!observerRef.current) return;
    const observer = new IntersectionObserver(
      (entries) => {
        if (entries[0].isIntersecting && hasNextPage && !isFetchingNextPage) {
          fetchNextPage();
        }
      },
      { threshold: 0.1 }
    );
    observer.observe(observerRef.current);
    return () => observer.disconnect();
  }, [hasNextPage, isFetchingNextPage, fetchNextPage]);

  const scans = data?.pages.flatMap((p) => p.scans) || [];

  if (!isLoading && scans.length === 0) {
    return (
      <div className="text-center py-16">
        <div className="w-16 h-16 mx-auto mb-4 rounded-[4px] bg-[#1A1A1A] flex items-center justify-center">
          <FiSearch className="w-8 h-8 text-[#797979]" />
        </div>
        <p className="text-sm text-[#797979] mb-1">
          {hasFilters ? "No scans match the current filters" : "No results yet. Start your first scan!"}
        </p>
        {hasFilters ? (
          <p className="text-xs text-[#797979]/60">Try adjusting or clearing your filters</p>
        ) : (
          <Link
            href="/scanner/new"
            className="inline-flex items-center gap-2 px-5 py-2.5 mt-3 rounded-[4px] text-sm font-semibold bg-[#8b5cf6] hover:bg-[#7c3aed] transition-all no-underline text-white"
          >
            Start Scanning
          </Link>
        )}
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

  const getIntensityStyle = (intensity: string) => {
    switch (intensity) {
      case "LIGHT":
        return "text-blue-400 bg-blue-500/10 border-blue-500/30";
      case "MEDIUM":
        return "text-yellow-400 bg-yellow-500/10 border-yellow-500/30";
      case "AGGRESSIVE":
        return "text-red-400 bg-red-500/10 border-red-500/30";
      default:
        return "text-[#797979] bg-[#1A1A1A] border-[#2D2D2D]";
    }
  };

  const formatDate = (dateStr: string) => {
    const d = new Date(dateStr);
    return d.toLocaleDateString("en-US", { month: "short", day: "numeric", year: "numeric" });
  };

  const formatTime = (dateStr: string) => {
    const d = new Date(dateStr);
    return d.toLocaleTimeString("en-US", { hour: "2-digit", minute: "2-digit" });
  };

  const getDuration = (createdAt: string, completedAt: string | null) => {
    if (!completedAt) return "—";
    const ms = new Date(completedAt).getTime() - new Date(createdAt).getTime();
    if (ms > 60000) return `${(ms / 60000).toFixed(1)}m`;
    return `${(ms / 1000).toFixed(0)}s`;
  };

  return (
    <div className="overflow-x-auto">
      <table className="w-full">
        <thead>
          <tr className="border-b border-[#2D2D2D]">
            {["Target URL", "Status", "Intensity", "Findings", "Duration", "Date", "Actions"].map((h) => (
              <th
                key={h}
                className="p-3 text-left text-[11px] font-semibold uppercase tracking-wider text-[#797979]"
              >
                {h}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {scans.map((scan: Record<string, unknown>, index: number) => (
            <tr
              key={`${scan.id}-${index}`}
              className="border-b border-[#2D2D2D] hover:bg-[#1A1A1A]/50 transition-colors"
            >
              {/* Target URL */}
              <td className="p-3 max-w-[280px]">
                <code className="bg-[#0a0a0a] px-3 py-1.5 rounded-[4px] text-[12px] font-mono text-[#E7E7E7] block truncate">
                  {scan.targetUrl as string}
                </code>
              </td>

              {/* Status */}
              <td className="p-3">
                <span
                  className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-[4px] text-[11px] font-semibold uppercase tracking-wider ${getStatusStyle(scan.status as string)}`}
                >
                  {(scan.status === "RUNNING" || scan.status === "PENDING") && (
                    <span className="w-1.5 h-1.5 rounded-full bg-yellow-400 animate-pulse" />
                  )}
                  {scan.status as string}
                </span>
              </td>

              {/* Intensity */}
              <td className="p-3">
                {scan.intensity ? (
                  <span className={`inline-flex items-center px-2.5 py-1 rounded-[4px] text-[10px] font-bold uppercase tracking-widest border ${getIntensityStyle(scan.intensity as string)}`}>
                    {scan.intensity as string}
                  </span>
                ) : (
                  <span className="text-[#797979] text-xs">—</span>
                )}
              </td>

              {/* Findings */}
              <td className="p-3">
                <span className={`text-sm font-bold ${(scan.findingsCount as number) > 0 ? "text-red-400" : "text-green-400"}`}>
                  {scan.findingsCount as number}
                </span>
                {(scan.findingsCount as number) > 0 && (
                  <span className="text-[11px] text-[#797979] ml-1">issues</span>
                )}
              </td>

              {/* Duration */}
              <td className="p-3 text-[12px] text-[#797979] font-mono">
                {getDuration(scan.createdAt as string, scan.completedAt as string | null)}
              </td>

              {/* Date */}
              <td className="p-3">
                <div className="text-[12px] text-[#E7E7E7]">{formatDate(scan.createdAt as string)}</div>
                <div className="text-[11px] text-[#797979]">{formatTime(scan.createdAt as string)}</div>
              </td>

              {/* Actions */}
              <td className="p-3">
                <div className="flex gap-1.5">
                  <Link
                    href={`/dashboard/scans/${scan.id}`}
                    className="inline-flex items-center gap-1.5 px-3 py-1.5 text-[11px] font-semibold bg-[#8b5cf6] hover:bg-[#7c3aed] rounded-[4px] text-white transition-all no-underline"
                    title="View Details"
                  >
                    <FiExternalLink className="w-3 h-3" />
                    View
                  </Link>
                  <Link
                    href={`/scanner/new?rescanFrom=${scan.id}&targetUrl=${encodeURIComponent(scan.targetUrl as string)}&intensity=${scan.intensity || "MEDIUM"}`}
                    className="inline-flex items-center gap-1.5 px-3 py-1.5 text-[11px] font-semibold bg-[#1A1A1A] hover:bg-[#252525] border border-[#2D2D2D] rounded-[4px] text-[#E7E7E7] transition-all no-underline"
                    title="Rescan"
                  >
                    <FiRefreshCw className="w-3 h-3" />
                    Rescan
                  </Link>
                  {scan.status === "COMPLETED" && (scan.findingsCount as number) > 0 && (
                    <Link
                      href={`/dashboard/scans/${scan.id}`}
                      className="inline-flex items-center gap-1.5 px-3 py-1.5 text-[11px] font-semibold bg-[#1A1A1A] hover:bg-[#252525] border border-[#2D2D2D] rounded-[4px] text-[#E7E7E7] transition-all no-underline"
                      title="View Report"
                    >
                      <FiDownload className="w-3 h-3" />
                      Report
                    </Link>
                  )}
                </div>
              </td>
            </tr>
          ))}
        </tbody>
      </table>

      {/* Loading / Pagination */}
      {hasNextPage && (
        <div ref={observerRef} className="py-4 text-center">
          {isFetchingNextPage ? (
            <span className="text-[12px] text-[#797979] animate-pulse">Loading more results...</span>
          ) : (
            <span className="text-[12px] text-[#797979] opacity-0">Scroll for more</span>
          )}
        </div>
      )}

      {/* Result Count */}
      {!isLoading && scans.length > 0 && (
        <div className="px-4 py-3 border-t border-[#2D2D2D] flex items-center justify-between">
          <span className="text-[11px] text-[#797979]">
            Showing {scans.length} result{scans.length !== 1 ? "s" : ""}
            {hasNextPage && " — scroll for more"}
          </span>
        </div>
      )}
    </div>
  );
}
