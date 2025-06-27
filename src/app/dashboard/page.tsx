"use client";

import { useDashboard } from "@/client/dashboard/hooks/useDashboard";
import StatCard from "@/client/dashboard/components/StatCard";
import RecentScansTable from "@/client/dashboard/components/RecentScansTable";
import {
  FiSearch,
  FiActivity,
  FiAlertCircle,
  FiAlertTriangle,
  FiCheckCircle,
} from "react-icons/fi";
import { motion } from "framer-motion";
import {
  AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer,
  BarChart, Bar, Legend, PieChart, Pie, Cell,
  RadarChart, Radar, PolarGrid, PolarAngleAxis, PolarRadiusAxis
} from "recharts";
import { SEVERITY_COLORS, OWASP_API_TOP_10 } from "@/lib/constants";

export default function DashboardPage() {
  const { data: stats, isLoading } = useDashboard();

  if (isLoading) {
    return (
      <div className="flex flex-col h-screen w-full overflow-hidden animate-pulse">
        <div className="flex-none bg-[#0F0F0F]/80 backdrop-blur-md px-5 py-4 z-20 border-b border-[#2D2D2D]">
          <div className="h-7 w-32 bg-[#1A1A1A] rounded-[4px]"></div>
        </div>

        <div className="flex-1 overflow-y-auto px-4 pb-10 pt-6 space-y-6">
          {/* Stat Cards Skeleton */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            {[...Array(4)].map((_, i) => (
              <div key={i} className="h-32 rounded-[4px] border border-[#2D2D2D] bg-[#0F0F0F] p-4 flex flex-col justify-between">
                <div className="h-10 w-10 bg-[#1A1A1A] rounded-[4px]"></div>
                <div>
                  <div className="h-6 w-16 bg-[#1A1A1A] rounded-[4px] mb-2"></div>
                  <div className="h-3 w-24 bg-[#1A1A1A] rounded-[4px]"></div>
                </div>
              </div>
            ))}
          </div>

          {/* Top Charts Skeleton */}
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
            <div className="lg:col-span-2 h-[340px] rounded-[4px] border border-[#2D2D2D] bg-[#0F0F0F] p-6">
              <div className="h-4 w-48 bg-[#1A1A1A] rounded-[4px] mb-2"></div>
              <div className="h-3 w-64 bg-[#1A1A1A] rounded-[4px] mb-6"></div>
              <div className="h-[220px] w-full bg-[#1A1A1A] rounded-[4px]"></div>
            </div>
            <div className="h-[340px] rounded-[4px] border border-[#2D2D2D] bg-[#0F0F0F] p-6 flex flex-col items-center">
              <div className="w-full h-4 w-40 bg-[#1A1A1A] rounded-[4px] mb-2 self-start"></div>
              <div className="w-full h-3 w-32 bg-[#1A1A1A] rounded-[4px] mb-6 self-start"></div>
              <div className="w-40 h-40 rounded-full bg-[#1A1A1A] mb-6"></div>
              <div className="w-full h-4 bg-[#1A1A1A] rounded-[4px]"></div>
            </div>
          </div>

          {/* Bottom Charts Skeleton */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            <div className="h-[340px] rounded-[4px] border border-[#2D2D2D] bg-[#0F0F0F] p-6">
              <div className="h-4 w-48 bg-[#1A1A1A] rounded-[4px] mb-2"></div>
              <div className="h-3 w-64 bg-[#1A1A1A] rounded-[4px] mb-6"></div>
              <div className="space-y-4">
                {[...Array(5)].map((_, i) => (
                  <div key={i} className="h-6 w-full bg-[#1A1A1A] rounded-[4px]"></div>
                ))}
              </div>
            </div>
            <div className="h-[340px] rounded-[4px] border border-[#2D2D2D] bg-[#0F0F0F] p-6 flex flex-col items-center justify-center">
              <div className="w-full h-4 w-48 bg-[#1A1A1A] rounded-[4px] mb-2 self-start"></div>
              <div className="w-full h-3 w-56 bg-[#1A1A1A] rounded-[4px] mb-12 self-start"></div>
              <div className="w-48 h-48 bg-[#1A1A1A] rounded-full opacity-50 polygon-skeleton"></div>
            </div>
          </div>
        </div>
      </div>
    );
  }

  // Derived datasets
  const severityDist = stats?.severityDistribution || [];
  const sevMap = severityDist.map(s => ({
    name: s.severity,
    value: s._count,
    fill: SEVERITY_COLORS[s.severity as keyof typeof SEVERITY_COLORS] || "#797979",
  })).sort((a, b) => b.value - a.value);

  const owaspArr = Object.values(OWASP_API_TOP_10);
  const owaspRadar = owaspArr.map(o => {
    const found = stats?.findingsByOwasp?.find(f => f.owaspId === o.id);
    return { name: o.id, findings: found ? found.count : 0 };
  });

  const checkData = (stats?.findingsByCheck || [])
    .map(c => ({ name: c.checkType.replace(/_/g, " ").replace(/\b\w/g, l => l.toUpperCase()), count: c.count }))
    .sort((a, b) => b.count - a.count)
    .slice(0, 8); // Top 8 mapped

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const tooltipStyle: any = { background: "#0F0F0F", border: "1px solid #2D2D2D", borderRadius: 4, fontSize: 12, color: "#E7E7E7" };

  return (
    <div className="flex flex-col h-screen w-full overflow-hidden">
      <div className="flex-none bg-[#0F0F0F]/90 backdrop-blur-md border-b border-[#2D2D2D] px-5 py-4 z-20">
        <div className="flex justify-between items-center">
          <div>
            <h1 className="text-[24px] font-serif -tracking-[1px] text-[#E7E7E7]">
              Overview
            </h1>
            <p className="text-sm text-[#797979] font-dnsans mt-1">
              Real-time telemetry and API security insights
            </p>
          </div>
        </div>
      </div>

      <div className="flex-1 overflow-y-auto px-4 pb-10 pt-6 space-y-6">

        {/* Stats Grid */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <StatCard
            title="Total Scans"
            value={stats?.totalScans || 0}
            icon={<FiSearch />}
            color="#06b6d4"
          />
          <StatCard
            title="Total Findings"
            value={stats?.totalFindings || 0}
            icon={<FiActivity />}
            color="#8b5cf6"
          />
          <StatCard
            title="Critical Issues"
            value={stats?.criticalFindings || 0}
            icon={<FiAlertCircle />}
            color="#ef4444"
          />
          <StatCard
            title="Platform Risk State"
            value={(stats?.totalFindings || 0) > 0 ? "Elevated Risk" : "Secure Baseline"}
            icon={
              (stats?.totalFindings || 0) > 0 ? <FiAlertTriangle /> : <FiCheckCircle />
            }
            color={
              (stats?.totalFindings || 0) > 0 ? "#f59e0b" : "#22c55e"
            }
            isText
          />
        </div>

        {/* Main Analytical Charts */}
        {stats && (stats.totalFindings > 0) ? (
          <>
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
              {/* 7-Day Trend Area Chart */}
              <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.1 }}
                className="border border-[#2D2D2D] rounded-[4px] p-6 lg:col-span-2 bg-[#0A0A0A]">
                <h2 className=" text-[#E7E7E7] mb-1">7-Day Threat Discovery Trend</h2>
                <p className="text-xs text-[#797979] mb-4">Volume of vulnerabilities identified over the past week</p>
                {stats.timeline && stats.timeline.length > 0 ? (
                  <ResponsiveContainer width="100%" height={260}>
                    <AreaChart data={stats.timeline}>
                      <defs>
                        <linearGradient id="colorTotal" x1="0" y1="0" x2="0" y2="1">
                          <stop offset="5%" stopColor="#8b5cf6" stopOpacity={0.3} />
                          <stop offset="95%" stopColor="#8b5cf6" stopOpacity={0} />
                        </linearGradient>
                        <linearGradient id="colorCrit" x1="0" y1="0" x2="0" y2="1">
                          <stop offset="5%" stopColor="#ef4444" stopOpacity={0.4} />
                          <stop offset="95%" stopColor="#ef4444" stopOpacity={0} />
                        </linearGradient>
                      </defs>
                      <CartesianGrid strokeDasharray="3 3" stroke="#2D2D2D" vertical={false} />
                      <XAxis dataKey="date" tick={{ fill: "#797979", fontSize: 10 }} axisLine={false} tickLine={false} />
                      <YAxis tick={{ fill: "#797979", fontSize: 10 }} axisLine={false} tickLine={false} />
                      <Tooltip contentStyle={tooltipStyle} />
                      <Legend wrapperStyle={{ fontSize: 11, paddingTop: 10, color: "#797979" }} />
                      <Area type="monotone" name="Total Findings" dataKey="total" stroke="#8b5cf6" strokeWidth={2} fillOpacity={1} fill="url(#colorTotal)" animationDuration={1000} />
                      <Area type="monotone" name="Critical Severity" dataKey="critical" stroke="#ef4444" strokeWidth={2} fillOpacity={1} fill="url(#colorCrit)" animationDuration={1000} />
                    </AreaChart>
                  </ResponsiveContainer>
                ) : <div className="h-[260px] flex items-center justify-center text-[#797979] text-sm">No timeline data available</div>}
              </motion.div>

              {/* Severity Distribution Pie Chart */}
              <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.2 }}
                className="border border-[#2D2D2D] rounded-[4px] p-6 bg-[#0A0A0A] flex flex-col items-center">
                <div className="w-full">
                  <h2 className=" text-[#E7E7E7] mb-1">Global Severity Distribution</h2>
                  <p className="text-xs text-[#797979]">Across all scanned targets</p>
                </div>
                <div className="flex-1 w-full min-h-[220px]">
                  <ResponsiveContainer width="100%" height="100%">
                    <PieChart>
                      <Pie data={sevMap} cx="50%" cy="50%" innerRadius={60} outerRadius={90} paddingAngle={4} dataKey="value" animationDuration={1200}>
                        {sevMap.map((e, i) => <Cell key={i} fill={e.fill} stroke="transparent" />)}
                      </Pie>
                      <Tooltip contentStyle={tooltipStyle} />
                    </PieChart>
                  </ResponsiveContainer>
                </div>
                <div className="w-full flex flex-wrap justify-center gap-2 mt-2">
                  {sevMap.map(s => (
                    <div key={s.name} className="flex items-center gap-1.5 px-2 py-0.5 rounded-[4px] bg-[#1A1A1A] border border-[#2D2D2D]">
                      <span className="w-2 h-2 rounded-full" style={{ background: s.fill }} />
                      <span className="text-[10px] uppercase font-bold text-[#E7E7E7]">{s.name}</span>
                      <span className="text-[10px] text-[#797979]">{s.value}</span>
                    </div>
                  ))}
                </div>
              </motion.div>
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
              {/* Top Security Checks Bar Chart */}
              <motion.div initial={{ opacity: 0, x: -10 }} animate={{ opacity: 1, x: 0 }} transition={{ delay: 0.3 }}
                className="border border-[#2D2D2D] rounded-[4px] p-6 bg-[#0A0A0A]">
                <h2 className=" text-[#E7E7E7] mb-1">Highest Frequency Vulnerabilities</h2>
                <p className="text-xs text-[#797979] mb-4">Top occurring security checks flagged by the scanner</p>
                {checkData.length > 0 ? (
                  <ResponsiveContainer width="100%" height={260}>
                    <BarChart data={checkData} layout="vertical" margin={{ left: 10, right: 10 }}>
                      <CartesianGrid strokeDasharray="3 3" stroke="#2D2D2D" horizontal={true} vertical={false} />
                      <XAxis type="number" tick={{ fill: "#797979", fontSize: 10 }} axisLine={false} tickLine={false} />
                      <YAxis type="category" dataKey="name" tick={{ fill: "#E7E7E7", fontSize: 10 }} width={140} axisLine={false} tickLine={false} />
                      <Tooltip contentStyle={tooltipStyle} cursor={{ fill: '#1A1A1A' }} />
                      <Bar dataKey="count" name="Frequency" fill="#06b6d4" radius={[0, 4, 4, 0]} animationDuration={1200} barSize={16}>
                        {checkData.map((_, i) => (
                          <Cell key={`cell-${i}`} fill={i === 0 ? "#ef4444" : i === 1 ? "#f97316" : i === 2 ? "#eab308" : "#06b6d4"} />
                        ))}
                      </Bar>
                    </BarChart>
                  </ResponsiveContainer>
                ) : <div className="h-[260px] flex items-center justify-center text-[#797979] text-sm">No vulnerability data structured</div>}
              </motion.div>

              {/* OWASP Coverage Radar */}
              <motion.div initial={{ opacity: 0, x: 10 }} animate={{ opacity: 1, x: 0 }} transition={{ delay: 0.4 }}
                className="border border-[#2D2D2D] rounded-[4px] p-6 bg-[#0A0A0A]">
                <h2 className=" text-[#E7E7E7] mb-1">OWASP Top 10 Surface Alignment</h2>
                <p className="text-xs text-[#797979] mb-2">Platform-wide threat coverage mapped to OWASP categories</p>
                <ResponsiveContainer width="100%" height={260}>
                  <RadarChart data={owaspRadar}>
                    <PolarGrid stroke="#2D2D2D" />
                    <PolarAngleAxis dataKey="name" tick={{ fill: "#E7E7E7", fontSize: 9 }} />
                    <PolarRadiusAxis tick={{ fill: "#797979", fontSize: 9 }} angle={30} domain={[0, 'auto']} />
                    <Tooltip contentStyle={tooltipStyle} />
                    <Radar name="Findings Map" dataKey="findings" stroke="#8b5cf6" strokeWidth={2} fill="#8b5cf6" fillOpacity={0.25} animationDuration={1500} />
                  </RadarChart>
                </ResponsiveContainer>
              </motion.div>
            </div>
          </>
        ) : (
          <div className="border border-[#2D2D2D] rounded-[4px] py-16 text-center bg-[#0A0A0A] mt-4">
            <FiCheckCircle className="w-12 h-12 text-[#2D2D2D] mx-auto mb-4" />
            <h2 className="text-base font-bold text-[#E7E7E7] mb-2">No Vulnerability Data</h2>
            <p className="text-sm text-[#797979]">Perform a scan to populate platform analytics.</p>
          </div>
        )}

        {/* Recent Scans Table */}
        <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.5 }}
          className="border border-[#2D2D2D] rounded-[4px] bg-[#0A0A0A]">
          <div className="flex justify-between items-center p-4 border-b border-[#2D2D2D]">
            <div>
              <h2 className=" text-white">Execution Logs & History</h2>
              <p className="text-xs text-[#797979]">Chronological record of engine scans</p>
            </div>
          </div>
          {stats && <RecentScansTable stats={stats} />}
        </motion.div>
      </div>
    </div>
  );
}
