import { DashboardStats } from "@/types";
import { SEVERITY_COLORS } from "@/lib/constants";

export default function SeverityDistribution({ stats }: { stats: DashboardStats }) {
    const severityDist: Array<{ severity: string; _count: number }> = stats?.severityDistribution || [];
    const getSeverityCount = (sev: string) => severityDist.find((s) => s.severity === sev)?._count || 0;

    return (
        <div>
            <div className="flex items-center justify-between mb-4">
                <h2 className="text-sm font-bold text-[#E7E7E7]">Severity Distribution</h2>
                <span className="text-[12px] text-[#797979]">
                    {stats?.totalFindings || 0} total findings
                </span>
            </div>
            
            <div className="flex gap-1 h-3 rounded-[4px] overflow-hidden bg-[#0a0a0a]">
                {["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"].map((sev) => {
                    const count = getSeverityCount(sev);
                    const total = stats?.totalFindings || 1;
                    const width = (count / total) * 100;
                    if (width === 0) return null;
                    return (
                        <div
                            key={sev}
                            className="h-full rounded-[2px] transition-all duration-500 ease-out"
                            style={{
                                width: `${width}%`,
                                backgroundColor: SEVERITY_COLORS[sev as keyof typeof SEVERITY_COLORS]
                            }}
                            title={`${sev}: ${count}`}
                        />
                    );
                })}
            </div>
            
            <div className="flex gap-5 mt-4 flex-wrap">
                {["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"].map((sev) => {
                    const count = getSeverityCount(sev);
                    return (
                        <div key={sev} className="flex items-center gap-2">
                            <div
                                className="w-2.5 h-2.5 rounded-[2px]"
                                style={{ backgroundColor: SEVERITY_COLORS[sev as keyof typeof SEVERITY_COLORS] }}
                            />
                            <span className="text-[12px] text-[#797979] uppercase font-medium">{sev}</span>
                            <span className="text-[13px] font-bold text-[#E7E7E7]">{count}</span>
                        </div>
                    );
                })}
            </div>
        </div>
    );
}
