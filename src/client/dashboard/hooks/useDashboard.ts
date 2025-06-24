import { useQuery } from "@tanstack/react-query";
import { dashboardService } from "../services/dashboard.service";
import { DashboardStats } from "@/types";

export const useDashboard = () => {
    return useQuery<DashboardStats>({
        queryKey: ["dashboard"],
        queryFn: dashboardService.getStats,
    });
};
