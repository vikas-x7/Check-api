import api from "@/lib/axios";
import { DashboardStats } from "@/types";

export const dashboardService = {
    getStats: async (): Promise<DashboardStats> => {
        const res = await api.get("/dashboard");
        return res.data;
    }
};
