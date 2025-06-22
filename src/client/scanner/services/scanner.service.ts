import api from "@/lib/axios";

export interface ManualEndpoint {
    path: string;
    method: "GET" | "POST" | "PUT" | "DELETE" | "PATCH";
    headers?: Record<string, string>;
    body?: string;
    queryParams?: Record<string, string>;
    description?: string;
}

export interface ScanPayload {
    targetUrl: string;
    intensity: "LIGHT" | "MEDIUM" | "AGGRESSIVE";
    openApiSpec?: string;
    endpoints?: ManualEndpoint[];
    requestsPerSecond?: number;
    projectId?: string;
    authConfig?: {
        type: "none" | "bearer" | "api_key";
        value?: string;
        headerName?: string;
    };
}

export const scannerService = {
    createScan: async (payload: ScanPayload) => {
        const res = await api.post("/scans", payload);
        return res.data;
    }
};
