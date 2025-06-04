export type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";
export type ScanStatus = "PENDING" | "RUNNING" | "COMPLETED" | "FAILED";
export type ScanIntensity = "LIGHT" | "MEDIUM" | "AGGRESSIVE";
export type ReportFormat = "PDF" | "JSON" | "HTML";

export interface ScanConfig {
    targetUrl: string;
    intensity: ScanIntensity;
    authConfig?: AuthConfig;
    openApiSpec?: object;
    checks?: string[];
    requestsPerSecond?: number;
}

export interface AuthConfig {
    type: "none" | "api_key" | "bearer" | "jwt";
    value?: string;
    headerName?: string;
}

export interface ScanTarget {
    baseUrl: string;
    endpoints: EndpointInfo[];
    authConfig?: AuthConfig;
    intensity: ScanIntensity;
    requestsPerSecond?: number;
}

export interface EndpointInfo {
    path: string;
    method: string;
    description?: string;
    parameters?: ParameterInfo[];
    customHeaders?: Record<string, string>;
    requestBody?: string;
}

export interface ParameterInfo {
    name: string;
    in: "path" | "query" | "header" | "body";
    type: string;
    required: boolean;
    example?: string;
}

export interface FindingResult {
    id?: string;
    checkType: string;
    severity: Severity;
    title: string;
    description: string;
    evidence: Evidence;
    owaspMapping: string;
    owaspId: string;
    remediation: string;
    endpoint?: string;
    method?: string;
}

export interface Evidence {
    request: {
        url: string;
        method: string;
        headers: Record<string, string>;
        body?: unknown;
    };
    response: {
        status: number;
        headers: Record<string, string>;
        body?: unknown;
        responseTime?: number;
    };
    description: string;
    payload?: string;
}

export interface SecurityCheck {
    name: string;
    description: string;
    owaspMapping: string;
    owaspId: string;
    run(target: ScanTarget): Promise<FindingResult[]>;
}

export interface ScanProgress {
    scanId: string;
    status: ScanStatus;
    progress: number;
    totalChecks: number;
    currentCheck: string;
    currentEndpoint?: string;
    totalEndpoints?: number;
    findings: number;
}

export interface ReportData {
    scan: {
        id: string;
        targetUrl: string;
        status: ScanStatus;
        intensity: ScanIntensity;
        startedAt: string;
        completedAt: string;
    };
    findings: FindingResult[];
    summary: {
        total: number;
        critical: number;
        high: number;
        medium: number;
        low: number;
        info: number;
        riskScore: number;
    };
    owaspCoverage: {
        id: string;
        name: string;
        findings: number;
        status: "pass" | "fail" | "warning";
    }[];
}

export interface DashboardStats {
    totalScans: number;
    totalFindings: number;
    criticalFindings: number;
    averageRiskScore: number;
    severityDistribution?: Array<{ severity: string; _count: number }>;
    findingsByCheck?: Array<{ checkType: string; count: number }>;
    findingsByOwasp?: Array<{ owaspId: string; count: number }>;
    timeline?: Array<{ date: string; total: number; critical: number }>;
    recentScans: {
        id: string;
        targetUrl: string;
        status: ScanStatus;
        findingsCount: number;
        createdAt: string;
    }[];
}
