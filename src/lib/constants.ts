export const APP_NAME = "SecuriScan";
export const APP_DESCRIPTION = "API Security Analyzer & Penetration Testing Report Generator";

export const OWASP_API_TOP_10 = {
    API1: {
        id: "API1:2023",
        name: "Broken Object Level Authorization",
        description: "APIs expose endpoints that handle object identifiers, creating a wide attack surface of Object Level Access Control issues.",
    },
    API2: {
        id: "API2:2023",
        name: "Broken Authentication",
        description: "Authentication mechanisms are often implemented incorrectly, allowing attackers to compromise authentication tokens.",
    },
    API3: {
        id: "API3:2023",
        name: "Broken Object Property Level Authorization",
        description: "Lack of or improper authorization validation at the object property level leads to information exposure or manipulation.",
    },
    API4: {
        id: "API4:2023",
        name: "Unrestricted Resource Consumption",
        description: "API requests consume resources such as network bandwidth, CPU, memory, and storage without any restrictions.",
    },
    API5: {
        id: "API5:2023",
        name: "Broken Function Level Authorization",
        description: "Complex access control policies with different hierarchies, groups, and roles make it easy to introduce flaws.",
    },
    API6: {
        id: "API6:2023",
        name: "Unrestricted Access to Sensitive Business Flows",
        description: "APIs vulnerable to this risk expose a business flow without compensating for the damage if used excessively.",
    },
    API7: {
        id: "API7:2023",
        name: "Server Side Request Forgery",
        description: "SSRF flaws can occur when an API fetches a remote resource without validating the user-supplied URI.",
    },
    API8: {
        id: "API8:2023",
        name: "Security Misconfiguration",
        description: "APIs and supporting systems typically contain complex configurations, which can be easily misconfigured.",
    },
    API9: {
        id: "API9:2023",
        name: "Improper Inventory Management",
        description: "APIs tend to expose more endpoints than traditional web applications, making proper documentation important.",
    },
    API10: {
        id: "API10:2023",
        name: "Unsafe Consumption of APIs",
        description: "Developers tend to trust data received from third-party APIs more than user input.",
    },
} as const;

export const SEVERITY_COLORS = {
    CRITICAL: "#dc2626",
    HIGH: "#ea580c",
    MEDIUM: "#d97706",
    LOW: "#2563eb",
    INFO: "#6b7280",
} as const;

export const SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"] as const;

export const CHECK_TYPES = {
    AUTH: "authentication",
    DATA_EXPOSURE: "data_exposure",
    RATE_LIMIT: "rate_limiting",
    METHOD_FUZZ: "method_fuzzing",
    CORS: "cors_misconfiguration",
    IDOR: "idor",
    ERROR_LEAK: "error_leakage",
} as const;
