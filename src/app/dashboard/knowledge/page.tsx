"use client";

import { motion } from "framer-motion";
import { HiCode, HiLockClosed, HiDatabase } from "react-icons/hi";
import { FiShield, FiGlobe } from "react-icons/fi";
import Link from "next/link";

const knowledgeCategories = [
    {
        title: "OWASP API Security Top 10 (2023)",
        icon: <FiShield className="w-6 h-6" />,
        description: "Understanding the most critical API security risks",
        items: [
            { name: "Broken Object Level Authorization", id: "api1-bola", severity: "critical" },
            { name: "Broken Authentication", id: "api2-broken-auth", severity: "critical" },
            { name: "Broken Object Property Level Authorization", id: "api3-bopla", severity: "high" },
            { name: "Unrestricted Resource Consumption", id: "api4-urc", severity: "high" },
            { name: "Broken Function Level Authorization", id: "api5-bfla", severity: "high" },
            { name: "Unrestricted Access to Sensitive Business Flows", id: "api6-uasbf", severity: "medium" },
            { name: "Server-Side Request Forgery", id: "api7-ssrf", severity: "high" },
            { name: "Security Misconfiguration", id: "api8-sec-misconfig", severity: "high" },
            { name: "Improper Inventory Management", id: "api9-improper-inventory", severity: "medium" },
            { name: "Unsafe Consumption of APIs", id: "api10-unsafe-consumption", severity: "high" },
        ]
    },
    {
        title: "Common Vulnerability Types",
        icon: <HiCode className="w-6 h-6" />,
        description: "Learn about common security vulnerabilities in APIs",
        items: [
            { name: "SQL Injection", id: "sqli", severity: "critical" },
            { name: "NoSQL Injection", id: "nosqli", severity: "critical" },
            { name: "JWT Token Vulnerabilities", id: "jwt-vulns", severity: "high" },
            { name: "CORS Misconfiguration", id: "cors-misconfig", severity: "medium" },
            { name: "Rate Limiting Issues", id: "rate-limiting-issues", severity: "medium" },
            { name: "Sensitive Data Exposure", id: "sensitive-data-exposure", severity: "high" },
        ]
    },
    {
        title: "API Best Practices",
        icon: <FiGlobe className="w-6 h-6" />,
        description: "Secure coding practices for API development",
        items: [
            { name: "Use HTTPS for All Communications", id: "https-best-practice", severity: "info" },
            { name: "Validate and Sanitize All Input", id: "input-validation", severity: "info" },
            { name: "Use Parameterized Queries", id: "parameterized-queries", severity: "info" },
            { name: "Apply Principle of Least Privilege", id: "least-privilege", severity: "info" },
            { name: "Implement Proper Logging", id: "logging-best-practice", severity: "info" },
            { name: "Use Security Headers", id: "security-headers", severity: "info" },
            { name: "Enable API Rate Limiting", id: "api-rate-limiting", severity: "info" },
        ]
    },
    {
        title: "Authentication & Authorization",
        icon: <HiLockClosed className="w-6 h-6" />,
        description: "Understanding API authentication mechanisms",
        items: [
            { name: "Broken Authentication", id: "api2-broken-auth", severity: "critical" },
            { name: "Broken Function Level Authorization", id: "api5-bfla", severity: "high" },
            { name: "JWT Token Vulnerabilities", id: "jwt-vulns", severity: "high" },
            { name: "OAuth 2.0 Security", id: "oauth2-security", severity: "info" },
            { name: "API Key Management", id: "api-key-management", severity: "info" },
        ]
    },
    {
        title: "Data Protection",
        icon: <HiDatabase className="w-6 h-6" />,
        description: "Protecting sensitive data in your APIs",
        items: [
            { name: "Sensitive Data Exposure", id: "sensitive-data-exposure", severity: "high" },
            { name: "SQL Injection", id: "sqli", severity: "critical" },
            { name: "NoSQL Injection", id: "nosqli", severity: "critical" },
            { name: "Server-Side Request Forgery", id: "api7-ssrf", severity: "high" },
            { name: "Data Encryption Best Practices", id: "data-encryption", severity: "info" },
        ]
    },
];

const severityColors: Record<string, string> = {
    critical: "bg-red-500/20 text-red-400 border-red-500/30",
    high: "bg-orange-500/20 text-orange-400 border-orange-500/30",
    medium: "bg-yellow-500/20 text-yellow-400 border-yellow-500/30",
    low: "bg-blue-500/20 text-blue-400 border-blue-500/30",
    info: "bg-gray-500/20 text-gray-400 border-gray-500/30",
};

export default function KnowledgePage() {
    return (
        <div className="px-5 py-3">
            <div className="mb-7">
                <h1 className="text-3xl font-serif -tracking-[1px] text-[#E7E7E7]">
                    Knowledge Base
                </h1>
                <p className="text-sm text-[#797979] font-dnsans">
                    Learn about API security vulnerabilities and best practices
                </p>
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                {knowledgeCategories.map((category, index) => (
                    <motion.div
                        key={category.title}
                        initial={{ opacity: 0, y: 20 }}
                        animate={{ opacity: 1, y: 0 }}
                        transition={{ delay: index * 0.1, duration: 0.3 }}
                        className="border border-[#2D2D2D] rounded-[4px] bg-[#0F0F0F] overflow-hidden"
                    >
                        <div className="flex items-center gap-3 p-4 border-b border-[#2D2D2D]">
                            <div className="w-10 h-10 rounded-[4px] bg-[#1A1A1A] flex items-center justify-center text-[#E7E7E7]">
                                {category.icon}
                            </div>
                            <div>
                                <h2 className="text-sm font-bold text-[#E7E7E7]">{category.title}</h2>
                                <p className="text-[11px] text-[#797979]">{category.description}</p>
                            </div>
                        </div>
                        <div className="p-4 space-y-2">
                            {category.items.map((item) => (
                                <Link
                                    key={item.id}
                                    href={`/dashboard/knowledge/${item.id}`}
                                    className="flex items-center justify-between py-2 px-3 rounded-[4px] bg-[#0a0a0a] hover:bg-[#141414] transition-colors cursor-pointer"
                                >
                                    <span className="text-xs text-[#E7E7E7]">{item.name}</span>
                                    <span
                                        className={`text-[10px] px-2 py-0.5 rounded-[4px] border uppercase font-semibold ${severityColors[item.severity]}`}
                                    >
                                        {item.severity}
                                    </span>
                                </Link>
                            ))}
                        </div>
                    </motion.div>
                ))}
            </div>

            <motion.div
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                transition={{ delay: 0.6 }}
                className="mt-8 p-6 border border-[#2D2D2D] rounded-[4px] bg-[#0F0F0F] text-center"
            >
                <div className="text-4xl mb-3"></div>
                <h2 className="text-lg font-bold text-[#E7E7E7] mb-2">Stay Updated</h2>
                <p className="text-sm text-[#797979] max-w-md mx-auto">
                    This knowledge base will be expanded with more security resources, vulnerability explanations, and remediation guides.
                </p>
            </motion.div>
        </div>
    );
}