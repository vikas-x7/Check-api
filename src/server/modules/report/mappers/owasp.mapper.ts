import { OWASP_API_TOP_10 } from "@/lib/constants";
import { FindingResult } from "@/types";

export function mapFindingsToOWASP(findings: FindingResult[]) {
    const owaspEntries = Object.values(OWASP_API_TOP_10);

    return owaspEntries.map((owasp) => {
        const relatedFindings = findings.filter((f) => f.owaspId === owasp.id);
        const hasCritical = relatedFindings.some((f) => f.severity === "CRITICAL");
        const hasHigh = relatedFindings.some((f) => f.severity === "HIGH");

        return {
            id: owasp.id,
            name: owasp.name,
            description: owasp.description,
            findings: relatedFindings.length,
            status: relatedFindings.length === 0
                ? ("pass" as const)
                : hasCritical || hasHigh
                    ? ("fail" as const)
                    : ("warning" as const),
        };
    });
}

export function calculateRiskScore(findings: FindingResult[]): number {
    if (findings.length === 0) return 100;

    const weights = { CRITICAL: 25, HIGH: 15, MEDIUM: 8, LOW: 3, INFO: 1 };
    let totalPenalty = 0;

    for (const finding of findings) {
        totalPenalty += weights[finding.severity] || 0;
    }

    return Math.max(0, Math.min(100, 100 - totalPenalty));
}
