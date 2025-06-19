import { ScanTarget, FindingResult, ScanProgress } from "@/types";
import { ALL_CHECKS } from "./checks";
import { logger } from "@/server/core/logging/logger";

const log = logger.child("scanner-engine");

export class ScannerEngine {
    private progressCallback?: (progress: ScanProgress) => Promise<void> | void;

    setProgressCallback(cb: (progress: ScanProgress) => Promise<void> | void) {
        this.progressCallback = cb;
    }

    private async notifyProgress(progress: ScanProgress) {
        if (!this.progressCallback) return;
        try {
            await this.progressCallback(progress);
        } catch (err) {
            log.error("Progress callback failed", { error: err, progress });
        }
    }

    async runScan(scanId: string, target: ScanTarget): Promise<FindingResult[]> {
        const totalChecks = ALL_CHECKS.length;
        let completedChecks = 0;

        const runCheck = async (check: unknown, index: number): Promise<FindingResult[]> => {
            if (!check || typeof (check as { run?: unknown }).run !== "function") {
                log.warn("Check is missing or invalid", { index });
                completedChecks += 1;
                await this.notifyProgress({
                    scanId,
                    status: "RUNNING",
                    progress: Math.round((completedChecks / totalChecks) * 100),
                    totalChecks,
                    totalEndpoints: target.endpoints.length,
                    currentCheck: "unknown",
                    currentEndpoint: "N/A",
                    findings: 0,
                });
                return [];
            }

            const typedCheck = check as { name?: string; run: (target: ScanTarget) => Promise<FindingResult[]> };

            try {
                const findings = await typedCheck.run(target);
                return findings || [];
            } catch (error) {
                log.error(`Check evaluation failed: ${typedCheck.name ?? "unknown"}`, { error });
                return [];
            } finally {
                completedChecks += 1;
                await this.notifyProgress({
                    scanId,
                    status: "RUNNING",
                    progress: Math.min(100, Math.round((completedChecks / totalChecks) * 100)),
                    totalChecks,
                    totalEndpoints: target.endpoints.length,
                    currentCheck: typedCheck.name || "unknown",
                    currentEndpoint: "N/A",
                    findings: 0,
                });
            }
        };

        const results = await Promise.all(ALL_CHECKS.map(runCheck));
        const allFindings = results.flatMap((x) => x);

        log.info("Scan completed", { scanId, findings: allFindings.length });

        await this.notifyProgress({
            scanId,
            status: "COMPLETED",
            progress: 100,
            totalChecks,
            totalEndpoints: target.endpoints.length,
            currentCheck: "Complete",
            currentEndpoint: "Complete",
            findings: allFindings.length,
        });

        return allFindings;
    }
}
