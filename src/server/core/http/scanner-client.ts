import axios, { AxiosRequestConfig, AxiosResponse, type AxiosError } from "axios";
import { logger } from "@/server/core/logging/logger";
import { getRateLimiter } from "./rate-limiter";

const log = logger.child("scanner-client");

export interface ScannerClientOptions extends AxiosRequestConfig {
    maxRetries?: number;
    requestsPerSecond?: number;
}

const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

export async function scannerClient(config: ScannerClientOptions): Promise<AxiosResponse> {
    const maxRetries = config.maxRetries ?? 2;
    let attempt = 0;

    // Default timeout to 10 seconds (between 3-10 secs required)
    const finalConfig = {
        timeout: 10000,
        ...config,
        validateStatus: config.validateStatus || (() => true),
    };

    while (attempt <= maxRetries) {
        try {
            if (finalConfig.url) {
                try {
                    const parsedUrl = new URL(finalConfig.url, finalConfig.baseURL);
                    const limiter = getRateLimiter(parsedUrl.hostname, finalConfig.requestsPerSecond);
                    await limiter.limit();
                } catch {
                    // Invalid URL, ignore rate limit
                }
            }

            const response = await axios(finalConfig);

            // Retry on 5xx errors
            if (response.status >= 500 && response.status < 600) {
                if (attempt >= maxRetries) {
                    return response; // Return the 5xx response if max retries reached
                }
                throw new Error(`ServerError:${response.status}`);
            }

            return response; // Return 2xx, 3xx, 4xx (no retry)
        } catch (error: unknown) {
            const axiosError = error as AxiosError;
            const isAxiosError = axios.isAxiosError(error);
            const errMessage = (error instanceof Error) ? error.message : "";

            const isTimeout = isAxiosError && (axiosError.code === "ECONNABORTED" || errMessage.includes("timeout"));
            const isConnectionError = isAxiosError && !axiosError.response && axiosError.code !== "ECONNABORTED";
            const isServerError = errMessage && errMessage.startsWith("ServerError:");

            // Do not retry on 401, 403, 404 (handled by returning response above anyway since validateStatus = true)
            // Only retry if it's a known retryable condition
            if (!isTimeout && !isConnectionError && !isServerError) {
                throw error;
            }

            if (attempt >= maxRetries) {
                if (isTimeout) {
                    log.error("Request timeout exceeded", {
                        url: config.url,
                        reason: "possible rate limiting, possible DoS protection, or unstable API",
                        action: "marked as timeout"
                    });
                }
                throw error;
            }

            attempt++;
            const backoffMs = Math.pow(2, attempt - 1) * 1000;
            const errMsg = (error instanceof Error) ? error.message : String(error);
            log.warn(`Request failed for ${config.url}, retrying in ${backoffMs}ms (Attempt ${attempt}/${maxRetries})`, {
                url: config.url,
                error: errMsg,
                type: isTimeout ? "timeout" : isServerError ? "5xx" : "connection",
            });
            await sleep(backoffMs);
        }
    }

    throw new Error("Unreachable");
}
