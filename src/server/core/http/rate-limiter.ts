export class RateLimiter {
    private nextSlotTime = 0;
    private minDelayMs: number;

    /**
     * @param requestsPerSecond Maximum number of requests allowed per second.
     * If 0 or undefined, rate limiting is disabled.
     */
    constructor(requestsPerSecond?: number) {
        this.minDelayMs = requestsPerSecond && requestsPerSecond > 0 ? 1000 / requestsPerSecond : 0;
    }

    /**
     * Returns a promise that resolves when the caller is allowed to execute its request.
     */
    async limit(): Promise<void> {
        if (this.minDelayMs === 0) return;

        const now = Date.now();
        let slot: number;

        // This effectively creates a queue of timeslots for incoming requests without blocking the event loop
        if (now > this.nextSlotTime) {
            slot = now;
            this.nextSlotTime = now + this.minDelayMs;
        } else {
            slot = this.nextSlotTime;
            this.nextSlotTime += this.minDelayMs;
        }

        const delay = slot - now;
        if (delay > 0) {
            await new Promise(resolve => setTimeout(resolve, delay));
        }
    }
}

// Global host-based dictionary of rate limiters
const hostRateLimiters: Record<string, RateLimiter> = {};

/**
 * Gets or creates a RateLimiter for a specific hostname.
 */
export function getRateLimiter(hostname: string, requestsPerSecond?: number): RateLimiter {
    // We only update or create a new instance if we have a defined non-zero limit
    if (!hostRateLimiters[hostname]) {
        hostRateLimiters[hostname] = new RateLimiter(requestsPerSecond);
    } else if (requestsPerSecond !== undefined) {
        // Option to overwrite limit dynamically
        const currentMs = hostRateLimiters[hostname]["minDelayMs"];
        const newMs = requestsPerSecond > 0 ? 1000 / requestsPerSecond : 0;
        if (currentMs !== newMs) {
            hostRateLimiters[hostname] = new RateLimiter(requestsPerSecond);
        }
    }
    return hostRateLimiters[hostname];
}
