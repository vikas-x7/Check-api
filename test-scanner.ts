import { scannerClient } from "./src/server/core/http/scanner-client";

async function testRateLimiter() {
    console.log("=== Testing Rate Limiter ===");
    console.log("Setting limit to 2 Requests Per Second (Should be ~500ms between each request)");
    console.log("Firing 5 concurrent requests at once...\n");

    const requests = Array.from({ length: 5 }).map(async (_, index) => {
        try {
            const start = Date.now();
            await scannerClient({
                method: "GET",
                url: "http://httpbin.org/get",
                requestsPerSecond: 2, // 2 requests per second = 500ms interval
                maxRetries: 1,
            });
            const end = Date.now();
            console.log(`✅ Request ${index + 1} completed at ${new Date().toISOString()} (Delay: ${end - start}ms)`);
        } catch (e: unknown) {
            const message = e instanceof Error ? e.message : String(e);
            console.log(`❌ Request ${index + 1} failed: ${message}`);
        }
    });

    await Promise.all(requests);
    console.log("\nDone checking rate limit.");
}

testRateLimiter().then(() => console.log("Test finished."));
