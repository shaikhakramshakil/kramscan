import http from "http";
import https from "https";
import { logger } from "../utils/logger";

export interface ProbeResult {
    reachable: boolean;
    statusCode?: number;
    server?: string;
    framework?: string;
    responseTime: number;
}

/**
 * Probes a localhost URL for server readiness.
 * Polls with exponential backoff until the server responds or timeout is reached.
 */
export async function probeServer(
    url: string,
    options: { timeout?: number; interval?: number; maxAttempts?: number } = {}
): Promise<ProbeResult> {
    const { timeout = 30000, interval = 1000, maxAttempts = 20 } = options;
    const startTime = Date.now();
    let attempts = 0;
    let lastError: string | null = null;

    while (attempts < maxAttempts && Date.now() - startTime < timeout) {
        attempts++;

        try {
            const result = await pingUrl(url);
            if (result.reachable) {
                return result;
            }
            lastError = `HTTP ${result.statusCode}`;
        } catch (err) {
            lastError = (err as Error).message;
        }

        // Exponential backoff with cap
        const delay = Math.min(interval * Math.pow(1.5, attempts - 1), 5000);
        await sleep(delay);
    }

    return {
        reachable: false,
        responseTime: Date.now() - startTime,
    };
}

/**
 * Single ping to a URL — returns immediately.
 */
function pingUrl(url: string): Promise<ProbeResult> {
    return new Promise((resolve, reject) => {
        const startTime = Date.now();
        const parsedUrl = new URL(url);
        const client = parsedUrl.protocol === "https:" ? https : http;

        const req = client.get(
            url,
            {
                timeout: 5000,
                rejectUnauthorized: false, // Allow self-signed certs in dev
            },
            (res) => {
                const responseTime = Date.now() - startTime;
                const server = res.headers["server"] || undefined;
                const poweredBy = res.headers["x-powered-by"] || "";

                // Detect framework from headers
                let framework: string | undefined;
                if (poweredBy.includes("Express")) framework = "Express.js";
                else if (poweredBy.includes("Next.js")) framework = "Next.js";
                else if (poweredBy.includes("Nuxt")) framework = "Nuxt.js";
                else if (poweredBy.includes("PHP")) framework = "PHP";
                else if (poweredBy.includes("ASP.NET")) framework = "ASP.NET";
                else if (res.headers["x-django-request-id"]) framework = "Django";
                else if (res.headers["x-request-id"] && server?.includes("nginx")) framework = "Rails/nginx";

                // Consume body to free socket
                res.resume();

                resolve({
                    reachable: (res.statusCode || 0) >= 100 && (res.statusCode || 0) < 600,
                    statusCode: res.statusCode,
                    server: server as string | undefined,
                    framework,
                    responseTime,
                });
            }
        );

        req.on("error", (err) => {
            reject(err);
        });

        req.on("timeout", () => {
            req.destroy();
            reject(new Error("Connection timed out"));
        });
    });
}

function sleep(ms: number): Promise<void> {
    return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * Checks if a URL points to localhost.
 */
export function isLocalhost(url: string): boolean {
    try {
        const parsed = new URL(url);
        const host = parsed.hostname.toLowerCase();
        return (
            host === "localhost" ||
            host === "127.0.0.1" ||
            host === "0.0.0.0" ||
            host === "::1" ||
            host.endsWith(".localhost")
        );
    } catch {
        return false;
    }
}
