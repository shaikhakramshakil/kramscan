import { BaseVulnerabilityPlugin, PluginContext } from "../types";
import { Vulnerability } from "../../core/vulnerability-detector";

export class DebugEndpointPlugin extends BaseVulnerabilityPlugin {
    readonly name = "Debug Endpoint Detector";
    readonly type = "info" as const;
    readonly description = "Probes for common debug, admin, and development endpoints left exposed";

    private readonly reportedPaths = new Set<string>();

    /**
     * Common debug/dev endpoints that developers forget to disable before deployment.
     * Each entry has a path, a human-readable name, and expected severity.
     */
    private readonly debugEndpoints: Array<{
        path: string;
        name: string;
        severity: "critical" | "high" | "medium" | "low";
        indicators: string[];
        remediation: string;
    }> = [
            {
                path: "/debug",
                name: "Debug Panel",
                severity: "high",
                indicators: ["debug", "stack", "trace", "error"],
                remediation: "Remove or protect the /debug endpoint behind authentication.",
            },
            {
                path: "/__debug__",
                name: "Django Debug Panel",
                severity: "high",
                indicators: ["django", "debug", "toolbar"],
                remediation: "Set DEBUG=False in Django settings for production.",
            },
            {
                path: "/phpinfo.php",
                name: "PHP Info Page",
                severity: "high",
                indicators: ["phpinfo", "PHP Version", "Configuration"],
                remediation: "Remove phpinfo.php from production servers.",
            },
            {
                path: "/server-status",
                name: "Apache Server Status",
                severity: "medium",
                indicators: ["Apache", "Server Version", "Current Time"],
                remediation: "Restrict /server-status to internal IPs only.",
            },
            {
                path: "/server-info",
                name: "Apache Server Info",
                severity: "medium",
                indicators: ["Apache", "Server Information"],
                remediation: "Disable mod_info or restrict access to internal IPs.",
            },
            {
                path: "/graphql",
                name: "GraphQL Endpoint (Introspection)",
                severity: "medium",
                indicators: ["graphql", "__schema", "query"],
                remediation: "Disable GraphQL introspection in production.",
            },
            {
                path: "/graphiql",
                name: "GraphiQL IDE",
                severity: "high",
                indicators: ["graphiql", "GraphiQL"],
                remediation: "Remove GraphiQL from production deployments.",
            },
            {
                path: "/swagger",
                name: "Swagger UI",
                severity: "medium",
                indicators: ["swagger", "api-docs", "openapi"],
                remediation: "Protect Swagger UI behind authentication or remove from production.",
            },
            {
                path: "/swagger-ui.html",
                name: "Swagger UI HTML",
                severity: "medium",
                indicators: ["swagger", "api-docs"],
                remediation: "Protect Swagger UI behind authentication or remove from production.",
            },
            {
                path: "/api-docs",
                name: "API Documentation",
                severity: "low",
                indicators: ["api", "docs", "openapi", "swagger"],
                remediation: "Restrict API docs to authenticated users in production.",
            },
            {
                path: "/actuator",
                name: "Spring Boot Actuator",
                severity: "high",
                indicators: ["actuator", "beans", "health", "info"],
                remediation: "Secure Spring Boot Actuator endpoints with authentication.",
            },
            {
                path: "/actuator/env",
                name: "Spring Boot Environment",
                severity: "critical",
                indicators: ["property", "source", "value"],
                remediation: "Never expose /actuator/env publicly. It reveals environment variables and secrets.",
            },
            {
                path: "/actuator/heapdump",
                name: "Spring Boot Heap Dump",
                severity: "critical",
                indicators: [],
                remediation: "Disable heap dump endpoint. It can expose sensitive memory contents.",
            },
            {
                path: "/elmah.axd",
                name: "ELMAH Error Log (.NET)",
                severity: "high",
                indicators: ["elmah", "error", "exception"],
                remediation: "Restrict ELMAH access to authenticated administrators.",
            },
            {
                path: "/trace.axd",
                name: ".NET Trace Page",
                severity: "high",
                indicators: ["trace", "request", "response"],
                remediation: "Disable tracing in production web.config.",
            },
            {
                path: "/.env",
                name: "Environment File",
                severity: "critical",
                indicators: ["=", "KEY", "SECRET", "PASSWORD", "DATABASE"],
                remediation: "Never serve .env files. Add them to .gitignore and configure your server to deny access.",
            },
            {
                path: "/wp-config.php",
                name: "WordPress Config",
                severity: "critical",
                indicators: ["DB_NAME", "DB_PASSWORD", "AUTH_KEY"],
                remediation: "Ensure wp-config.php is not accessible via HTTP.",
            },
            {
                path: "/.git/config",
                name: "Git Repository Config",
                severity: "critical",
                indicators: ["[core]", "[remote", "repositoryformatversion"],
                remediation: "Block access to .git directory. Your source code is exposed.",
            },
            {
                path: "/.git/HEAD",
                name: "Git HEAD Reference",
                severity: "high",
                indicators: ["ref:", "refs/heads/"],
                remediation: "Block access to the entire .git directory in your web server configuration.",
            },
            {
                path: "/config.json",
                name: "JSON Config File",
                severity: "medium",
                indicators: ["apiKey", "secret", "password", "database", "connection"],
                remediation: "Do not serve config files via HTTP. Move them outside the web root.",
            },
            {
                path: "/test",
                name: "Test Endpoint",
                severity: "low",
                indicators: ["test", "debug", "hello"],
                remediation: "Remove test endpoints before deploying to production.",
            },
            {
                path: "/health",
                name: "Health Check (Verbose)",
                severity: "low",
                indicators: ["database", "connection", "redis", "memory", "uptime"],
                remediation: "Limit health check responses to simple status. Do not expose internal service details.",
            },
            {
                path: "/metrics",
                name: "Prometheus Metrics",
                severity: "medium",
                indicators: ["process_", "http_", "nodejs_", "go_"],
                remediation: "Protect /metrics endpoint behind authentication or restrict to internal networks.",
            },
        ];

    async analyzeContent(context: PluginContext, _content: string): Promise<Vulnerability[]> {
        const vulnerabilities: Vulnerability[] = [];
        const baseUrl = new URL(context.url).origin;

        for (const endpoint of this.debugEndpoints) {
            const fullPath = `${baseUrl}${endpoint.path}`;

            if (this.reportedPaths.has(fullPath)) continue;

            try {
                const response = await context.page.evaluate(async (url: string) => {
                    try {
                        const res = await fetch(url, {
                            method: "GET",
                            redirect: "follow",
                            credentials: "omit",
                        });
                        const text = await res.text();
                        return { status: res.status, body: text.substring(0, 2000) };
                    } catch {
                        return { status: 0, body: "" };
                    }
                }, fullPath);

                // Check if the endpoint exists and contains debug indicators
                if (response.status >= 200 && response.status < 400) {
                    const bodyLower = response.body.toLowerCase();

                    // For endpoints with no indicators (like heap dumps), 200 status is enough
                    const hasIndicators = endpoint.indicators.length === 0 ||
                        endpoint.indicators.some(ind => bodyLower.includes(ind.toLowerCase()));

                    if (hasIndicators) {
                        this.reportedPaths.add(fullPath);
                        vulnerabilities.push(
                            this.createVulnerability(
                                `Exposed ${endpoint.name}`,
                                `The ${endpoint.name} endpoint is accessible at ${endpoint.path}. ` +
                                `This can expose sensitive internal information, configuration details, or debug data.`,
                                fullPath,
                                endpoint.severity,
                                `HTTP ${response.status} at ${endpoint.path} (${response.body.substring(0, 100)}...)`,
                                endpoint.remediation,
                                "CWE-215"
                            )
                        );
                    }
                }
            } catch {
                // Endpoint not reachable, skip silently
            }
        }

        return vulnerabilities;
    }

    reset(): void {
        this.reportedPaths.clear();
    }
}
