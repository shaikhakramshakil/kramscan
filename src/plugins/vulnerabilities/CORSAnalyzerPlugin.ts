import { BaseVulnerabilityPlugin, PluginContext } from "../types";
import { Vulnerability } from "../../core/vulnerability-detector";

export class CORSAnalyzerPlugin extends BaseVulnerabilityPlugin {
    readonly name = "CORS Analyzer";
    readonly type = "header" as const;
    readonly description = "Detects overly permissive Cross-Origin Resource Sharing configurations";

    private readonly reportedHosts = new Set<string>();

    async analyzeHeaders(context: PluginContext, headers: Record<string, string>): Promise<Vulnerability[]> {
        const host = new URL(context.url).host;

        // Only report once per host
        if (this.reportedHosts.has(host)) {
            return [];
        }

        const vulnerabilities: Vulnerability[] = [];
        const acao = headers["access-control-allow-origin"];
        const acac = headers["access-control-allow-credentials"];
        const acam = headers["access-control-allow-methods"];
        const acah = headers["access-control-allow-headers"];

        // Check for wildcard origin
        if (acao === "*") {
            vulnerabilities.push(
                this.createVulnerability(
                    "CORS: Wildcard Origin Allowed",
                    `The server at ${host} allows requests from any origin (Access-Control-Allow-Origin: *). ` +
                    `This can expose sensitive data to malicious third-party websites.`,
                    context.url,
                    "medium",
                    `Access-Control-Allow-Origin: *`,
                    "Restrict Access-Control-Allow-Origin to trusted domains only. " +
                    "Use a whitelist of allowed origins instead of the wildcard *.",
                    "CWE-942"
                )
            );
        }

        // Check for wildcard with credentials (very dangerous)
        if (acao === "*" && acac?.toLowerCase() === "true") {
            vulnerabilities.push(
                this.createVulnerability(
                    "CORS: Wildcard Origin with Credentials",
                    `The server at ${host} allows any origin AND sends credentials. ` +
                    `This is a critical misconfiguration that can lead to complete session hijacking.`,
                    context.url,
                    "critical",
                    `Access-Control-Allow-Origin: * with Access-Control-Allow-Credentials: true`,
                    "Never combine wildcard origin with credentials. " +
                    "Validate the Origin header against a strict whitelist and reflect only trusted origins.",
                    "CWE-942"
                )
            );
        }

        // Check if origin is reflected without validation (test with a probe)
        if (acao && acao !== "*" && acao !== "null") {
            // If the ACAO reflects back what looks like an origin, it might be reflecting without validation
            const isLikelyReflecting = acao.includes("://") && !acao.includes(host);
            if (isLikelyReflecting && acac?.toLowerCase() === "true") {
                vulnerabilities.push(
                    this.createVulnerability(
                        "CORS: Origin Reflection with Credentials",
                        `The server at ${host} appears to reflect the Origin header value while also allowing credentials. ` +
                        `An attacker can make authenticated requests from any origin.`,
                        context.url,
                        "high",
                        `Access-Control-Allow-Origin: ${acao}, Access-Control-Allow-Credentials: true`,
                        "Validate the Origin header against a strict whitelist of trusted domains. " +
                        "Never blindly reflect the Origin header.",
                        "CWE-942"
                    )
                );
            }
        }

        // Check for null origin allowed (can be exploited via sandboxed iframes)
        if (acao === "null") {
            vulnerabilities.push(
                this.createVulnerability(
                    "CORS: Null Origin Allowed",
                    `The server at ${host} accepts the 'null' origin. ` +
                    `Attackers can exploit this using sandboxed iframes or data URIs.`,
                    context.url,
                    "medium",
                    `Access-Control-Allow-Origin: null`,
                    "Do not allow the 'null' origin. Sandboxed iframes and redirects can send Origin: null.",
                    "CWE-942"
                )
            );
        }

        // Check for dangerous methods
        if (acam) {
            const dangerousMethods = ["PUT", "DELETE", "PATCH"];
            const allowedMethods = acam.toUpperCase().split(",").map(m => m.trim());
            const exposed = dangerousMethods.filter(m => allowedMethods.includes(m));

            if (exposed.length > 0 && acao === "*") {
                vulnerabilities.push(
                    this.createVulnerability(
                        "CORS: Dangerous Methods with Wildcard Origin",
                        `The server at ${host} allows ${exposed.join(", ")} methods from any origin. ` +
                        `This could allow unauthorized data modification from third-party sites.`,
                        context.url,
                        "high",
                        `Access-Control-Allow-Methods: ${acam}; Access-Control-Allow-Origin: *`,
                        "Restrict allowed methods to those actually needed, and never combine with wildcard origin.",
                        "CWE-942"
                    )
                );
            }
        }

        if (vulnerabilities.length > 0) {
            this.reportedHosts.add(host);
        }

        return vulnerabilities;
    }

    reset(): void {
        this.reportedHosts.clear();
    }
}
