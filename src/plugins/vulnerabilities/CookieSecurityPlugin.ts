import { BaseVulnerabilityPlugin, PluginContext } from "../types";
import { Vulnerability } from "../../core/vulnerability-detector";

export class CookieSecurityPlugin extends BaseVulnerabilityPlugin {
    readonly name = "Cookie Security Auditor";
    readonly type = "header" as const;
    readonly description = "Audits cookies for missing security flags (HttpOnly, Secure, SameSite)";

    private readonly reportedCookies = new Set<string>();

    async analyzeHeaders(context: PluginContext, headers: Record<string, string>): Promise<Vulnerability[]> {
        const vulnerabilities: Vulnerability[] = [];
        const host = new URL(context.url).host;

        // Collect all set-cookie headers
        const setCookieHeader = headers["set-cookie"];
        if (!setCookieHeader) return [];

        // set-cookie headers might be combined with newlines in some scenarios
        const cookies = setCookieHeader.split(/,(?=[^;]*=)/g).map(c => c.trim());

        for (const cookie of cookies) {
            const cookieName = cookie.split("=")[0]?.trim();
            if (!cookieName) continue;

            const cookieKey = `${host}:${cookieName}`;
            if (this.reportedCookies.has(cookieKey)) continue;

            const cookieLower = cookie.toLowerCase();
            const issues: string[] = [];

            // Check HttpOnly flag
            if (!cookieLower.includes("httponly")) {
                issues.push("Missing HttpOnly flag (vulnerable to XSS cookie theft)");
            }

            // Check Secure flag
            if (!cookieLower.includes("secure")) {
                issues.push("Missing Secure flag (cookie sent over HTTP)");
            }

            // Check SameSite attribute
            if (!cookieLower.includes("samesite")) {
                issues.push("Missing SameSite attribute (vulnerable to CSRF)");
            } else if (cookieLower.includes("samesite=none")) {
                if (!cookieLower.includes("secure")) {
                    issues.push("SameSite=None without Secure flag (browser will reject)");
                }
                issues.push("SameSite=None allows cross-site requests (verify this is intentional)");
            }

            // Check for session-like cookies with missing flags
            const isSessionCookie = /^(sess|session|sid|token|auth|jwt|csrf|xsrf|connect\.sid|phpsessid|jsessionid|asp\.net_sessionid)/i.test(cookieName);

            if (issues.length > 0) {
                const severity = isSessionCookie
                    ? (issues.some(i => i.includes("HttpOnly")) ? "high" : "medium")
                    : "low";

                this.reportedCookies.add(cookieKey);

                vulnerabilities.push(
                    this.createVulnerability(
                        `Insecure Cookie: ${cookieName}`,
                        `The cookie '${cookieName}' on ${host} has security issues:\n` +
                        issues.map(i => `  • ${i}`).join("\n"),
                        context.url,
                        severity,
                        `Set-Cookie: ${cookie.substring(0, 200)}`,
                        "Set all cookies with: HttpOnly (prevents JS access), " +
                        "Secure (HTTPS only), SameSite=Lax or Strict (CSRF protection). " +
                        "Example: Set-Cookie: session=abc; HttpOnly; Secure; SameSite=Lax; Path=/",
                        "CWE-614"
                    )
                );
            }

            // Check for overly broad domain
            const domainMatch = cookie.match(/domain=([^;]+)/i);
            if (domainMatch) {
                const domain = domainMatch[1].trim();
                if (domain.startsWith(".") && domain.split(".").length <= 2) {
                    this.reportedCookies.add(cookieKey + ":domain");
                    vulnerabilities.push(
                        this.createVulnerability(
                            `Cookie Domain Too Broad: ${cookieName}`,
                            `The cookie '${cookieName}' has domain set to '${domain}', which allows ` +
                            `any subdomain to read this cookie. This increases the attack surface.`,
                            context.url,
                            "low",
                            `Domain=${domain}`,
                            "Set the cookie domain to the most specific subdomain possible.",
                            "CWE-1275"
                        )
                    );
                }
            }

            // Check for missing expiry on session cookies (persistent session)
            if (isSessionCookie && !cookieLower.includes("expires") && !cookieLower.includes("max-age")) {
                // This is actually good practice (session cookie dies with browser close)
                // But if there's _no_ expiry and it's NOT a session cookie, flag it
            } else if (isSessionCookie && cookieLower.includes("max-age")) {
                const maxAgeMatch = cookie.match(/max-age=(\d+)/i);
                if (maxAgeMatch) {
                    const maxAge = parseInt(maxAgeMatch[1], 10);
                    const thirtyDays = 30 * 24 * 60 * 60;
                    if (maxAge > thirtyDays) {
                        vulnerabilities.push(
                            this.createVulnerability(
                                `Long-Lived Session Cookie: ${cookieName}`,
                                `The session cookie '${cookieName}' has a very long lifetime (${Math.round(maxAge / 86400)} days). ` +
                                `Long-lived session tokens increase the window for token theft.`,
                                context.url,
                                "low",
                                `Max-Age=${maxAge} (${Math.round(maxAge / 86400)} days)`,
                                "Set session cookie lifetime to the minimum needed (e.g., 24 hours for most apps).",
                                "CWE-613"
                            )
                        );
                    }
                }
            }
        }

        return vulnerabilities;
    }

    reset(): void {
        this.reportedCookies.clear();
    }
}
