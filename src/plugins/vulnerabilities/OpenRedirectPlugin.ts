import { BaseVulnerabilityPlugin, PluginContext } from "../types";
import { Vulnerability } from "../../core/vulnerability-detector";

export class OpenRedirectPlugin extends BaseVulnerabilityPlugin {
    readonly name = "Open Redirect Detector";
    readonly type = "redirect" as const;
    readonly description = "Detects open redirect vulnerabilities in URL parameters";

    private readonly redirectParams = [
        "url", "redirect", "redirect_url", "redirect_uri", "return", "return_url",
        "returnTo", "next", "next_url", "goto", "target", "dest", "destination",
        "rurl", "redir", "out", "continue", "forward", "callback", "callback_url",
        "path", "ref", "site", "view", "to", "link", "logout_redirect",
    ];

    private readonly testDomains = [
        "https://evil.com",
        "//evil.com",
        "https://evil.com%2f%2f",
        "/\\evil.com",
        "https:evil.com",
    ];

    async analyzeContent(context: PluginContext, content: string): Promise<Vulnerability[]> {
        const vulnerabilities: Vulnerability[] = [];
        const url = new URL(context.url);

        // Check if the current URL uses any redirect-like parameters
        for (const param of this.redirectParams) {
            const value = url.searchParams.get(param);
            if (value) {
                // Current URL has a redirect param — test it
                for (const testDomain of this.testDomains) {
                    try {
                        const testUrl = new URL(context.url);
                        testUrl.searchParams.set(param, testDomain);

                        const result = await context.page.evaluate(async (targetUrl: string) => {
                            try {
                                const res = await fetch(targetUrl, {
                                    method: "GET",
                                    redirect: "manual",
                                    credentials: "omit",
                                });
                                const location = res.headers.get("location") || "";
                                return {
                                    status: res.status,
                                    location,
                                };
                            } catch {
                                return { status: 0, location: "" };
                            }
                        }, testUrl.toString());

                        if (
                            result.status >= 300 && result.status < 400 &&
                            result.location.includes("evil.com")
                        ) {
                            vulnerabilities.push(
                                this.createVulnerability(
                                    "Open Redirect",
                                    `The parameter '${param}' allows redirection to arbitrary external URLs. ` +
                                    `Attackers can use this for phishing by crafting legitimate-looking URLs that redirect to malicious sites.`,
                                    context.url,
                                    "medium",
                                    `${param}=${testDomain} → Location: ${result.location}`,
                                    "Validate redirect URLs against a whitelist of allowed domains. " +
                                    "Use relative paths instead of full URLs. " +
                                    "Never redirect to user-supplied URLs without validation.",
                                    "CWE-601"
                                )
                            );
                            break; // One proof is enough for this param
                        }
                    } catch {
                        // Skip this test
                    }
                }
            }
        }

        return vulnerabilities;
    }
}
