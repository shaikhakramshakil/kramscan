import { BaseVulnerabilityPlugin, PluginContext, VulnerabilityTestResult } from "../types";
import { Vulnerability } from "../../core/vulnerability-detector";

export class DirectoryTraversalPlugin extends BaseVulnerabilityPlugin {
    readonly name = "Directory Traversal / LFI Detector";
    readonly type = "lfi" as const;
    readonly description = "Tests for path traversal and local file inclusion vulnerabilities";

    /**
     * Payloads designed to detect directory traversal / LFI.
     * Each payload targets a well-known file with distinctive content markers.
     */
    private readonly payloads: Array<{
        payload: string;
        markers: string[];
        os: string;
    }> = [
            // Linux/Unix path traversal
            {
                payload: "../../../etc/passwd",
                markers: ["root:", "/bin/bash", "/bin/sh", "nobody:"],
                os: "linux",
            },
            {
                payload: "....//....//....//etc/passwd",
                markers: ["root:", "/bin/bash", "/bin/sh"],
                os: "linux",
            },
            {
                payload: "..%2F..%2F..%2Fetc%2Fpasswd",
                markers: ["root:", "/bin/bash", "/bin/sh"],
                os: "linux",
            },
            {
                payload: "%2e%2e/%2e%2e/%2e%2e/etc/passwd",
                markers: ["root:", "/bin/bash"],
                os: "linux",
            },
            {
                payload: "....\\\\....\\\\....\\\\etc\\\\passwd",
                markers: ["root:", "/bin/bash"],
                os: "linux",
            },
            // Windows path traversal
            {
                payload: "..\\..\\..\\windows\\win.ini",
                markers: ["[fonts]", "[extensions]", "[mci extensions]"],
                os: "windows",
            },
            {
                payload: "..%5C..%5C..%5Cwindows%5Cwin.ini",
                markers: ["[fonts]", "[extensions]"],
                os: "windows",
            },
            {
                payload: "../../../windows/win.ini",
                markers: ["[fonts]", "[extensions]"],
                os: "windows",
            },
            // Null byte injection (legacy PHP)
            {
                payload: "../../../etc/passwd%00",
                markers: ["root:", "/bin/bash"],
                os: "linux",
            },
            // Double encoding
            {
                payload: "%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd",
                markers: ["root:", "/bin/bash"],
                os: "linux",
            },
        ];

    async testParameter(
        context: PluginContext,
        param: string,
        value: string
    ): Promise<VulnerabilityTestResult> {
        for (const { payload, markers, os } of this.payloads) {
            try {
                const testUrl = this.buildTestUrl(context.url, param, payload);

                const response = await context.page.evaluate(async (url: string) => {
                    try {
                        const res = await fetch(url, {
                            method: "GET",
                            redirect: "follow",
                            credentials: "omit",
                        });
                        const text = await res.text();
                        return { status: res.status, body: text.substring(0, 5000) };
                    } catch {
                        return { status: 0, body: "" };
                    }
                }, testUrl);

                if (response.status >= 200 && response.status < 500) {
                    const bodyLower = response.body.toLowerCase();
                    const matchedMarkers = markers.filter(m =>
                        bodyLower.includes(m.toLowerCase())
                    );

                    if (matchedMarkers.length >= 2) {
                        return this.success(
                            this.createVulnerability(
                                "Directory Traversal / Local File Inclusion",
                                `The parameter '${param}' is vulnerable to directory traversal. ` +
                                `An attacker can read arbitrary files from the server filesystem (${os}).`,
                                context.url,
                                "critical",
                                `Payload: ${param}=${payload} — matched markers: ${matchedMarkers.join(", ")}`,
                                "Validate and sanitize all file path inputs. Use a whitelist of allowed files/directories. " +
                                "Never pass user input directly to file system operations. " +
                                "Use path.resolve() and verify the resolved path starts with the expected base directory.",
                                "CWE-22"
                            )
                        );
                    }
                }
            } catch {
                // Skip this payload, try next
            }
        }

        return this.failure();
    }

    private buildTestUrl(baseUrl: string, param: string, payload: string): string {
        const url = new URL(baseUrl);
        url.searchParams.set(param, payload);
        return url.toString();
    }
}
