import { validateConfig, validateScanProfile } from "./config-schema";

describe("config-schema", () => {
    // ─── validateConfig ────────────────────────────────────────────

    describe("validateConfig", () => {
        const validConfig = {
            ai: {
                provider: "openai" as const,
                apiKey: "sk-test",
                defaultModel: "gpt-4",
                enabled: true,
            },
            scan: {
                defaultTimeout: 30000,
                maxThreads: 5,
                userAgent: "KramScan/0.1.0",
                followRedirects: true,
                verifySSL: true,
                rateLimitPerSecond: 5,
                strictScope: true,
                profiles: {
                    quick: { depth: 1, timeout: 15000, maxPages: 10, maxLinksPerPage: 20 },
                },
                defaultProfile: "balanced",
            },
            report: {
                defaultFormat: "word" as const,
                companyName: "Test Corp",
                includeScreenshots: false,
                severityThreshold: "low" as const,
            },
            skills: {
                sqli: { enabled: true },
                xss: { enabled: true },
            },
        };

        it("should accept a valid config", () => {
            const result = validateConfig(validConfig);
            expect(result.ai.provider).toBe("openai");
            expect(result.scan.maxThreads).toBe(5);
        });

        it("should reject invalid AI provider", () => {
            expect(() =>
                validateConfig({
                    ...validConfig,
                    ai: { ...validConfig.ai, provider: "invalid_provider" },
                })
            ).toThrow();
        });

        it("should reject invalid report format", () => {
            expect(() =>
                validateConfig({
                    ...validConfig,
                    report: { ...validConfig.report, defaultFormat: "pdf" },
                })
            ).toThrow();
        });

        it("should reject timeout below minimum", () => {
            expect(() =>
                validateConfig({
                    ...validConfig,
                    scan: { ...validConfig.scan, defaultTimeout: 500 },
                })
            ).toThrow();
        });

        it("should reject maxThreads above maximum", () => {
            expect(() =>
                validateConfig({
                    ...validConfig,
                    scan: { ...validConfig.scan, maxThreads: 25 },
                })
            ).toThrow();
        });

        it("should reject maxThreads below minimum", () => {
            expect(() =>
                validateConfig({
                    ...validConfig,
                    scan: { ...validConfig.scan, maxThreads: 0 },
                })
            ).toThrow();
        });

        it("should accept all valid AI providers", () => {
            const providers = ["openai", "anthropic", "gemini", "openrouter", "mistral", "kimi", "groq"];
            for (const provider of providers) {
                expect(() =>
                    validateConfig({
                        ...validConfig,
                        ai: { ...validConfig.ai, provider },
                    })
                ).not.toThrow();
            }
        });

        it("should accept all valid severity thresholds", () => {
            const thresholds = ["info", "low", "medium", "high", "critical"];
            for (const threshold of thresholds) {
                expect(() =>
                    validateConfig({
                        ...validConfig,
                        report: { ...validConfig.report, severityThreshold: threshold },
                    })
                ).not.toThrow();
            }
        });
    });

    // ─── validateScanProfile ───────────────────────────────────────

    describe("validateScanProfile", () => {
        it("should accept a valid scan profile", () => {
            const profile = validateScanProfile({
                depth: 2,
                timeout: 30000,
                maxPages: 50,
                maxLinksPerPage: 30,
            });

            expect(profile.depth).toBe(2);
            expect(profile.maxPages).toBe(50);
        });

        it("should reject depth below minimum", () => {
            expect(() =>
                validateScanProfile({
                    depth: 0,
                    timeout: 30000,
                    maxPages: 50,
                    maxLinksPerPage: 30,
                })
            ).toThrow();
        });

        it("should reject depth above maximum", () => {
            expect(() =>
                validateScanProfile({
                    depth: 6,
                    timeout: 30000,
                    maxPages: 50,
                    maxLinksPerPage: 30,
                })
            ).toThrow();
        });

        it("should reject timeout below minimum", () => {
            expect(() =>
                validateScanProfile({
                    depth: 2,
                    timeout: 500,
                    maxPages: 50,
                    maxLinksPerPage: 30,
                })
            ).toThrow();
        });

        it("should reject maxPages below minimum", () => {
            expect(() =>
                validateScanProfile({
                    depth: 2,
                    timeout: 30000,
                    maxPages: 0,
                    maxLinksPerPage: 30,
                })
            ).toThrow();
        });

        it("should accept boundary values", () => {
            expect(() =>
                validateScanProfile({
                    depth: 1,
                    timeout: 1000,
                    maxPages: 1,
                    maxLinksPerPage: 1,
                })
            ).not.toThrow();

            expect(() =>
                validateScanProfile({
                    depth: 5,
                    timeout: 120000,
                    maxPages: 1000,
                    maxLinksPerPage: 500,
                })
            ).not.toThrow();
        });
    });
});
