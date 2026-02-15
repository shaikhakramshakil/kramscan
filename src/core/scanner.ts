import puppeteer, { Browser, Page } from "puppeteer";
import { EventEmitter } from "events";
import { VulnerabilityDetector, ScanResult, Vulnerability } from "./vulnerability-detector";
import { getConfig, getScanProfile, ScanProfile } from "./config";
import { logger } from "../utils/logger";
import { pluginManager, PluginExecutionResult } from "../plugins";
import { XSSPlugin, SQLInjectionPlugin, SecurityHeadersPlugin, SensitiveDataPlugin, CSRFPlugin } from "../plugins";

export interface ScanEventMap {
    "scan:start": { target: string; options: ScanOptions };
    "scan:complete": { result: ScanResult };
    "scan:error": { error: Error };
    "crawl:start": { url: string; depth: number };
    "crawl:page": { url: string; crawledCount: number; maxPages: number };
    "crawl:complete": { url: string };
    "crawl:error": { url: string; error: Error };
    "form:test": { url: string; formCount: number };
    "vuln:found": { vulnerability: Vulnerability };
    "plugin:execute": { plugin: string; url: string; duration: number };
    "progress": { stage: string; current: number; total: number; message?: string };
}

export interface ScanOptions {
    depth?: number;
    timeout?: number;
    headless?: boolean;
    maxPages?: number;
    maxLinksPerPage?: number;
    include?: string[];
    exclude?: string[];
    strictScope?: boolean;
    profile?: string;
}

interface RateLimiter {
    lastRequestTime: number;
    minInterval: number;
}

interface RetryConfig {
    maxRetries: number;
    baseDelay: number;
    maxDelay: number;
}

export interface ScanError {
    url: string;
    error: string;
    plugin?: string;
}

export class Scanner extends EventEmitter {
    private browser: Browser | null = null;
    private detector: VulnerabilityDetector;
    private visitedUrls: Set<string> = new Set();
    private crawledUrls: number = 0;
    private testedForms: number = 0;
    private requestsMade: number = 0;
    private headersChecked: Set<string> = new Set();
    private rateLimiter: RateLimiter;
    private retryConfig: RetryConfig;
    private maxConcurrency = 5;
    private strictScope = true;
    private baseOrigin: string | null = null;
    private maxPages = 30;
    private maxLinksPerPage = 50;
    private includePatterns: RegExp[] = [];
    private excludePatterns: RegExp[] = [];
    private userAgent = "KramScan/0.1.0";
    private scanErrors: ScanError[] = [];
    private pluginErrors: Map<string, Array<{ url: string; error: string }>> = new Map();
    private usePlugins: boolean = true;

    constructor(usePlugins: boolean = true) {
        super();
        this.usePlugins = usePlugins;
        this.detector = new VulnerabilityDetector();
        this.detector.setOnVulnerabilityFound((vuln) => {
            this.emit("vuln:found", { vulnerability: vuln });
        });
        this.rateLimiter = {
            lastRequestTime: 0,
            minInterval: 200,
        };
        this.retryConfig = {
            maxRetries: 3,
            baseDelay: 1000,
            maxDelay: 10000,
        };
        
        // Register default plugins
        if (usePlugins) {
            this.registerDefaultPlugins();
        }
    }

    private registerDefaultPlugins(): void {
        pluginManager.register(new XSSPlugin());
        pluginManager.register(new SQLInjectionPlugin());
        pluginManager.register(new SecurityHeadersPlugin());
        pluginManager.register(new SensitiveDataPlugin());
        pluginManager.register(new CSRFPlugin());
    }

    // Type-safe event emitter methods
    emit<K extends keyof ScanEventMap>(event: K, data: ScanEventMap[K]): boolean {
        return super.emit(event, data);
    }

    on<K extends keyof ScanEventMap>(event: K, listener: (data: ScanEventMap[K]) => void): this {
        return super.on(event, listener);
    }

    once<K extends keyof ScanEventMap>(event: K, listener: (data: ScanEventMap[K]) => void): this {
        return super.once(event, listener);
    }

    getScanErrors(): ScanError[] {
        return [...this.scanErrors];
    }

    getPluginErrors(): Map<string, Array<{ url: string; error: string }>> {
        return new Map(this.pluginErrors);
    }

    private async initializeScanSettings(targetUrl: string, options: ScanOptions): Promise<void> {
        const config = await getConfig();
        this.rateLimiter.minInterval = 1000 / (config.scan.rateLimitPerSecond || 5);
        this.maxConcurrency = Math.max(1, config.scan.maxThreads || 5);
        this.strictScope = options.strictScope ?? (config.scan.strictScope ?? true);
        this.baseOrigin = new URL(targetUrl).origin;
        this.userAgent = config.scan.userAgent || this.userAgent;

        // Load scan profile
        const profileName = options.profile || config.scan.defaultProfile || "balanced";
        const profile: ScanProfile | undefined = await getScanProfile(profileName);
        
        this.maxPages = Math.max(1, options.maxPages ?? profile?.maxPages ?? 30);
        this.maxLinksPerPage = Math.max(1, options.maxLinksPerPage ?? profile?.maxLinksPerPage ?? 50);

        const compileList = (values?: string[]): RegExp[] => {
            if (!values || values.length === 0) return [];
            const patterns: RegExp[] = [];
            for (const raw of values) {
                try {
                    patterns.push(new RegExp(raw));
                } catch {
                    logger.warn(`Invalid regex pattern ignored: ${raw}`);
                }
            }
            return patterns;
        };

        this.includePatterns = compileList(options.include);
        this.excludePatterns = compileList(options.exclude);
    }

    private resetScanState(): void {
        this.detector.clear();
        this.visitedUrls.clear();
        this.crawledUrls = 0;
        this.testedForms = 0;
        this.requestsMade = 0;
        this.headersChecked.clear();
        this.scanErrors = [];
        this.pluginErrors.clear();
        this.rateLimiter.lastRequestTime = 0;
        this.removeAllListeners();
        
        // Reset plugin manager state
        if (this.usePlugins) {
            const securityHeadersPlugin = pluginManager.getPlugin("Security Headers Analyzer") as SecurityHeadersPlugin | undefined;
            if (securityHeadersPlugin && typeof securityHeadersPlugin.reset === "function") {
                securityHeadersPlugin.reset();
            }
        }
    }

    async initialize(options: ScanOptions = {}): Promise<void> {
        const headless = options.headless ?? true;

        this.browser = await puppeteer.launch({
            headless,
            args: [
                "--no-sandbox",
                "--disable-setuid-sandbox",
                "--disable-web-security",
                "--disable-features=IsolateOrigins,site-per-process",
            ],
        });

        logger.debug("Browser initialized");
    }

    async scan(targetUrl: string, options: ScanOptions = {}): Promise<ScanResult> {
        const startTime = Date.now();
        const depth = options.depth ?? 2;
        const timeout = options.timeout ?? 30000;

        this.resetScanState();
        await this.initializeScanSettings(targetUrl, options);

        if (!this.browser) {
            await this.initialize(options);
        }

        this.emit("scan:start", { target: targetUrl, options });
        logger.info(`Starting scan of ${targetUrl} (depth: ${depth}, timeout: ${timeout}ms)`);

        try {
            await this.crawl(targetUrl, depth, timeout);
        } catch (error) {
            const err = error as Error;
            this.emit("scan:error", { error: err });
            logger.error(`Scan failed: ${err.message}`);
            throw error;
        } finally {
            await this.close();
        }

        const duration = Date.now() - startTime;

        const result: ScanResult = {
            target: targetUrl,
            timestamp: new Date().toISOString(),
            duration,
            vulnerabilities: this.detector.getVulnerabilities(),
            summary: this.detector.getSummary(),
            metadata: {
                crawledUrls: this.crawledUrls,
                testedForms: this.testedForms,
                requestsMade: this.requestsMade,
            },
        };

        this.emit("scan:complete", { result });
        return result;
    }

    private async applyRateLimit(): Promise<void> {
        const now = Date.now();
        const timeSinceLastRequest = now - this.rateLimiter.lastRequestTime;
        
        if (timeSinceLastRequest < this.rateLimiter.minInterval) {
            const delay = this.rateLimiter.minInterval - timeSinceLastRequest;
            await new Promise(resolve => setTimeout(resolve, delay));
        }
        
        this.rateLimiter.lastRequestTime = Date.now();
    }

    private async withRetry<T>(
        operation: () => Promise<T>,
        context: string
    ): Promise<T> {
        let lastError: Error | null = null;
        
        for (let attempt = 0; attempt <= this.retryConfig.maxRetries; attempt++) {
            try {
                await this.applyRateLimit();
                return await operation();
            } catch (error) {
                lastError = error as Error;
                
                if (attempt < this.retryConfig.maxRetries) {
                    const delay = Math.min(
                        this.retryConfig.baseDelay * Math.pow(2, attempt),
                        this.retryConfig.maxDelay
                    );
                    logger.debug(`Retry ${attempt + 1}/${this.retryConfig.maxRetries} for ${context} after ${delay}ms`);
                    await new Promise(resolve => setTimeout(resolve, delay));
                }
            }
        }
        
        throw new Error(`Failed after ${this.retryConfig.maxRetries + 1} attempts: ${lastError?.message}`);
    }

    private async createInstrumentedPage(): Promise<Page> {
        const page = await this.browser!.newPage();
        await page.setUserAgent(this.userAgent);
        await page.setRequestInterception(true);
        page.on("request", (request) => {
            this.requestsMade++;
            const resourceType = request.resourceType();
            if (resourceType === "image" || resourceType === "font" || resourceType === "media") {
                request.abort();
                return;
            }
            request.continue();
        });
        return page;
    }

    private async runInIsolatedPage<T>(
        operation: (page: Page) => Promise<T>
    ): Promise<T> {
        const page = await this.createInstrumentedPage();
        try {
            return await operation(page);
        } finally {
            await page.close().catch((err) => logger.debug(`Error closing page: ${err.message}`));
        }
    }

    private async crawl(url: string, depth: number, timeout: number): Promise<void> {
        if (this.crawledUrls >= this.maxPages) {
            return;
        }

        if (depth === 0 || this.visitedUrls.has(url)) {
            return;
        }

        this.visitedUrls.add(url);
        this.crawledUrls++;

        this.emit("crawl:start", { url, depth });
        this.emit("crawl:page", { url, crawledCount: this.crawledUrls, maxPages: this.maxPages });
        this.emit("progress", { 
            stage: "crawling", 
            current: this.crawledUrls, 
            total: this.maxPages,
            message: `Crawling: ${url}` 
        });

        const page = await this.createInstrumentedPage();

        try {
            const response = await this.withRetry(
                () => page.goto(url, { waitUntil: "networkidle2", timeout }),
                `crawl ${url}`
            );

            if (!response) {
                logger.warn(`No response from ${url}`);
                this.scanErrors.push({ url, error: "No response" });
                return;
            }

            const content = await page.content();
            const headers = response.headers();

            // Analyze with plugins
            if (this.usePlugins) {
                await this.runPlugins(page, url, content, headers, timeout);
            } else {
                // Fallback to legacy detector
                await this.runLegacyDetection(page, url, content, headers, timeout);
            }

            if (depth > 1) {
                const links = await this.extractLinks(page, url);
                for (const link of links) {
                    await this.crawl(link, depth - 1, timeout);
                }
            }

            this.emit("crawl:complete", { url });
        } catch (error) {
            const err = error as Error;
            this.scanErrors.push({ url, error: err.message });
            this.emit("crawl:error", { url, error: err });
            logger.error(`Error crawling ${url}: ${err.message}`);
        } finally {
            await page.close().catch(err => logger.debug(`Error closing page: ${err.message}`));
        }
    }

    private async runPlugins(
        page: Page, 
        url: string, 
        content: string, 
        headers: Record<string, string>,
        timeout: number
    ): Promise<void> {
        const context = {
            page,
            url,
            baseUrl: this.baseOrigin || url,
            timeout,
            userAgent: this.userAgent,
        };

        // Analyze headers
        const host = new URL(url).host;
        if (!this.headersChecked.has(host)) {
            const headerResults = await pluginManager.analyzeHeaders(context, headers);
            this.processPluginResults(headerResults);
            this.headersChecked.add(host);
        }

        // Analyze content
        const contentResults = await pluginManager.analyzeContent(context, content);
        this.processPluginResults(contentResults);

        // Test URL parameters
        await this.testUrlParametersWithPlugins(page, url, timeout);

        // Test forms
        await this.testFormsWithPlugins(page, url, timeout);
    }

    private processPluginResults(results: PluginExecutionResult[]): void {
        for (const result of results) {
            // Track plugin errors
            if (result.errors.length > 0) {
                const existing = this.pluginErrors.get(result.plugin) || [];
                this.pluginErrors.set(result.plugin, [...existing, ...result.errors]);
            }

            // Add vulnerabilities to detector
            for (const vuln of result.vulnerabilities) {
                this.detector.addVulnerability(vuln);
            }

            // Emit event for monitoring
            this.emit("plugin:execute", {
                plugin: result.plugin,
                url: result.errors[0]?.url || "",
                duration: result.duration,
            });
        }
    }

    private async testUrlParametersWithPlugins(page: Page, url: string, timeout: number): Promise<void> {
        try {
            const urlObj = new URL(url);
            const params = Array.from(urlObj.searchParams.keys());

            for (const param of params) {
                const value = urlObj.searchParams.get(param) || "";
                const context = {
                    page,
                    url,
                    baseUrl: this.baseOrigin || url,
                    timeout,
                    userAgent: this.userAgent,
                };

                const results = await pluginManager.testParameter(context, param, value);
                this.processPluginResults(results);
            }
        } catch (error) {
            logger.debug(`Error testing URL parameters with plugins: ${(error as Error).message}`);
        }
    }

    private async testFormsWithPlugins(page: Page, url: string, timeout: number): Promise<void> {
        const forms = await page.$$("form");

        if (forms.length > 0) {
            this.emit("form:test", { url, formCount: forms.length });
        }

        for (const form of forms) {
            this.testedForms++;

            try {
                const inputs = await form.$$eval("input, textarea, select", (elements) =>
                    elements.map((el) => ({
                        name: el.getAttribute("name") || "",
                        type: el.getAttribute("type") || "text",
                        value: (el as HTMLInputElement | HTMLTextAreaElement | HTMLSelectElement).value || "",
                    })).filter((input) => input.name && input.type !== "hidden" && input.type !== "submit")
                ) as Array<{ name: string; type: string; value: string }>;

                const formData = {
                    action: await form.evaluate((el) => (el as HTMLFormElement).action || ""),
                    method: await form.evaluate((el) => (el as HTMLFormElement).method || "GET"),
                    inputs,
                };

                const context = {
                    page,
                    url,
                    baseUrl: this.baseOrigin || url,
                    timeout,
                    userAgent: this.userAgent,
                };

                const results = await pluginManager.testFormInput(context, formData);
                this.processPluginResults(results);
            } catch (error) {
                logger.debug(`Error testing form with plugins: ${(error as Error).message}`);
            }
        }
    }

    private async runLegacyDetection(
        page: Page, 
        url: string, 
        content: string, 
        headers: Record<string, string>,
        timeout: number
    ): Promise<void> {
        const host = new URL(url).host;
        if (!this.headersChecked.has(host)) {
            this.detector.analyzeSecurityHeaders(url, headers);
            this.headersChecked.add(host);
        }

        this.detector.detectSensitiveData(url, content);
        this.detector.detectInfoDisclosure(url, content);

        await this.testFormsLegacy(page, url, timeout);
        await this.testUrlParametersLegacy(page, url, timeout);
    }

    private async testFormsLegacy(page: Page, url: string, timeout: number): Promise<void> {
        const forms = await page.$$("form");

        if (forms.length > 0) {
            this.emit("form:test", { url, formCount: forms.length });
        }

        for (const form of forms) {
            this.testedForms++;

            try {
                const formHtml = await form.evaluate((el) => el.outerHTML);
                this.detector.detectCSRF(url, formHtml);

                const inputs = await form.$$("input, textarea, select");
                const inputTests: Array<() => Promise<void>> = [];

                for (const input of inputs) {
                    const name = await input.evaluate((el) => el.getAttribute("name"));
                    const type = await input.evaluate((el) => el.getAttribute("type"));

                    if (!name || type === "hidden" || type === "submit") {
                        continue;
                    }

                    inputTests.push(() =>
                        this.runInIsolatedPage((testPage) =>
                            this.testXSS(testPage, url, name, timeout)
                        )
                    );
                    inputTests.push(() =>
                        this.runInIsolatedPage((testPage) =>
                            this.testSQLi(testPage, url, name, timeout)
                        )
                    );
                }

                await this.runWithConcurrency(inputTests, this.maxConcurrency);
            } catch (error) {
                logger.debug(`Error testing form: ${(error as Error).message}`);
            }
        }
    }

    private async testUrlParametersLegacy(page: Page, baseUrl: string, timeout: number): Promise<void> {
        try {
            const url = new URL(baseUrl);
            const params = Array.from(url.searchParams.keys());

            for (const param of params) {
                await this.testXSS(page, baseUrl, param, timeout);
                await this.testSQLi(page, baseUrl, param, timeout);
            }
        } catch (error) {
            logger.debug(`Error testing URL parameters: ${(error as Error).message}`);
        }
    }

    private async runWithConcurrency<T>(
        tasks: Array<() => Promise<T>>,
        maxConcurrency: number
    ): Promise<void> {
        if (tasks.length === 0) {
            return;
        }

        const workerCount = Math.max(1, Math.min(maxConcurrency, tasks.length));
        let nextIndex = 0;

        const workers = Array.from({ length: workerCount }, async () => {
            while (nextIndex < tasks.length) {
                const currentTask = tasks[nextIndex++];
                try {
                    await currentTask();
                } catch (error) {
                    logger.debug(`Task failed: ${(error as Error).message}`);
                }
            }
        });

        await Promise.all(workers);
    }

    private async testXSS(page: Page, url: string, param: string, timeout: number): Promise<void> {
        const payloads = [
            "<script>alert('XSS')</script>",
            '"><script>alert(1)</script>',
            "<img src=x onerror=alert(1)>",
        ];

        for (const payload of payloads) {
            try {
                const testUrl = this.buildTestUrl(url, param, payload);
                
                await this.withRetry(
                    () => page.goto(testUrl, { waitUntil: "networkidle2", timeout }),
                    `XSS test for ${param}`
                );

                const content = await page.content();
                this.detector.detectXSS(url, param, payload, content);
            } catch (error) {
                logger.debug(`XSS test failed for ${param}: ${(error as Error).message}`);
            }
        }
    }

    private async testSQLi(page: Page, url: string, param: string, timeout: number): Promise<void> {
        const errorBasedPayloads = ["'", "1' OR '1'='1", "' OR 1=1--"];

        for (const payload of errorBasedPayloads) {
            try {
                const testUrl = this.buildTestUrl(url, param, payload);
                
                await this.withRetry(
                    () => page.goto(testUrl, { waitUntil: "networkidle2", timeout }),
                    `SQLi test for ${param}`
                );

                const content = await page.content();
                this.detector.detectSQLi(url, param, content);
            } catch (error) {
                logger.debug(`SQLi test failed for ${param}: ${(error as Error).message}`);
            }
        }
    }

    private buildTestUrl(baseUrl: string, param: string, value: string): string {
        try {
            const url = new URL(baseUrl);
            url.searchParams.set(param, value);
            return url.toString();
        } catch (error) {
            throw new Error(`Invalid URL: ${baseUrl}`);
        }
    }

    private async extractLinks(page: Page, baseUrl: string): Promise<string[]> {
        const links = await page.$$eval("a[href]", (anchors: Element[]) =>
            (anchors as HTMLAnchorElement[]).map((a) => a.getAttribute("href")).filter(Boolean)
        );

        const absoluteLinks: string[] = [];
        const baseOrigin = this.baseOrigin || new URL(baseUrl).origin;

        const isAllowedByPatterns = (candidate: URL): boolean => {
            const asString = candidate.toString();
            for (const pattern of this.excludePatterns) {
                if (pattern.test(asString)) {
                    return false;
                }
            }

            if (this.includePatterns.length > 0) {
                return this.includePatterns.some((pattern) => pattern.test(asString));
            }

            return true;
        };

        for (const link of links) {
            if (!link) continue;

            try {
                const absolute = new URL(link, baseUrl);
                if (!["http:", "https:"].includes(absolute.protocol)) {
                    continue;
                }

                if (this.strictScope && absolute.origin !== baseOrigin) {
                    continue;
                }

                if (!isAllowedByPatterns(absolute)) {
                    continue;
                }

                absolute.hash = "";
                absoluteLinks.push(absolute.toString());
            } catch {
                // Skip invalid URLs
            }
        }

        const deduped = [...new Set(absoluteLinks)];
        return deduped.slice(0, this.maxLinksPerPage);
    }

    async close(): Promise<void> {
        if (this.browser) {
            try {
                await this.browser.close();
            } catch (error) {
                logger.debug(`Error closing browser: ${(error as Error).message}`);
            } finally {
                this.browser = null;
            }
        }
    }
}
