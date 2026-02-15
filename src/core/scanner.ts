import puppeteer, { Browser, Page } from "puppeteer";
import { VulnerabilityDetector, ScanResult } from "./vulnerability-detector";
import { getConfig } from "./config";
import { logger } from "../utils/logger";

export interface ScanOptions {
  depth?: number;
  timeout?: number;
  headless?: boolean;
  maxPages?: number;
  maxLinksPerPage?: number;
  include?: string[];
  exclude?: string[];
  strictScope?: boolean;
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

export class Scanner {
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

  constructor() {
    this.detector = new VulnerabilityDetector();
    this.rateLimiter = {
      lastRequestTime: 0,
      minInterval: 200, // Default: 5 requests per second
    };
    this.retryConfig = {
      maxRetries: 3,
      baseDelay: 1000,
      maxDelay: 10000,
    };
  }

  private async initializeScanSettings(targetUrl: string, options: ScanOptions): Promise<void> {
    const config = await getConfig();
    this.rateLimiter.minInterval = 1000 / (config.scan.rateLimitPerSecond || 5);
    this.maxConcurrency = Math.max(1, config.scan.maxThreads || 5);
    this.strictScope = options.strictScope ?? (config.scan.strictScope ?? true);
    this.baseOrigin = new URL(targetUrl).origin;
    this.maxPages = Math.max(1, options.maxPages ?? 30);
    this.maxLinksPerPage = Math.max(1, options.maxLinksPerPage ?? 50);
    this.userAgent = config.scan.userAgent || this.userAgent;

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
    this.rateLimiter.lastRequestTime = 0;
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

    logger.info(`Starting scan of ${targetUrl} (depth: ${depth}, timeout: ${timeout}ms)`);

    try {
      await this.crawl(targetUrl, depth, timeout);
    } catch (error) {
      logger.error(`Scan failed: ${(error as Error).message}`);
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

  private sanitizePayload(payload: string): string {
    // Prevent null bytes and extreme length payloads
    if (payload.includes('\0')) {
      throw new Error("Payload contains null bytes");
    }
    if (payload.length > 10000) {
      throw new Error("Payload exceeds maximum length of 10000 characters");
    }
    return payload;
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

  private async runInIsolatedPage(
    operation: (page: Page) => Promise<void>
  ): Promise<void> {
    const page = await this.createInstrumentedPage();
    try {
      await operation(page);
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

    const page = await this.createInstrumentedPage();

    try {
      const response = await this.withRetry(
        () => page.goto(url, { waitUntil: "networkidle2", timeout }),
        `crawl ${url}`
      );

      if (!response) {
        logger.warn(`No response from ${url}`);
        return;
      }

      const host = new URL(url).host;
      if (!this.headersChecked.has(host)) {
        this.detector.analyzeSecurityHeaders(url, response.headers());
        this.headersChecked.add(host);
      }

      const content = await page.content();

      this.detector.detectSensitiveData(url, content);
      this.detector.detectInfoDisclosure(url, content);

      await this.testForms(page, url, timeout);

      await this.testUrlParameters(page, url, timeout);

      if (depth > 1) {
        const links = await this.extractLinks(page, url);
        for (const link of links) {
          await this.crawl(link, depth - 1, timeout);
        }
      }
    } catch (error) {
      logger.error(`Error crawling ${url}: ${(error as Error).message}`);
    } finally {
      await page.close().catch(err => logger.debug(`Error closing page: ${err.message}`));
    }
  }

  private async testForms(page: Page, url: string, timeout: number): Promise<void> {
    const forms = await page.$$("form");

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
          inputTests.push(() =>
            this.runInIsolatedPage((testPage) =>
              this.testLFI(testPage, url, name, timeout)
            )
          );
          inputTests.push(() =>
            this.runInIsolatedPage((testPage) =>
              this.testCMDI(testPage, url, name, timeout)
            )
          );
        }

        // Execute tests with concurrency control
        await this.runWithConcurrency(inputTests, this.maxConcurrency);
      } catch (error) {
        logger.debug(`Error testing form: ${(error as Error).message}`);
      }
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

  private async testUrlParameters(page: Page, baseUrl: string, timeout: number): Promise<void> {
    try {
      const url = new URL(baseUrl);
      const params = Array.from(url.searchParams.keys());

      for (const param of params) {
        await this.testIDOR(page, baseUrl, param, timeout);
        await this.testLFI(page, baseUrl, param, timeout);
        await this.testPathTraversal(page, baseUrl, param, timeout);
        await this.testCMDI(page, baseUrl, param, timeout);
        await this.testSSRF(page, baseUrl, param, timeout);
        await this.testOpenRedirect(page, baseUrl, param, timeout);
      }
    } catch (error) {
      logger.debug(`Error testing URL parameters: ${(error as Error).message}`);
    }
  }

  private async testXSS(page: Page, url: string, param: string, timeout: number): Promise<void> {
    const payloads = [
      "<script>alert('XSS')</script>",
      '"><script>alert(1)</script>',
      "<img src=x onerror=alert(1)>",
      "'-alert(1)-'",
      "<svg/onload=alert(1)>",
    ];

    for (const payload of payloads) {
      try {
        const sanitizedPayload = this.sanitizePayload(payload);
        const testUrl = this.buildTestUrl(url, param, sanitizedPayload);
        
        await this.withRetry(
          () => page.goto(testUrl, { waitUntil: "networkidle2", timeout }),
          `XSS test for ${param}`
        );

        const content = await page.content();
        this.detector.detectXSS(url, param, sanitizedPayload, content);
      } catch (error) {
        logger.debug(`XSS test failed for ${param}: ${(error as Error).message}`);
      }
    }
  }

  private async testSQLi(page: Page, url: string, param: string, timeout: number): Promise<void> {
    const errorBasedPayloads = [
      "'",
      "1' OR '1'='1",
      "1; DROP TABLE users--",
      "' OR 1=1--",
      "' UNION SELECT 1--",
      "1' AND '1'='1",
    ];

    const timeBasedPayloads = [
      "' AND SLEEP(5)--",
      "1' AND SLEEP(5)--",
      "'; WAITFOR DELAY '00:00:05'--",
    ];

    let baselineTime = 0;
    try {
      const baselineStart = Date.now();
      await this.withRetry(
        () => page.goto(url, { waitUntil: "networkidle2", timeout }),
        `SQLi baseline for ${param}`
      );
      baselineTime = Date.now() - baselineStart;
    } catch (error) {
      logger.debug(`Could not collect baseline response for SQLi test: ${(error as Error).message}`);
      return;
    }

    for (const payload of errorBasedPayloads) {
      try {
        const sanitizedPayload = this.sanitizePayload(payload);
        const testUrl = this.buildTestUrl(url, param, sanitizedPayload);
        
        await this.withRetry(
          () => page.goto(testUrl, { waitUntil: "networkidle2", timeout }),
          `SQLi error test for ${param}`
        );

        const content = await page.content();
        this.detector.detectSQLi(url, param, content);
      } catch (error) {
        logger.debug(`SQLi test failed for ${param}: ${(error as Error).message}`);
      }
    }

    for (const payload of timeBasedPayloads) {
      try {
        const sanitizedPayload = this.sanitizePayload(payload);
        const testUrl = this.buildTestUrl(url, param, sanitizedPayload);
        const startTime = Date.now();
        
        await this.withRetry(
          () => page.goto(testUrl, { waitUntil: "networkidle2", timeout }),
          `Blind SQLi test for ${param}`
        );
        
        const testTime = Date.now() - startTime;
        this.detector.detectBlindSQLi(url, param, baselineTime, testTime);
      } catch (error) {
        logger.debug(`Blind SQLi test failed for ${param}: ${(error as Error).message}`);
      }
    }
  }

  private async testLFI(page: Page, url: string, param: string, timeout: number): Promise<void> {
    const lfiPayloads = [
      "../../../../etc/passwd",
      "../../../../../../etc/passwd",
      "..\\..\\..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
      "..%2f..%2f..%2f..%2fetc%2fpasswd",
      "/etc/passwd",
      "/etc/shadow",
    ];

    for (const payload of lfiPayloads) {
      try {
        const sanitizedPayload = this.sanitizePayload(payload);
        const testUrl = this.buildTestUrl(url, param, sanitizedPayload);
        
        await this.withRetry(
          () => page.goto(testUrl, { waitUntil: "networkidle2", timeout }),
          `LFI test for ${param}`
        );

        const content = await page.content();
        this.detector.detectLFI(url, param, sanitizedPayload, content);
      } catch (error) {
        logger.debug(`LFI test failed for ${param}: ${(error as Error).message}`);
      }
    }
  }

  private async testPathTraversal(page: Page, url: string, param: string, timeout: number): Promise<void> {
    const traversalPayloads = [
      "../../../../etc/passwd",
      "..%2f..%2f..%2f..%2fetc%2fpasswd",
      "....//....//....//etc/passwd",
      "..\\..\\..\\..\\windows\\system32\\config\\sam",
    ];

    for (const payload of traversalPayloads) {
      try {
        const sanitizedPayload = this.sanitizePayload(payload);
        const testUrl = this.buildTestUrl(url, param, sanitizedPayload);
        
        await this.withRetry(
          () => page.goto(testUrl, { waitUntil: "networkidle2", timeout }),
          `Path traversal test for ${param}`
        );

        const content = await page.content();
        this.detector.detectPathTraversal(url, param, sanitizedPayload, content);
      } catch (error) {
        logger.debug(`Path traversal test failed for ${param}: ${(error as Error).message}`);
      }
    }
  }

  private async testCMDI(page: Page, url: string, param: string, timeout: number): Promise<void> {
    const cmdiPayloads = [
      "; whoami",
      "| whoami",
      "`whoami`",
      "$(whoami)",
      "; id",
      "| id",
      "; cat /etc/passwd",
      "| ls -la",
      "& ping -c 3 127.0.0.1",
      "&& whoami",
    ];

    for (const payload of cmdiPayloads) {
      try {
        const sanitizedPayload = this.sanitizePayload(payload);
        const testUrl = this.buildTestUrl(url, param, sanitizedPayload);
        
        await this.withRetry(
          () => page.goto(testUrl, { waitUntil: "networkidle2", timeout }),
          `CMDI test for ${param}`
        );

        const content = await page.content();
        this.detector.detectCMDI(url, param, sanitizedPayload, content);
      } catch (error) {
        logger.debug(`CMDI test failed for ${param}: ${(error as Error).message}`);
      }
    }
  }

  private async testSSRF(page: Page, url: string, param: string, _timeout: number): Promise<void> {
    const ssrfPayloads = [
      "http://localhost",
      "http://127.0.0.1",
      "http://169.254.169.254/latest/meta-data/",
      "https://metadata.google.internal/",
      "http://0.0.0.0",
      "http://[::1]",
    ];

    for (const payload of ssrfPayloads) {
      try {
        const sanitizedPayload = this.sanitizePayload(payload);
        const testUrl = this.buildTestUrl(url, param, sanitizedPayload);
        
        try {
          await this.withRetry(
            () => page.goto(testUrl, { waitUntil: "networkidle2", timeout: 5000 }),
            `SSRF test for ${param}`
          );
        } catch {
          // Expected to fail for internal URLs
        }

        const content = await page.content();
        this.detector.detectSSRF(url, param, sanitizedPayload, content);
      } catch (error) {
        logger.debug(`SSRF test failed for ${param}: ${(error as Error).message}`);
      }
    }
  }

  private async testOpenRedirect(page: Page, url: string, param: string, _timeout: number): Promise<void> {
    const redirectPayloads = [
      "https://evil.com",
      "https://google.com",
      "//evil.com",
      "///evil.com",
      "https://google.com%23",
      "javascript:alert(1)",
    ];

    for (const payload of redirectPayloads) {
      try {
        const sanitizedPayload = this.sanitizePayload(payload);
        const testUrl = this.buildTestUrl(url, param, sanitizedPayload);
        
        const response = await this.withRetry(
          () => page.goto(testUrl, { waitUntil: "domcontentloaded", timeout: 5000 }),
          `Open redirect test for ${param}`
        );
        
        if (response) {
          const finalUrl = response.url();
          this.detector.detectOpenRedirect(url, param, sanitizedPayload, finalUrl);
        }
      } catch (error) {
        logger.debug(`Open redirect test failed for ${param}: ${(error as Error).message}`);
      }
    }
  }

  private async testIDOR(page: Page, baseUrl: string, param: string, timeout: number): Promise<void> {
    try {
      const url = new URL(baseUrl);
      const originalValue = url.searchParams.get(param);

      if (!originalValue || isNaN(Number(originalValue))) {
        return;
      }

      const originalResponse = await this.withRetry(
        () => page.goto(baseUrl, { waitUntil: "networkidle2", timeout }),
        `IDOR original request for ${param}`
      );
      const originalContent = originalResponse ? await originalResponse.text() : "";

      const modifiedValue = String(Number(originalValue) + 1);
      url.searchParams.set(param, modifiedValue);
      const testUrl = url.toString();

      const testResponse = await this.withRetry(
        () => page.goto(testUrl, { waitUntil: "networkidle2", timeout }),
        `IDOR test request for ${param}`
      );
      const testContent = testResponse ? await testResponse.text() : "";

      this.detector.detectIDOR(baseUrl, param, originalValue, testContent, originalContent);
    } catch (error) {
      logger.debug(`IDOR test failed for ${param}: ${(error as Error).message}`);
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
