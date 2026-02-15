import puppeteer, { Browser, Page } from "puppeteer";
import { VulnerabilityDetector, ScanResult } from "./vulnerability-detector";
import { getConfig } from "./config";
import { logger } from "../utils/logger";

export interface ScanOptions {
  depth?: number;
  timeout?: number;
  headless?: boolean;
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

  private async initializeRateLimiter(): Promise<void> {
    const config = await getConfig();
    this.rateLimiter.minInterval = 1000 / (config.scan.rateLimitPerSecond || 5);
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

    await this.initializeRateLimiter();

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

  private async crawl(url: string, depth: number, timeout: number): Promise<void> {
    if (depth === 0 || this.visitedUrls.has(url)) {
      return;
    }

    this.visitedUrls.add(url);
    this.crawledUrls++;

    const page = await this.browser!.newPage();

    try {
      await page.setRequestInterception(true);
      page.on("request", (request) => {
        this.requestsMade++;
        request.continue();
      });

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
        for (const link of links.slice(0, 10)) {
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
    const config = await getConfig();
    const maxConcurrency = config.scan.maxThreads || 5;

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

          inputTests.push(() => this.testXSS(page, url, name, timeout));
          inputTests.push(() => this.testSQLi(page, url, name, timeout));
          inputTests.push(() => this.testLFI(page, url, name, timeout));
          inputTests.push(() => this.testCMDI(page, url, name, timeout));
        }

        // Execute tests with concurrency control
        await this.runWithConcurrency(inputTests, maxConcurrency);
      } catch (error) {
        logger.debug(`Error testing form: ${(error as Error).message}`);
      }
    }
  }

  private async runWithConcurrency<T>(
    tasks: Array<() => Promise<T>>,
    maxConcurrency: number
  ): Promise<void> {
    const executing: Promise<T | undefined>[] = [];

    for (const task of tasks) {
      const promise = task().catch((error): undefined => {
        logger.debug(`Task failed: ${(error as Error).message}`);
        return undefined;
      });

      executing.push(promise);

      if (executing.length >= maxConcurrency) {
        await Promise.race(executing);
        executing.splice(executing.findIndex(p => p === promise), 1);
      }
    }

    await Promise.all(executing);
  }

  private async testUrlParameters(page: Page, baseUrl: string, timeout: number): Promise<void> {
    try {
      const url = new URL(baseUrl);
      const params = Array.from(url.searchParams.keys());

      for (const param of params) {
        await this.testIDOR(baseUrl, param, timeout);
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

    try {
      await page.content();
    } catch (error) {
      logger.debug(`Could not get original response for SQLi test: ${(error as Error).message}`);
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

    const startTime = Date.now();
    for (const payload of timeBasedPayloads) {
      try {
        const sanitizedPayload = this.sanitizePayload(payload);
        const testUrl = this.buildTestUrl(url, param, sanitizedPayload);
        
        await this.withRetry(
          () => page.goto(testUrl, { waitUntil: "networkidle2", timeout }),
          `Blind SQLi test for ${param}`
        );
        
        const testTime = Date.now() - startTime;
        this.detector.detectBlindSQLi(url, param, 0, testTime);
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

  private async testIDOR(baseUrl: string, param: string, timeout: number): Promise<void> {
    const page = await this.browser!.newPage();
    
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
    } finally {
      await page.close().catch(err => logger.debug(`Error closing page: ${err.message}`));
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

    for (const link of links) {
      if (!link) continue;

      try {
        const absolute = new URL(link, baseUrl);
        if (absolute.origin === new URL(baseUrl).origin) {
          absoluteLinks.push(absolute.toString());
        }
      } catch {
        // Skip invalid URLs
      }
    }

    return [...new Set(absoluteLinks)];
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
