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

    // Start crawling
    await this.crawl(targetUrl, depth, timeout);

    // Close browser
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
      // Set up request interception
      await page.setRequestInterception(true);
      page.on("request", (request) => {
        this.requestsMade++;
        request.continue();
      });

      // Navigate to page
      const response = await page.goto(url, {
        waitUntil: "networkidle2",
        timeout,
      });

      if (!response) {
        logger.warn(`No response from ${url}`);
        return;
      }

      // Get response headers
      const headers = response.headers();
      this.detector.analyzeSecurityHeaders(url, headers);

      // Get page content
      const content = await page.content();

      // Check for sensitive data
      this.detector.detectSensitiveData(url, content);

      // Find and test forms
      await this.testForms(page, url, timeout);

      // Find links and crawl deeper
      if (depth > 1) {
        const links = await this.extractLinks(page, url);
        for (const link of links.slice(0, 10)) {
          // Limit to 10 links per page
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

      // Get form HTML for CSRF detection
      const formHtml = await form.evaluate((el) => el.outerHTML);
      this.detector.detectCSRF(url, formHtml);

      // Find input fields
      const inputs = await form.$$("input, textarea");

      for (const input of inputs) {
        const name = await input.evaluate((el) => el.getAttribute("name"));
        const type = await input.evaluate((el) => el.getAttribute("type"));

        if (!name || type === "hidden" || type === "submit") {
          continue;
        }

        // Test for XSS
        await this.testXSS(page, url, name, timeout);

        // Test for SQLi
        await this.testSQLi(page, url, name, timeout);
      }
    }
  }

  private async testXSS(page: Page, url: string, param: string, timeout: number): Promise<void> {
    const payloads = [
      "<script>alert('XSS')</script>",
      '"><script>alert(1)</script>',
      "<img src=x onerror=alert(1)>",
    ];

    for (const payload of payloads) {
      try {
        // Try to inject payload
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
    const payloads = ["'", "1' OR '1'='1", "1; DROP TABLE users--", "' OR 1=1--"];

    for (const payload of payloads) {
      try {
        const testUrl = this.buildTestUrl(url, param, payload);
        await page.goto(testUrl, { waitUntil: "networkidle2", timeout });

        const content = await page.content();
        this.detector.detectSQLi(url, param, content);
      } catch (error) {
        logger.debug(`SQLi test failed for ${param}: ${(error as Error).message}`);
      }
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

    const base = new URL(baseUrl);
    const absoluteLinks: string[] = [];

    for (const link of links) {
      if (!link) continue;

      try {
        const absolute = new URL(link, baseUrl);
        // Only crawl same-origin links
        if (absolute.origin === base.origin) {
          absoluteLinks.push(absolute.toString());
        }
      } catch {
        // Invalid URL, skip
      }
    }

    return [...new Set(absoluteLinks)]; // Remove duplicates
  }

  async close(): Promise<void> {
    if (this.browser) {
      await this.browser.close();
      this.browser = null;
    }
  }
}
