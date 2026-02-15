import { Command } from "commander";
import chalk from "chalk";
import puppeteer from "puppeteer";
import { Scanner } from "../core/scanner";
import { ScanResult } from "../core/vulnerability-detector";
import { logger } from "../utils/logger";
import { addScanToIndex } from "../core/scan-index";
import { ensureReportsDirectory, ensureScansDirectory } from "../core/scan-storage";
import fs from "fs/promises";
import path from "path";

export function registerScanCommand(program: Command): void {
    program
        .command("scan <url>")
        .description("Scan a target URL for vulnerabilities")
        .option("--profile <name>", "Scan profile: quick|balanced|deep", "balanced")
        .option("-d, --depth <number>", "Crawl depth (overrides profile)")
        .option("-t, --timeout <ms>", "Request timeout (overrides profile)")
        .option("--max-pages <number>", "Maximum pages to crawl (overrides profile)")
        .option("--max-links-per-page <number>", "Maximum links to follow per page (overrides profile)")
        .option("--include <regex...>", "Only include URLs matching these regex patterns")
        .option("--exclude <regex...>", "Exclude URLs matching these regex patterns")
        .option("--no-pdf", "Disable automatic PDF report generation")
        .option("-o, --output <file>", "Save results to file")
        .option("--headless", "Run in headless mode", true)
        .action(async (url: string, options) => {
            console.log("");
            console.log(chalk.bold.cyan("🔍 Starting Security Scan"));
            console.log(chalk.gray("─".repeat(50)));
            console.log("");

            // Validate URL
            try {
                new URL(url);
            } catch (error) {
                logger.error(`Invalid URL: ${url}`);
                process.exit(1);
            }

            const spinner = logger.spinner("Initializing scanner...");

            try {
                const profile = String(options.profile || "balanced").toLowerCase();
                const profileDefaults: Record<string, { depth: number; timeout: number; maxPages: number; maxLinksPerPage: number }> = {
                    quick: { depth: 1, timeout: 15000, maxPages: 10, maxLinksPerPage: 20 },
                    balanced: { depth: 2, timeout: 30000, maxPages: 30, maxLinksPerPage: 50 },
                    deep: { depth: 3, timeout: 60000, maxPages: 100, maxLinksPerPage: 100 },
                };
                const defaults = profileDefaults[profile] || profileDefaults.balanced;

                const parsedDepth = Number.parseInt(options.depth ?? String(defaults.depth), 10);
                const parsedTimeout = Number.parseInt(options.timeout ?? String(defaults.timeout), 10);
                const parsedMaxPages = Number.parseInt(options.maxPages ?? String(defaults.maxPages), 10);
                const parsedMaxLinksPerPage = Number.parseInt(options.maxLinksPerPage ?? String(defaults.maxLinksPerPage), 10);

                if (!Number.isFinite(parsedDepth) || parsedDepth < 1 || parsedDepth > 5) {
                    throw new Error("Depth must be a number between 1 and 5.");
                }

                if (!Number.isFinite(parsedTimeout) || parsedTimeout < 1000) {
                    throw new Error("Timeout must be a positive number (milliseconds).");
                }

                if (!Number.isFinite(parsedMaxPages) || parsedMaxPages < 1) {
                    throw new Error("max-pages must be a positive number.");
                }

                if (!Number.isFinite(parsedMaxLinksPerPage) || parsedMaxLinksPerPage < 1) {
                    throw new Error("max-links-per-page must be a positive number.");
                }

                const scanner = new Scanner();
                spinner.text = `Scanning ${url}...`;

                const result = await scanner.scan(url, {
                    depth: parsedDepth,
                    timeout: parsedTimeout,
                    headless: options.headless,
                    maxPages: parsedMaxPages,
                    maxLinksPerPage: parsedMaxLinksPerPage,
                    include: options.include,
                    exclude: options.exclude,
                });

                spinner.succeed("Scan complete!");

                // Save results
                const scanDir = await ensureScansDirectory();

                const timestamp = new Date().toISOString().replace(/[:.]/g, "-");
                const filename = options.output || `scan-${timestamp}.json`;
                const filepath = path.isAbsolute(filename)
                    ? filename
                    : path.join(scanDir, filename);

                await fs.writeFile(filepath, JSON.stringify(result, null, 2));

                let pdfPath: string | null = null;
                if (options.pdf !== false) {
                    const pdfSpinner = logger.spinner("Generating PDF report...");
                    try {
                        pdfPath = await generatePdfReport(result, filename);
                        pdfSpinner.succeed("PDF report generated!");
                    } catch (error) {
                        pdfSpinner.fail("PDF report generation failed");
                        logger.warn(
                            `Could not generate PDF automatically: ${(error as Error).message}`
                        );
                    }
                }

                try {
                    const target = new URL(result.target);
                    await addScanToIndex({
                        target: result.target,
                        hostname: target.hostname || "unknown",
                        timestamp: result.timestamp,
                        jsonPath: filepath,
                        pdfPath: pdfPath || undefined,
                        summary: result.summary,
                    });
                } catch (error) {
                    logger.debug(`Failed to update scan index: ${(error as Error).message}`);
                }

                // Display summary
                console.log("");
                console.log(chalk.bold("📊 Scan Summary"));
                console.log(chalk.gray("─".repeat(50)));
                console.log("");
                console.log(chalk.white("Target:"), chalk.cyan(result.target));
                console.log(
                    chalk.white("Duration:"),
                    chalk.cyan(`${(result.duration / 1000).toFixed(2)}s`)
                );
                console.log(chalk.white("URLs Crawled:"), chalk.cyan(result.metadata.crawledUrls));
                console.log(chalk.white("Forms Tested:"), chalk.cyan(result.metadata.testedForms));
                console.log(
                    chalk.white("Requests Made:"),
                    chalk.cyan(result.metadata.requestsMade)
                );
                console.log("");

                // Vulnerability summary
                console.log(chalk.bold("🛡️  Vulnerabilities Found"));
                console.log(chalk.gray("─".repeat(50)));
                console.log("");

                const { summary } = result;
                if (summary.total === 0) {
                    console.log(chalk.green("✓ No vulnerabilities found!"));
                } else {
                    if (summary.critical > 0)
                        console.log(
                            chalk.red(`  ${summary.critical} Critical`),
                            chalk.gray("- Immediate action required")
                        );
                    if (summary.high > 0)
                        console.log(
                            chalk.red(`  ${summary.high} High`),
                            chalk.gray("- Should be fixed soon")
                        );
                    if (summary.medium > 0)
                        console.log(
                            chalk.yellow(`  ${summary.medium} Medium`),
                            chalk.gray("- Fix when possible")
                        );
                    if (summary.low > 0)
                        console.log(
                            chalk.blue(`  ${summary.low} Low`),
                            chalk.gray("- Minor issues")
                        );
                    if (summary.info > 0)
                        console.log(
                            chalk.gray(`  ${summary.info} Info`),
                            chalk.gray("- Informational")
                        );
                }

                console.log("");
                console.log(chalk.gray("Results saved to:"), chalk.white(filepath));
                if (pdfPath) {
                    console.log(chalk.gray("PDF report saved to:"), chalk.white(pdfPath));
                }
                console.log("");

                // Show top vulnerabilities
                if (result.vulnerabilities.length > 0) {
                    console.log(chalk.bold("🔴 Top Findings"));
                    console.log(chalk.gray("─".repeat(50)));
                    console.log("");

                    const topVulns = result.vulnerabilities
                        .sort((a, b) => {
                            const severityOrder = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
                            return severityOrder[a.severity] - severityOrder[b.severity];
                        })
                        .slice(0, 5);

                    for (const vuln of topVulns) {
                        const severityColor =
                            vuln.severity === "critical" || vuln.severity === "high"
                                ? chalk.red
                                : vuln.severity === "medium"
                                    ? chalk.yellow
                                    : chalk.blue;

                        console.log(severityColor(`[${vuln.severity.toUpperCase()}]`), chalk.bold(vuln.title));
                        console.log(chalk.gray(`  ${vuln.url}`));
                        console.log(chalk.white(`  ${vuln.description}`));
                        console.log("");
                    }

                    if (result.vulnerabilities.length > 5) {
                        console.log(
                            chalk.gray(`  ... and ${result.vulnerabilities.length - 5} more`)
                        );
                        console.log("");
                    }
                }

                console.log(chalk.cyan("💡 Next steps:"));
                console.log(
                    chalk.white(`  1. Run ${chalk.cyan(`kramscan analyze ${filepath}`)} for AI-powered insights`)
                );
                console.log(chalk.white("  2. PDF report is generated automatically after the scan"));
                console.log("");
            } catch (error) {
                spinner.fail("Scan failed");
                logger.error((error as Error).message);
                process.exit(1);
            }
        });
}

function escapeHtml(text: string): string {
    return text
        .replaceAll("&", "&amp;")
        .replaceAll("<", "&lt;")
        .replaceAll(">", "&gt;")
        .replaceAll('"', "&quot;")
        .replaceAll("'", "&#39;");
}

function sanitizeFilenamePart(value: string): string {
    // Keep it Windows-safe: no <>:"/\\|?* and no control chars.
    return value
        .replace(/[<>:"/\\|?*\x00-\x1F]/g, "_")
        .replace(/\s+/g, "_")
        .replace(/_+/g, "_")
        .replace(/^_+|_+$/g, "");
}

function severityBadge(severity: string): string {
    const s = severity.toLowerCase();
    if (s === "critical") return "badge badge-critical";
    if (s === "high") return "badge badge-high";
    if (s === "medium") return "badge badge-medium";
    if (s === "low") return "badge badge-low";
    return "badge badge-info";
}

function buildPdfHtml(scan: ScanResult): string {
    const rows = scan.vulnerabilities
        .map((v, i) => {
            const sev = escapeHtml(v.severity.toUpperCase());
            const title = escapeHtml(v.title);
            const url = escapeHtml(v.url);
            const type = escapeHtml(v.type);
            const desc = escapeHtml(v.description);
            const evidence = v.evidence ? escapeHtml(v.evidence) : "";
            const remediation = v.remediation ? escapeHtml(v.remediation) : "";
            const cwe = v.cwe ? escapeHtml(v.cwe) : "";

            return `
      <div class="card">
        <div class="card-h">
          <div class="idx">${i + 1}.</div>
          <div class="title">${title}</div>
          <div class="${severityBadge(v.severity)}">${sev}</div>
        </div>
        <div class="meta">
          <div><span class="k">URL:</span> <span class="v mono">${url}</span></div>
          <div><span class="k">Type:</span> <span class="v mono">${type}</span></div>
          ${cwe ? `<div><span class="k">CWE:</span> <span class="v mono">${cwe}</span></div>` : ""}
        </div>
        <div class="section">
          <div class="k">Description</div>
          <div class="v">${desc}</div>
        </div>
        ${evidence ? `<div class="section"><div class="k">Evidence</div><div class="v mono pre">${evidence}</div></div>` : ""}
        ${remediation ? `<div class="section"><div class="k">Remediation</div><div class="v">${remediation}</div></div>` : ""}
      </div>`;
        })
        .join("\n");

    const summary = scan.summary;

    return `<!doctype html>
<html>
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>KramScan Security Report</title>
    <style>
      :root {
        --bg: #0b1020;
        --panel: #111a33;
        --panel2: #0e1630;
        --text: #e9eefc;
        --muted: #a9b6e5;
        --line: rgba(233,238,252,0.14);
        --critical: #ff4d4f;
        --high: #ff7a45;
        --medium: #fadb14;
        --low: #40a9ff;
        --info: #8c8c8c;
      }
      * { box-sizing: border-box; }
      body {
        margin: 0;
        padding: 28px;
        font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, Arial, "Noto Sans", "Helvetica Neue", sans-serif;
        color: var(--text);
        background: radial-gradient(1000px 600px at 20% 10%, rgba(64,169,255,0.20), transparent 60%),
                    radial-gradient(900px 500px at 70% 0%, rgba(255,77,79,0.18), transparent 55%),
                    linear-gradient(180deg, var(--bg), #070a14 70%);
      }
      .top {
        display: flex;
        justify-content: space-between;
        align-items: flex-end;
        gap: 16px;
        padding-bottom: 14px;
        border-bottom: 1px solid var(--line);
      }
      .brand {
        display: flex;
        flex-direction: column;
        gap: 6px;
      }
      .h1 { font-size: 22px; font-weight: 800; letter-spacing: 0.3px; }
      .sub { color: var(--muted); font-size: 12px; }
      .mono { font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace; }
      .pill {
        padding: 6px 10px;
        border: 1px solid var(--line);
        border-radius: 999px;
        background: rgba(17,26,51,0.55);
        color: var(--muted);
        font-size: 12px;
        white-space: nowrap;
      }
      .grid {
        display: grid;
        grid-template-columns: 1fr 1fr 1fr 1fr 1fr;
        gap: 10px;
        margin: 16px 0 10px;
      }
      .stat {
        border: 1px solid var(--line);
        background: rgba(17,26,51,0.55);
        border-radius: 12px;
        padding: 10px 12px;
      }
      .stat .k { color: var(--muted); font-size: 11px; }
      .stat .v { font-size: 18px; font-weight: 800; margin-top: 6px; }
      .cards { margin-top: 14px; display: flex; flex-direction: column; gap: 12px; }
      .card {
        border: 1px solid var(--line);
        background: linear-gradient(180deg, rgba(17,26,51,0.70), rgba(14,22,48,0.70));
        border-radius: 14px;
        padding: 12px 12px 10px;
        page-break-inside: avoid;
      }
      .card-h {
        display: grid;
        grid-template-columns: auto 1fr auto;
        align-items: center;
        gap: 10px;
      }
      .idx { color: var(--muted); font-weight: 700; }
      .title { font-weight: 800; }
      .badge {
        padding: 4px 8px;
        border-radius: 999px;
        font-size: 11px;
        font-weight: 800;
        border: 1px solid var(--line);
      }
      .badge-critical { background: rgba(255,77,79,0.18); color: #ffd1d1; border-color: rgba(255,77,79,0.45); }
      .badge-high { background: rgba(255,122,69,0.18); color: #ffe1d2; border-color: rgba(255,122,69,0.45); }
      .badge-medium { background: rgba(250,219,20,0.16); color: #fff3bf; border-color: rgba(250,219,20,0.40); }
      .badge-low { background: rgba(64,169,255,0.16); color: #d6ecff; border-color: rgba(64,169,255,0.40); }
      .badge-info { background: rgba(140,140,140,0.16); color: #eee; border-color: rgba(140,140,140,0.35); }
      .meta { margin-top: 10px; display: grid; gap: 6px; }
      .section { margin-top: 10px; border-top: 1px dashed rgba(233,238,252,0.20); padding-top: 10px; }
      .k { color: var(--muted); font-size: 11px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.6px; }
      .v { margin-top: 6px; font-size: 12px; line-height: 1.45; }
      .pre { white-space: pre-wrap; }
      .footer { margin-top: 18px; color: var(--muted); font-size: 11px; border-top: 1px solid var(--line); padding-top: 12px; }
    </style>
  </head>
  <body>
    <div class="top">
      <div class="brand">
        <div class="h1">KramScan Security Report</div>
        <div class="sub">Target: <span class="mono">${escapeHtml(scan.target)}</span></div>
        <div class="sub">Timestamp: <span class="mono">${escapeHtml(scan.timestamp)}</span></div>
      </div>
      <div class="pill">Automated PDF generated after scan</div>
    </div>

    <div class="grid">
      <div class="stat"><div class="k">Total</div><div class="v">${summary.total}</div></div>
      <div class="stat"><div class="k">Critical</div><div class="v">${summary.critical}</div></div>
      <div class="stat"><div class="k">High</div><div class="v">${summary.high}</div></div>
      <div class="stat"><div class="k">Medium</div><div class="v">${summary.medium}</div></div>
      <div class="stat"><div class="k">Low</div><div class="v">${summary.low}</div></div>
    </div>

    <div class="sub">Crawled URLs: <span class="mono">${scan.metadata.crawledUrls}</span> | Forms tested: <span class="mono">${scan.metadata.testedForms}</span> | Requests: <span class="mono">${scan.metadata.requestsMade}</span> | Duration: <span class="mono">${(scan.duration / 1000).toFixed(2)}s</span></div>

    <div class="cards">
      ${rows || `<div class="card"><div class="title">No vulnerabilities found</div><div class="v">The scanner did not detect issues in the tested scope.</div></div>`}
    </div>

    <div class="footer">Generated by KramScan</div>
  </body>
</html>`;
}

async function generatePdfReport(scanResult: ScanResult, _scanFilename: string): Promise<string> {
    const reportsDir = await ensureReportsDirectory();

    const targetUrl = new URL(scanResult.target);
    const host = sanitizeFilenamePart(targetUrl.hostname || "unknown");
    const timestamp = new Date(scanResult.timestamp || new Date().toISOString())
        .toISOString()
        .replace(/[:.]/g, "-");

    // Example: scanreport_example.com_2026-02-15T13-43-01-146Z.pdf
    const pdfFilename = `scanreport_${host}_${timestamp}.pdf`;
    const pdfPath = path.join(reportsDir, pdfFilename);

    const browser = await puppeteer.launch({
        headless: true,
        args: ["--no-sandbox", "--disable-setuid-sandbox"],
    });

    try {
        const page = await browser.newPage();
        const html = buildPdfHtml(scanResult);
        await page.setContent(html, { waitUntil: "networkidle0" });
        await page.pdf({
            path: pdfPath,
            format: "A4",
            printBackground: true,
            margin: { top: "12mm", bottom: "12mm", left: "10mm", right: "10mm" },
        });
    } finally {
        await browser.close();
    }

    return pdfPath;
}
