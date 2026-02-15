import { Command } from "commander";
import { Scanner, ScanOptions, ScanError } from "../core/scanner";
import { addScanToIndex } from "../core/scan-index";
import { ensureScansDirectory } from "../core/scan-storage";
import { pdfGenerator, PdfReportData } from "../reports/PdfGenerator";
import { displayScanSummary, theme } from "../utils/theme";
import { logger } from "../utils/logger";
import fs from "fs/promises";
import path from "path";
import chalk from "chalk";

export interface ScanProfile {
    depth: number;
    timeout: number;
    maxPages: number;
    maxLinksPerPage: number;
}

export const scanProfiles: Record<string, ScanProfile> = {
    quick: { depth: 1, timeout: 15000, maxPages: 10, maxLinksPerPage: 20 },
    balanced: { depth: 2, timeout: 30000, maxPages: 30, maxLinksPerPage: 50 },
    deep: { depth: 3, timeout: 60000, maxPages: 100, maxLinksPerPage: 100 },
};

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
        .option("--no-plugins", "Disable plugin-based scanning (use legacy mode)")
        .action(async (url: string, options) => {
            console.log("");
            console.log(theme.brand.bold("🔍 Starting Security Scan"));
            console.log(theme.gray("─".repeat(50)));
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
                const defaults = scanProfiles[profile] || scanProfiles.balanced;

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

                const scanner = new Scanner(options.plugins !== false);
                
                // Set up event listeners for progress feedback
                let currentStage = "initializing";
                let vulnerabilitiesFound = 0;
                
                scanner.on("scan:start", () => {
                    spinner.text = `Starting scan of ${url}...`;
                    currentStage = "scanning";
                });

                scanner.on("crawl:page", (data) => {
                    spinner.text = `Crawling: ${data.url} (${data.crawledCount}/${data.maxPages})`;
                    currentStage = "crawling";
                });

                scanner.on("form:test", (data) => {
                    spinner.text = `Testing forms on ${data.url} (${data.formCount} forms)...`;
                    currentStage = "testing forms";
                });

                scanner.on("vuln:found", (data) => {
                    vulnerabilitiesFound++;
                    spinner.stopAndPersist({ 
                        symbol: theme.warning("⚠️"), 
                        text: `Found ${data.vulnerability.severity} vulnerability: ${data.vulnerability.title}` 
                    });
                    spinner.start(`Continuing scan (${vulnerabilitiesFound} vulns found)...`);
                });

                scanner.on("scan:complete", () => {
                    spinner.text = "Finalizing scan results...";
                });

                scanner.on("crawl:error", (data) => {
                    logger.warn(`Failed to crawl ${data.url}: ${data.error.message}`);
                });
                
                const scanOptions: ScanOptions = {
                    depth: parsedDepth,
                    timeout: parsedTimeout,
                    headless: options.headless,
                    maxPages: parsedMaxPages,
                    maxLinksPerPage: parsedMaxLinksPerPage,
                    include: options.include,
                    exclude: options.exclude,
                    profile,
                };

                const result = await scanner.scan(url, scanOptions);

                spinner.succeed("Scan complete!");

                // Save results
                const scanDir = await ensureScansDirectory();

                const timestamp = new Date().toISOString().replace(/[:.]/g, "-");
                const filename = options.output || `scan-${timestamp}.json`;
                const filepath = path.isAbsolute(filename)
                    ? filename
                    : path.join(scanDir, filename);

                // Include error data in JSON
                const scanErrors = scanner.getScanErrors();
                const pluginErrors = scanner.getPluginErrors();
                const resultWithErrors = {
                    ...result,
                    errors: {
                        scan: scanErrors,
                        plugins: Object.fromEntries(pluginErrors),
                    },
                };

                await fs.writeFile(filepath, JSON.stringify(resultWithErrors, null, 2));

                let pdfPath: string | null = null;
                if (options.pdf !== false) {
                    const pdfSpinner = logger.spinner("Generating PDF report...");
                    try {
                        const pdfData: PdfReportData = {
                            scanResult: result,
                            scanErrors,
                            pluginErrors,
                        };
                        pdfPath = await pdfGenerator.generate(pdfData);
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

                // Display summary using theme
                displayScanSummary({
                    target: result.target,
                    duration: result.duration,
                    metadata: result.metadata,
                    summary: result.summary,
                    vulnerabilities: result.vulnerabilities,
                    filepath,
                    pdfPath,
                });

                // Display any scan errors
                const scanErrorsList = scanner.getScanErrors();
                const pluginErrorsMap = scanner.getPluginErrors();
                
                if (scanErrorsList.length > 0 || pluginErrorsMap.size > 0) {
                    console.log(theme.warning("⚠️  Some URLs/plugins encountered errors:"));
                    
                    if (scanErrorsList.length > 0) {
                        console.log(theme.yellow("  Crawl Errors:"));
                        for (const error of scanErrorsList.slice(0, 5)) {
                            console.log(theme.gray(`    - ${error.url}: ${error.error}`));
                        }
                        if (scanErrorsList.length > 5) {
                            console.log(theme.gray(`    ... and ${scanErrorsList.length - 5} more`));
                        }
                    }

                    if (pluginErrorsMap.size > 0) {
                        console.log(theme.yellow("  Plugin Errors:"));
                        let totalPluginErrors = 0;
                        pluginErrorsMap.forEach((errors, pluginName) => {
                            totalPluginErrors += errors.length;
                        });
                        
                        for (const [pluginName, errors] of pluginErrorsMap) {
                            console.log(theme.gray(`    ${pluginName}:`));
                            for (const error of errors.slice(0, 3)) {
                                console.log(theme.gray(`      - ${error.url}: ${error.error}`));
                            }
                            if (errors.length > 3) {
                                console.log(theme.gray(`      ... and ${errors.length - 3} more`));
                            }
                        }
                        
                        if (totalPluginErrors > 10) {
                            console.log(theme.gray(`  Total plugin errors: ${totalPluginErrors}`));
                        }
                    }
                    console.log("");
                }

            } catch (error) {
                spinner.fail("Scan failed");
                logger.error((error as Error).message);
                process.exit(1);
            }
        });
}
