import { Command } from "commander";
import { Scanner, ScanOptions } from "../core/scanner";
import { addScanToIndex } from "../core/scan-index";
import { ensureScansDirectory } from "../core/scan-storage";
import { scanProfiles } from "../core/config";
import { pdfGenerator, PdfReportData } from "../reports/PdfGenerator";
import { displayScanSummary, theme } from "../utils/theme";
import { logger } from "../utils/logger";
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
        .option("--json", "Output scan results as JSON to stdout (CI/CD mode)")
        .option("-o, --output <file>", "Save results to file")
        .option("--headless", "Run in headless mode", true)
        .option("--no-plugins", "Disable plugin-based scanning (use legacy mode)")
        .action(async (url: string, options) => {
            const jsonMode = options.json === true;

            if (!jsonMode) {
                console.log("");
                console.log(theme.brand.bold("🔍 Starting Security Scan"));
                console.log(theme.gray("─".repeat(50)));
                console.log("");
            }

            if (!/^https?:\/\//i.test(url)) {
                url = `http://${url}`;
            }

            // Validate URL
            try {
                new URL(url);
            } catch (error) {
                if (jsonMode) {
                    console.log(JSON.stringify({ error: `Invalid URL: ${url}` }));
                } else {
                    logger.error(`Invalid URL: ${url}`);
                }
                process.exit(1);
            }

            const spinner = jsonMode ? null : logger.spinner("Initializing scanner...");

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

                // Display scan estimate
                if (!jsonMode) {
                    const estimateMap: Record<string, string> = {
                        quick: "~15–30s",
                        balanced: "~30–90s",
                        deep: "~2–5min",
                    };
                    const estimate = estimateMap[profile] || estimateMap.balanced;
                    console.log(theme.gray(`  ⏱  Estimated duration: ${estimate} (${profile} profile)`));
                    console.log("");
                }

                const scanner = new Scanner(options.plugins !== false);


                let vulnerabilitiesFound = 0;

                scanner.on("scan:start", () => {
                    if (spinner) spinner.text = `Starting scan of ${url}...`;
                });

                scanner.on("crawl:page", (data) => {
                    if (spinner) spinner.text = `Crawling: ${data.url} (${data.crawledCount}/${data.maxPages})`;
                });

                scanner.on("form:test", (data) => {
                    if (spinner) spinner.text = `Testing forms on ${data.url} (${data.formCount} forms)...`;
                });

                scanner.on("vuln:found", (data) => {
                    vulnerabilitiesFound++;
                    if (spinner) {
                        spinner.stopAndPersist({
                            symbol: theme.warning("⚠️"),
                            text: `Found ${data.vulnerability.severity} vulnerability: ${data.vulnerability.title}`
                        });
                        spinner.start(`Continuing scan (${vulnerabilitiesFound} vulns found)...`);
                    }
                });

                scanner.on("scan:complete", () => {
                    if (spinner) spinner.text = "Finalizing scan results...";
                });

                scanner.on("crawl:error", (data) => {
                    if (!jsonMode) logger.warn(`Failed to crawl ${data.url}: ${data.error.message}`);
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

                if (spinner) spinner.succeed("Scan complete!");

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

                // In JSON mode, output the result to stdout and exit
                if (jsonMode) {
                    console.log(JSON.stringify(resultWithErrors, null, 2));
                    return;
                }

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
                    score: result.score,
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

                        for (const [pluginName, errors] of pluginErrorsMap) {
                            console.log(theme.gray(`    ${pluginName}:`));
                            for (const error of errors.slice(0, 3)) {
                                console.log(theme.gray(`      - ${error.url}: ${error.error}`));
                            }
                            if (errors.length > 3) {
                                console.log(theme.gray(`      ... and ${errors.length - 3} more`));
                            }
                        }

                        const totalPluginErrors = Array.from(pluginErrorsMap.values()).reduce((sum, errs) => sum + errs.length, 0);
                        if (totalPluginErrors > 10) {
                            console.log(theme.gray(`  Total plugin errors: ${totalPluginErrors}`));
                        }
                    }
                    console.log("");
                }

                // Add "What's Next" interactive prompt
                if (!jsonMode) {
                    const inquirer = (await import("inquirer")).default;
                    const { nextAction } = await inquirer.prompt([
                        {
                            type: "list",
                            name: "nextAction",
                            message: theme.cyan("Scan complete! What would you like to do next?"),
                            choices: [
                                { name: "🧠  Analyze findings with AI", value: "analyze" },
                                { name: "📄  Generate a professional report", value: "report" },
                                { name: "🤖  Generate AI-ready Markdown report for fixing issues", value: "markdown" },
                                { name: "👋  Exit to main menu", value: "exit" }
                            ]
                        }
                    ]);

                    if (nextAction === "analyze") {
                        const { registerAnalyzeCommand } = await import("./analyze");
                        const analyzeProgram = new Command();
                        registerAnalyzeCommand(analyzeProgram);
                        await analyzeProgram.parseAsync(["node", "kramscan", "analyze", filepath]);
                    } else if (nextAction === "report") {
                        const { registerReportCommand } = await import("./report");
                        const reportProgram = new Command();
                        registerReportCommand(reportProgram);
                        await reportProgram.parseAsync(["node", "kramscan", "report", filepath]);
                    } else if (nextAction === "markdown") {
                        const { registerReportCommand } = await import("./report");
                        const reportProgram = new Command();
                        registerReportCommand(reportProgram);
                        await reportProgram.parseAsync(["node", "kramscan", "report", filepath, "-f", "markdown"]);
                    }
                }

            } catch (error) {
                if (spinner) spinner.fail("Scan failed");
                if (jsonMode) {
                    console.log(JSON.stringify({ error: (error as Error).message }));
                } else {
                    logger.error((error as Error).message);
                }
                process.exit(1);
            }
        });
}
