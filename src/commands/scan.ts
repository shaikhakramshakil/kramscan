import { Command } from "commander";
import chalk from "chalk";
import { Scanner } from "../core/scanner";
import { logger } from "../utils/logger";
import fs from "fs/promises";
import path from "path";
import os from "os";

export function registerScanCommand(program: Command): void {
    program
        .command("scan <url>")
        .description("Scan a target URL for vulnerabilities")
        .option("-d, --depth <number>", "Crawl depth", "2")
        .option("-t, --timeout <ms>", "Request timeout", "30000")
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
                const scanner = new Scanner();
                spinner.text = `Scanning ${url}...`;

                const result = await scanner.scan(url, {
                    depth: parseInt(options.depth),
                    timeout: parseInt(options.timeout),
                    headless: options.headless,
                });

                spinner.succeed("Scan complete!");

                // Save results
                const scanDir = path.join(os.homedir(), ".kramscan", "scans");
                await fs.mkdir(scanDir, { recursive: true });

                const timestamp = new Date().toISOString().replace(/[:.]/g, "-");
                const filename = options.output || `scan-${timestamp}.json`;
                const filepath = path.isAbsolute(filename)
                    ? filename
                    : path.join(scanDir, filename);

                await fs.writeFile(filepath, JSON.stringify(result, null, 2));

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
                console.log(
                    chalk.white(`  2. Run ${chalk.cyan(`kramscan report ${filepath}`)} to generate a report`)
                );
                console.log("");
            } catch (error) {
                spinner.fail("Scan failed");
                logger.error((error as Error).message);
                process.exit(1);
            }
        });
}
