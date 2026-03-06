import { Command } from "commander";
import { Scanner, ScanOptions } from "../core/scanner";
import { probeServer, isLocalhost } from "../core/server-probe";
import { theme } from "../utils/theme";
import { logger } from "../utils/logger";
import { ScanResult } from "../core/vulnerability-detector";

export function registerGateCommand(program: Command): void {
    program
        .command("gate <url>")
        .description("CI/CD security quality gate — scan and exit with code 1 if thresholds are breached")
        .option("--fail-on <severity>", "Minimum severity to fail on (critical|high|medium|low)", "high")
        .option("--max-vulns <number>", "Maximum allowed vulnerabilities before failing", "0")
        .option("--profile <name>", "Scan profile: quick|balanced|deep", "quick")
        .option("--timeout <ms>", "Maximum scan duration", "60000")
        .option("--json", "Output results as JSON")
        .action(async (url: string, options) => {
            const jsonMode = options.json === true;

            if (!jsonMode) {
                console.log("");
                console.log(theme.brand.bold("🚧 KramScan Security Gate"));
                console.log(theme.gray("─".repeat(50)));
                console.log("");
            }

            // Probe server
            if (!jsonMode) {
                const probeSpinner = logger.spinner(`Checking server at ${url}...`);
                const probeResult = await probeServer(url, { timeout: 10000, maxAttempts: 5 });

                if (!probeResult.reachable) {
                    probeSpinner.fail(`Server at ${url} is not responding`);
                    if (jsonMode) {
                        console.log(JSON.stringify({ error: "Server unreachable", passed: false }));
                    }
                    process.exit(1);
                }
                probeSpinner.succeed(`Server ready (${probeResult.responseTime}ms)`);
            }

            // Run scan
            const scanSpinner = jsonMode ? null : logger.spinner("Running security scan...");

            try {
                const scanner = new Scanner(true);
                const scanOptions: ScanOptions = {
                    depth: 2,
                    timeout: parseInt(options.timeout, 10) || 60000,
                    headless: true,
                    maxPages: 20,
                    maxLinksPerPage: 30,
                    profile: options.profile,
                };

                const result = await scanner.scan(url, scanOptions);
                await scanner.close();

                if (scanSpinner) scanSpinner.succeed(`Scan complete: ${result.summary.total} vulnerabilities`);

                // Evaluate threshold
                const severityLevels: Record<string, number> = {
                    critical: 4, high: 3, medium: 2, low: 1, info: 0,
                };
                const threshold = severityLevels[options.failOn.toLowerCase()] ?? 3;
                const maxVulns = parseInt(options.maxVulns, 10) || 0;

                const vulnsAboveThreshold = result.vulnerabilities.filter(
                    (v) => (severityLevels[v.severity] ?? 0) >= threshold
                );

                const passed = vulnsAboveThreshold.length <= maxVulns;

                if (jsonMode) {
                    console.log(JSON.stringify({
                        passed,
                        total: result.summary.total,
                        threshold: options.failOn,
                        vulnsAboveThreshold: vulnsAboveThreshold.length,
                        maxAllowed: maxVulns,
                        summary: result.summary,
                        vulnerabilities: vulnsAboveThreshold,
                    }, null, 2));
                } else {
                    console.log("");

                    if (passed) {
                        console.log(theme.success.bold("✅ SECURITY GATE: PASSED"));
                        console.log(theme.gray(`   ${result.summary.total} total vulnerabilities found`));
                        console.log(theme.gray(`   ${vulnsAboveThreshold.length} at or above '${options.failOn}' severity (max allowed: ${maxVulns})`));
                    } else {
                        console.log(theme.error.bold("❌ SECURITY GATE: FAILED"));
                        console.log(theme.error(`   ${vulnsAboveThreshold.length} vulnerabilities at or above '${options.failOn}' severity (max allowed: ${maxVulns})`));
                        console.log("");

                        for (const v of vulnsAboveThreshold.slice(0, 10)) {
                            const color = v.severity === "critical" ? theme.critical : theme.high;
                            console.log(color(`   [${v.severity.toUpperCase()}] ${v.title}`));
                            console.log(theme.gray(`     ${v.url}`));
                            if (v.remediation) {
                                console.log(theme.dim(`     Fix: ${v.remediation}`));
                            }
                        }

                        if (vulnsAboveThreshold.length > 10) {
                            console.log(theme.gray(`   ... and ${vulnsAboveThreshold.length - 10} more`));
                        }
                    }

                    console.log("");
                }

                process.exit(passed ? 0 : 1);
            } catch (err) {
                if (scanSpinner) scanSpinner.fail(`Scan failed: ${(err as Error).message}`);
                if (jsonMode) {
                    console.log(JSON.stringify({ error: (err as Error).message, passed: false }));
                }
                process.exit(1);
            }
        });
}
