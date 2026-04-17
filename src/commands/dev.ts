import { Command } from "commander";
import { Scanner, ScanOptions, ScanError } from "../core/scanner";
import { probeServer, isLocalhost } from "../core/server-probe";
import { diffScanResults, ScanDiff } from "../core/diff-engine";
import { displayScanSummary, theme } from "../utils/theme";
import { logger } from "../utils/logger";
import { ScanResult } from "../core/vulnerability-detector";
import { getSeverityColor } from "../utils/theme";
import path from "path";
import fs from "fs/promises";

export function registerDevCommand(program: Command): void {
    program
        .command("dev [url]")
        .description("Watch-mode security scanning for localhost development servers")
        .option("--port <number>", "Shorthand for http://localhost:<port>")
        .option("--watch-dir <path>", "Directory to watch for file changes", "./src")
        .option("--debounce <ms>", "Debounce time before re-scanning (ms)", "2000")
        .option("--profile <name>", "Scan profile: quick|balanced", "quick")
        .option("--notify", "Enable desktop notifications for critical findings")
        .option("--fail-on <severity>", "Exit with code 1 if severity threshold met")
        .option("--no-watch", "Run a single scan without watching (useful for CI)")
        .action(async (url: string | undefined, options) => {
            // Resolve target URL
            const targetUrl = url || (options.port ? `http://localhost:${options.port}` : null);

            if (!targetUrl) {
                console.log("");
                console.log(theme.error("✗ No target URL specified."));
                console.log(theme.gray("  Usage: kramscan dev http://localhost:3000"));
                console.log(theme.gray("     or: kramscan dev --port 3000"));
                console.log("");
                process.exit(1);
            }

            const isLocal = isLocalhost(targetUrl);

            console.log("");
            console.log(theme.brand.bold("🛠️  KramScan Dev Mode"));
            console.log(theme.gray("─".repeat(50)));
            console.log("");
            console.log(theme.white("Target:"), theme.cyan(targetUrl));
            console.log(theme.white("Profile:"), theme.cyan(options.profile));
            if (isLocal) {
                console.log(theme.white("Environment:"), theme.green("localhost (dev mode)"));
            }
            console.log("");

            // Probe server readiness
            const probeSpinner = logger.spinner(`Waiting for ${targetUrl} to be ready...`);

            const probeResult = await probeServer(targetUrl, { timeout: 30000 });

            if (!probeResult.reachable) {
                probeSpinner.fail(`Server at ${targetUrl} is not responding`);
                console.log("");
                console.log(theme.warning("⚠️  Make sure your dev server is running:"));
                console.log(theme.gray("  • npm run dev"));
                console.log(theme.gray("  • yarn dev"));
                console.log(theme.gray("  • python manage.py runserver"));
                console.log("");
                process.exit(1);
            }

            probeSpinner.succeed(
                `Server ready! (${probeResult.responseTime}ms` +
                `${probeResult.framework ? `, ${probeResult.framework}` : ""}` +
                `${probeResult.server ? `, ${probeResult.server}` : ""})`
            );

            // Run initial scan
            let previousResult: ScanResult | null = null;

            const runScan = async (isRescan: boolean = false): Promise<ScanResult | null> => {
                const scanSpinner = logger.spinner(
                    isRescan ? "Re-scanning after code change..." : "Running initial security scan..."
                );

                try {
                    const scanner = new Scanner(true);
                    const scanOptions: ScanOptions = {
                        depth: 2,
                        timeout: 10000,
                        headless: true,
                        maxPages: 15,
                        maxLinksPerPage: 30,
                        profile: options.profile,
                    };

                    const result = await scanner.scan(targetUrl, scanOptions);
                    scanSpinner.succeed(
                        isRescan
                            ? `Re-scan complete: ${result.summary.total} vulnerabilities`
                            : `Initial scan complete: ${result.summary.total} vulnerabilities`
                    );
                    await scanner.close();

                    if (isRescan && previousResult) {
                        // Show diff
                        const diff = diffScanResults(previousResult, result);
                        displayDiff(diff);
                    } else {
                        // Show full summary for initial scan
                        displayScanSummary({
                            target: result.target,
                            duration: result.duration,
                            metadata: result.metadata,
                            summary: result.summary,
                            vulnerabilities: result.vulnerabilities,
                            score: result.score,
                            filepath: "(dev mode — results in memory)",
                        });
                    }

                    // Desktop notification for critical/high findings
                    if (options.notify && result.summary.critical + result.summary.high > 0) {
                        try {
                            // node-notifier is optional — skip if not installed
                            // eslint-disable-next-line @typescript-eslint/no-var-requires
                            const notifier = require("node-notifier");
                            notifier.notify({
                                title: "⚠️ KramScan Security Alert",
                                message: `Found ${result.summary.critical} critical, ${result.summary.high} high vulnerabilities on ${targetUrl}`,
                                sound: true,
                            });
                        } catch {
                            // node-notifier not installed, skip silently
                        }
                    }

                    // Check fail threshold
                    if (options.failOn) {
                        const shouldFail = checkThreshold(result, options.failOn);
                        if (shouldFail && !options.watch) {
                            console.log(theme.error(`\n✗ Security gate failed: found vulnerabilities at or above '${options.failOn}' severity.\n`));
                            process.exit(1);
                        }
                    }

                    return result;
                } catch (err) {
                    scanSpinner.fail(`Scan failed: ${(err as Error).message}`);
                    return previousResult;
                }
            };

            // Initial scan
            previousResult = await runScan(false);

            // Watch mode
            if (options.watch !== false) {
                const watchDir = path.resolve(options.watchDir);

                try {
                    await fs.access(watchDir);
                } catch {
                    console.log(theme.warning(`⚠️  Watch directory not found: ${watchDir}`));
                    console.log(theme.gray("  Falling back to current directory."));
                }

                console.log("");
                console.log(theme.brand("👁️  Watching for changes..."));
                console.log(theme.gray(`  Directory: ${watchDir}`));
                console.log(theme.gray(`  Debounce: ${options.debounce}ms`));
                console.log(theme.gray("  Press Ctrl+C to stop."));
                console.log("");

                // Use fs.watch with recursive option (Node.js 19+)
                let debounceTimer: NodeJS.Timeout | null = null;
                let scanning = false;

                try {
                    const watcher = fs.watch(watchDir, { recursive: true });
                    for await (const event of watcher) {
                        if (scanning) continue;

                        // Ignore node_modules, dist, .git, etc.
                        const filename = event.filename || "";
                        if (
                            filename.includes("node_modules") ||
                            filename.includes("dist") ||
                            filename.includes(".git") ||
                            filename.includes(".next") ||
                            filename.includes("__pycache__")
                        ) {
                            continue;
                        }

                        if (debounceTimer) clearTimeout(debounceTimer);

                        debounceTimer = setTimeout(async () => {
                            scanning = true;
                            console.log("");
                            console.log(theme.dim(`📝 Change detected: ${filename}`));
                            previousResult = await runScan(true);
                            scanning = false;
                        }, parseInt(options.debounce, 10));
                    }
                } catch (err) {
                    console.log(theme.warning(`⚠️  File watching failed: ${(err as Error).message}`));
                    console.log(theme.gray("  Make sure the watch directory exists and is readable."));
                }
            }
        });
}

function displayDiff(diff: ScanDiff): void {
    console.log("");
    console.log(theme.brightWhite.bold("🔄 Scan Diff Report"));
    console.log(theme.gray("─".repeat(50)));

    if (diff.newVulnerabilities.length === 0 && diff.resolvedVulnerabilities.length === 0) {
        console.log(theme.gray("  No changes since last scan."));
        console.log(theme.gray(`  ${diff.unchangedCount} vulnerabilities unchanged.`));
    } else {
        // New vulnerabilities
        if (diff.newVulnerabilities.length > 0) {
            console.log("");
            console.log(theme.error(`  🆕 ${diff.newVulnerabilities.length} New Vulnerabilities`));
            for (const v of diff.newVulnerabilities) {
                const color = getSeverityColor(v.severity);
                console.log(color(`    [${v.severity.toUpperCase()}] ${v.title}`));
                console.log(theme.gray(`      ${v.url}`));
            }
        }

        // Resolved vulnerabilities
        if (diff.resolvedVulnerabilities.length > 0) {
            console.log("");
            console.log(theme.success(`  ✅ ${diff.resolvedVulnerabilities.length} Resolved`));
            for (const v of diff.resolvedVulnerabilities) {
                console.log(theme.green(`    ✓ ${v.title}`));
            }
        }

        console.log("");
        console.log(
            theme.gray(`  Total: ${diff.previousTotal} → ${diff.currentTotal} `) +
            (diff.currentTotal < diff.previousTotal
                ? theme.green(`(↓ ${diff.previousTotal - diff.currentTotal})`)
                : diff.currentTotal > diff.previousTotal
                    ? theme.error(`(↑ ${diff.currentTotal - diff.previousTotal})`)
                    : theme.gray("(no change)"))
        );
    }

    console.log("");
}

function checkThreshold(result: ScanResult, failOn: string): boolean {
    const severityLevels: Record<string, number> = {
        critical: 4,
        high: 3,
        medium: 2,
        low: 1,
        info: 0,
    };

    const threshold = severityLevels[failOn.toLowerCase()] ?? 3;

    for (const v of result.vulnerabilities) {
        if ((severityLevels[v.severity] ?? 0) >= threshold) {
            return true;
        }
    }

    return false;
}
