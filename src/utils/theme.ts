import chalk from "chalk";

export const theme = {
    // Colors
    brand: chalk.hex("#00D1FF"),
    error: chalk.red.bold,
    success: chalk.green,
    warning: chalk.yellow,
    info: chalk.blue,
    dim: chalk.gray,
    gray: chalk.gray,
    white: chalk.white,
    cyan: chalk.cyan,
    brightWhite: chalk.white.bold,
    brightCyan: chalk.cyan.bold,
    brightMagenta: chalk.magenta.bold,
    brightBlue: chalk.blue.bold,
    brightGreen: chalk.green.bold,
    brightYellow: chalk.yellow.bold,
    brightRed: chalk.red.bold,
    
    // Severity colors
    critical: chalk.red.bold,
    high: chalk.red,
    medium: chalk.yellow,
    low: chalk.blue,
    infoSeverity: chalk.gray,
    yellow: chalk.yellow,
    green: chalk.green,
};

export const CLI_VERSION = "0.1.1";

// ─── ASCII Art Banner ──────────────────────────────────────────────
export function printBanner(): void {
    const lines = [
        `██╗  ██╗██████╗  █████╗ ███╗   ███╗███████╗ ██████╗ █████╗ ███╗   ██╗`,
        `██║ ██╔╝██╔══██╗██╔══██╗████╗ ████║██╔════╝██╔════╝██╔══██╗████╗  ██║`,
        `█████╔╝ ██████╔╝███████║██╔████╔██║███████╗██║     ███████║██╔██╗ ██║`,
        `██╔═██╗ ██╔══██╗██╔══██║██║╚██╔╝██║╚════██║██║     ██╔══██║██║╚██╗██║`,
        `██║  ██╗██║  ██║██║  ██║██║ ╚═╝ ██║███████║╚██████╗██║  ██║██║ ╚████║`,
        `╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝     ╚═╝╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝`,
    ];

    console.log("");
    lines.forEach((line, i) => {
        const shade = i % 2 === 0 ? theme.brightWhite : theme.dim;
        console.log(`  ${shade(line)}`);
    });
    console.log("");
}

// ─── Dashboard Info ────────────────────────────────────────────────
export function printInfo(): void {
    console.log(
        `  ${theme.dim("───────────────────────────────────────────────────────")}`
    );
    console.log(
        `  ${theme.brightWhite(" KramScan")} ${theme.gray(`v${CLI_VERSION}`)}  ${theme.dim("|")}  ${theme.cyan("AI-Powered Web Security Scanner")}`
    );
    console.log(
        `  ${theme.dim("───────────────────────────────────────────────────────")}`
    );
    console.log("");
    console.log(`  ${theme.brightYellow("Tips for getting started:")}`);
    console.log(`  ${theme.white("1.")} ${theme.gray("Run")} ${theme.cyan("kramscan onboard")} ${theme.gray("to configure your API keys.")}`);
    console.log(`  ${theme.white("2.")} ${theme.gray("Run")} ${theme.cyan("kramscan scan <url>")} ${theme.gray("to scan a target.")}`);
    console.log(`  ${theme.white("3.")} ${theme.gray("Run")} ${theme.cyan("kramscan --help")} ${theme.gray("for all commands.")}`);
    console.log("");
}

// ─── Severity Color Helper ─────────────────────────────────────────
export function getSeverityColor(severity: string): (text: string) => string {
    const s = severity.toLowerCase();
    if (s === "critical") return theme.critical;
    if (s === "high") return theme.high;
    if (s === "medium") return theme.medium;
    if (s === "low") return theme.low;
    return theme.infoSeverity;
}

// ─── Scan Summary Display ──────────────────────────────────────────
export function displayScanSummary(result: {
    target: string;
    duration: number;
    metadata: {
        crawledUrls: number;
        testedForms: number;
        requestsMade: number;
    };
    summary: {
        total: number;
        critical: number;
        high: number;
        medium: number;
        low: number;
        info: number;
    };
    vulnerabilities: Array<{
        severity: string;
        title: string;
        url: string;
        description: string;
    }>;
    filepath: string;
    pdfPath?: string | null;
}): void {
    const { target, duration, metadata, summary, vulnerabilities, filepath, pdfPath } = result;

    // Scan Summary
    console.log("");
    console.log(theme.brightWhite.bold("📊 Scan Summary"));
    console.log(theme.gray("─".repeat(50)));
    console.log("");
    console.log(theme.white("Target:"), theme.cyan(target));
    console.log(
        theme.white("Duration:"),
        theme.cyan(`${(duration / 1000).toFixed(2)}s`)
    );
    console.log(theme.white("URLs Crawled:"), theme.cyan(metadata.crawledUrls));
    console.log(theme.white("Forms Tested:"), theme.cyan(metadata.testedForms));
    console.log(
        theme.white("Requests Made:"),
        theme.cyan(metadata.requestsMade)
    );
    console.log("");

    // Vulnerability summary
    console.log(theme.brightWhite.bold("🛡️  Vulnerabilities Found"));
    console.log(theme.gray("─".repeat(50)));
    console.log("");

    if (summary.total === 0) {
        console.log(theme.success("✓ No vulnerabilities found!"));
    } else {
        if (summary.critical > 0)
            console.log(
                theme.critical(`  ${summary.critical} Critical`),
                theme.gray("- Immediate action required")
            );
        if (summary.high > 0)
            console.log(
                theme.high(`  ${summary.high} High`),
                theme.gray("- Should be fixed soon")
            );
        if (summary.medium > 0)
            console.log(
                theme.medium(`  ${summary.medium} Medium`),
                theme.gray("- Fix when possible")
            );
        if (summary.low > 0)
            console.log(
                theme.low(`  ${summary.low} Low`),
                theme.gray("- Minor issues")
            );
        if (summary.info > 0)
            console.log(
                theme.infoSeverity(`  ${summary.info} Info`),
                theme.gray("- Informational")
            );
    }

    console.log("");
    console.log(theme.gray("Results saved to:"), theme.white(filepath));
    if (pdfPath) {
        console.log(theme.gray("PDF report saved to:"), theme.white(pdfPath));
    }
    console.log("");

    // Show top vulnerabilities
    if (vulnerabilities.length > 0) {
        console.log(theme.brightWhite.bold("🔴 Top Findings"));
        console.log(theme.gray("─".repeat(50)));
        console.log("");

        const topVulns = vulnerabilities
            .sort((a, b) => {
                const severityOrder = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
                return severityOrder[a.severity as keyof typeof severityOrder] - severityOrder[b.severity as keyof typeof severityOrder];
            })
            .slice(0, 5);

        for (const vuln of topVulns) {
            const severityColor = getSeverityColor(vuln.severity);

            console.log(severityColor(`[${vuln.severity.toUpperCase()}]`), theme.brightWhite.bold(vuln.title));
            console.log(theme.gray(`  ${vuln.url}`));
            console.log(theme.white(`  ${vuln.description}`));
            console.log("");
        }

        if (vulnerabilities.length > 5) {
            console.log(
                theme.gray(`  ... and ${vulnerabilities.length - 5} more`)
            );
            console.log("");
        }
    }

    console.log(theme.cyan("💡 Next steps:"));
    console.log(
        theme.white(`  1. Run ${theme.cyan(`kramscan analyze ${filepath}`)} for AI-powered insights`)
    );
    console.log(theme.white("  2. PDF report is generated automatically after the scan"));
    console.log("");
}

export default theme;
