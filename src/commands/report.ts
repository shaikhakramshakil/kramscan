import { Command } from "commander";
import chalk from "chalk";
import { ScanResult } from "../core/vulnerability-detector";
import { logger } from "../utils/logger";
import { getConfig } from "../core/config";
import fs from "fs/promises";
import path from "path";
import os from "os";
import { Document, Packer, Paragraph, TextRun, HeadingLevel, Table, TableRow, TableCell, WidthType, AlignmentType } from "docx";

export function registerReportCommand(program: Command): void {
    program
        .command("report [scan-file]")
        .description("Generate a professional security report")
        .option("-f, --format <type>", "Report format: word|json|txt")
        .option("-o, --output <file>", "Output filename")
        .action(async (scanFile: string | undefined, options) => {
            console.log("");
            console.log(chalk.bold.cyan("📄 Generating Security Report"));
            console.log(chalk.gray("─".repeat(50)));
            console.log("");

            try {
                // Load scan results
                let filepath: string;

                if (scanFile) {
                    filepath = path.isAbsolute(scanFile)
                        ? scanFile
                        : path.join(process.cwd(), scanFile);
                } else {
                    // Find latest scan
                    const scanDir = path.join(os.homedir(), ".kramscan", "scans");
                    const files = await fs.readdir(scanDir);
                    const scanFiles = files.filter((f) => f.endsWith(".json"));

                    if (scanFiles.length === 0) {
                        logger.error("No scan results found. Run 'kramscan scan <url>' first.");
                        process.exit(1);
                    }

                    scanFiles.sort().reverse();
                    filepath = path.join(scanDir, scanFiles[0]);
                    logger.info(`Using latest scan: ${scanFiles[0]}`);
                }

                const content = await fs.readFile(filepath, "utf-8");
                const scanResult: ScanResult = JSON.parse(content);

                // Determine format
                const config = getConfig();
                const format = options.format || config.report.defaultFormat;

                const spinner = logger.spinner(`Generating ${format.toUpperCase()} report...`);

                let outputPath: string;

                switch (format) {
                    case "word":
                        outputPath = await generateWordReport(scanResult, options.output);
                        break;
                    case "json":
                        outputPath = await generateJsonReport(scanResult, options.output);
                        break;
                    case "txt":
                        outputPath = await generateTxtReport(scanResult, options.output);
                        break;
                    default:
                        throw new Error(`Unsupported format: ${format}`);
                }

                spinner.succeed("Report generated!");

                console.log("");
                logger.success(`Report saved to: ${outputPath}`);
                console.log("");
            } catch (error) {
                logger.error((error as Error).message);
                process.exit(1);
            }
        });
}

async function generateWordReport(scanResult: ScanResult, outputFile?: string): Promise<string> {
    const doc = new Document({
        sections: [
            {
                properties: {},
                children: [
                    // Title
                    new Paragraph({
                        text: "Security Assessment Report",
                        heading: HeadingLevel.HEADING_1,
                        alignment: AlignmentType.CENTER,
                    }),
                    new Paragraph({
                        text: `Target: ${scanResult.target}`,
                        alignment: AlignmentType.CENTER,
                    }),
                    new Paragraph({
                        text: `Date: ${new Date(scanResult.timestamp).toLocaleString()}`,
                        alignment: AlignmentType.CENTER,
                    }),
                    new Paragraph({ text: "" }),

                    // Executive Summary
                    new Paragraph({
                        text: "Executive Summary",
                        heading: HeadingLevel.HEADING_2,
                    }),
                    new Paragraph({
                        children: [
                            new TextRun({
                                text: `This report contains the results of an automated security assessment performed on ${scanResult.target}. `,
                            }),
                            new TextRun({
                                text: `A total of ${scanResult.summary.total} vulnerabilities were identified, `,
                            }),
                            new TextRun({
                                text: `including ${scanResult.summary.critical} critical and ${scanResult.summary.high} high severity issues.`,
                            }),
                        ],
                    }),
                    new Paragraph({ text: "" }),

                    // Scan Statistics
                    new Paragraph({
                        text: "Scan Statistics",
                        heading: HeadingLevel.HEADING_2,
                    }),
                    new Paragraph({ text: `• URLs Crawled: ${scanResult.metadata.crawledUrls}` }),
                    new Paragraph({ text: `• Forms Tested: ${scanResult.metadata.testedForms}` }),
                    new Paragraph({ text: `• Requests Made: ${scanResult.metadata.requestsMade}` }),
                    new Paragraph({
                        text: `• Duration: ${(scanResult.duration / 1000).toFixed(2)} seconds`,
                    }),
                    new Paragraph({ text: "" }),

                    // Findings
                    new Paragraph({
                        text: "Detailed Findings",
                        heading: HeadingLevel.HEADING_2,
                    }),
                    ...scanResult.vulnerabilities.flatMap((vuln, i) => [
                        new Paragraph({
                            text: `${i + 1}. ${vuln.title} [${vuln.severity.toUpperCase()}]`,
                            heading: HeadingLevel.HEADING_3,
                        }),
                        new Paragraph({ text: `URL: ${vuln.url}` }),
                        new Paragraph({ text: `Type: ${vuln.type}` }),
                        new Paragraph({ text: `Description: ${vuln.description}` }),
                        ...(vuln.evidence
                            ? [new Paragraph({ text: `Evidence: ${vuln.evidence}` })]
                            : []),
                        ...(vuln.remediation
                            ? [new Paragraph({ text: `Remediation: ${vuln.remediation}` })]
                            : []),
                        ...(vuln.cwe ? [new Paragraph({ text: `CWE: ${vuln.cwe}` })] : []),
                        new Paragraph({ text: "" }),
                    ]),
                ],
            },
        ],
    });

    const buffer = await Packer.toBuffer(doc);

    const reportsDir = path.join(os.homedir(), ".kramscan", "reports");
    await fs.mkdir(reportsDir, { recursive: true });

    const timestamp = new Date().toISOString().replace(/[:.]/g, "-");
    const filename = outputFile || `report-${timestamp}.docx`;
    const filepath = path.isAbsolute(filename)
        ? filename
        : path.join(reportsDir, filename);

    await fs.writeFile(filepath, buffer);

    return filepath;
}

async function generateJsonReport(scanResult: ScanResult, outputFile?: string): Promise<string> {
    const reportsDir = path.join(os.homedir(), ".kramscan", "reports");
    await fs.mkdir(reportsDir, { recursive: true });

    const timestamp = new Date().toISOString().replace(/[:.]/g, "-");
    const filename = outputFile || `report-${timestamp}.json`;
    const filepath = path.isAbsolute(filename)
        ? filename
        : path.join(reportsDir, filename);

    await fs.writeFile(filepath, JSON.stringify(scanResult, null, 2));

    return filepath;
}

async function generateTxtReport(scanResult: ScanResult, outputFile?: string): Promise<string> {
    const lines: string[] = [];

    lines.push("=".repeat(60));
    lines.push("SECURITY ASSESSMENT REPORT");
    lines.push("=".repeat(60));
    lines.push("");
    lines.push(`Target: ${scanResult.target}`);
    lines.push(`Date: ${new Date(scanResult.timestamp).toLocaleString()}`);
    lines.push(`Duration: ${(scanResult.duration / 1000).toFixed(2)}s`);
    lines.push("");

    lines.push("EXECUTIVE SUMMARY");
    lines.push("-".repeat(60));
    lines.push(
        `Total Vulnerabilities: ${scanResult.summary.total} (${scanResult.summary.critical} Critical, ${scanResult.summary.high} High, ${scanResult.summary.medium} Medium, ${scanResult.summary.low} Low, ${scanResult.summary.info} Info)`
    );
    lines.push("");

    lines.push("SCAN STATISTICS");
    lines.push("-".repeat(60));
    lines.push(`URLs Crawled: ${scanResult.metadata.crawledUrls}`);
    lines.push(`Forms Tested: ${scanResult.metadata.testedForms}`);
    lines.push(`Requests Made: ${scanResult.metadata.requestsMade}`);
    lines.push("");

    lines.push("DETAILED FINDINGS");
    lines.push("-".repeat(60));
    lines.push("");

    scanResult.vulnerabilities.forEach((vuln, i) => {
        lines.push(`${i + 1}. ${vuln.title} [${vuln.severity.toUpperCase()}]`);
        lines.push(`   URL: ${vuln.url}`);
        lines.push(`   Type: ${vuln.type}`);
        lines.push(`   Description: ${vuln.description}`);
        if (vuln.evidence) lines.push(`   Evidence: ${vuln.evidence}`);
        if (vuln.remediation) lines.push(`   Remediation: ${vuln.remediation}`);
        if (vuln.cwe) lines.push(`   CWE: ${vuln.cwe}`);
        lines.push("");
    });

    lines.push("=".repeat(60));
    lines.push("End of Report");
    lines.push("=".repeat(60));

    const reportsDir = path.join(os.homedir(), ".kramscan", "reports");
    await fs.mkdir(reportsDir, { recursive: true });

    const timestamp = new Date().toISOString().replace(/[:.]/g, "-");
    const filename = outputFile || `report-${timestamp}.txt`;
    const filepath = path.isAbsolute(filename)
        ? filename
        : path.join(reportsDir, filename);

    await fs.writeFile(filepath, lines.join("\n"));

    return filepath;
}
