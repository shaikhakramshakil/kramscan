import { Command } from "commander";
import chalk from "chalk";
import {
  AlignmentType,
  Document,
  HeadingLevel,
  Packer,
  Paragraph,
  TextRun,
} from "docx";
import fs from "fs/promises";
import path from "path";
import os from "os";
import inquirer from "inquirer";
import { getConfig } from "../core/config";
import { ensureReportsDirectory, resolveScanFile } from "../core/scan-storage";
import { ScanResult } from "../core/vulnerability-detector";
import { createAIClient, generateExecutiveSummary } from "../core/ai-client";
import { logger } from "../utils/logger";

export function registerReportCommand(program: Command): void {
  program
    .command("report [scan-file]")
    .description("Generate a professional security report")
    .option("-f, --format <type>", "Report format: word|json|txt|markdown")
    .option("-o, --output <file>", "Output filename")
    .option("--ai-summary", "Generate an AI-powered executive summary")
    .action(async (scanFile: string | undefined, options) => {
      console.log("");
      console.log(chalk.bold.cyan("Generating Security Report"));
      console.log(chalk.gray("-".repeat(50)));
      console.log("");

      let spinner: ReturnType<typeof logger.spinner> | null = null;

      try {
        const resolved = await resolveScanFile(scanFile);
        const filepath = resolved.filepath;
        if (resolved.isLatest) {
          logger.info(`Using latest scan: ${resolved.filename}`);
        }

        const content = await fs.readFile(filepath, "utf-8");
        const scanResult: ScanResult = JSON.parse(content);

        const config = await getConfig();
        let format = (options.format || config.report.defaultFormat) as string;

        if (!options.format && !config.report.defaultFormat) {
            format = "markdown";
        }

        let aiSummary: string | undefined;
        if (options.aiSummary) {
          spinner = logger.spinner("Generating AI executive summary...");
          try {
            const aiClient = await createAIClient();
            aiSummary = await generateExecutiveSummary(aiClient, scanResult);
            spinner.succeed("AI summary generated!");
          } catch (err) {
            spinner.warn(`AI summary failed: ${(err as Error).message}`);
          }
        }

        let outputDir = "";
        if (!options.output) {
            const { location } = await inquirer.prompt([
                {
                    type: "list",
                    name: "location",
                    message: "Where should the report be saved?",
                    choices: [
                        { name: "Current Project Directory (./)", value: "cwd" },
                        { name: "Desktop", value: "desktop" },
                        { name: "Default Reports Directory (~/.kramscan/reports/)", value: "default" }
                    ]
                }
            ]);

            if (location === "cwd") {
                outputDir = process.cwd();
            } else if (location === "desktop") {
                outputDir = path.join(os.homedir(), "Desktop");
            }
        }

        spinner = logger.spinner(`Generating ${format.toUpperCase()} report...`);

        let outputPath: string;

        switch (format) {
          case "word":
            outputPath = await generateWordReport(scanResult, options.output, aiSummary, outputDir);
            break;
          case "json":
            outputPath = await generateJsonReport(scanResult, options.output, aiSummary, outputDir);
            break;
          case "txt":
            outputPath = await generateTxtReport(scanResult, options.output, aiSummary, outputDir);
            break;
          case "markdown":
          case "md":
            outputPath = await generateMarkdownReport(scanResult, options.output, aiSummary, outputDir);
            break;
          default:
            throw new Error(`Unsupported format: ${format}`);
        }

        spinner.succeed("Report generated!");

        console.log("");
        logger.success(`Report saved to: ${outputPath}`);
        console.log("");
      } catch (error) {
        if (spinner) {
          spinner.fail("Report generation failed");
        }
        logger.error((error as Error).message);
        process.exit(1);
      }
    });
}

async function generateWordReport(
  scanResult: ScanResult,
  outputFile?: string,
  aiSummary?: string,
  outputDir?: string
): Promise<string> {
  const doc = new Document({
    sections: [
      {
        properties: {},
        children: [
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

          new Paragraph({
            text: "Executive Summary",
            heading: HeadingLevel.HEADING_2,
          }),
          new Paragraph({
            children: [
              new TextRun({
                text: aiSummary || `This report contains the results of an automated security assessment performed on ${scanResult.target}. ` +
                  `A total of ${scanResult.summary.total} vulnerabilities were identified, ` +
                  `including ${scanResult.summary.critical} critical and ${scanResult.summary.high} high severity issues.`,
              }),
            ],
          }),
          new Paragraph({ text: "" }),

          new Paragraph({
            text: "Scan Statistics",
            heading: HeadingLevel.HEADING_2,
          }),
          new Paragraph({ text: `- URLs Crawled: ${scanResult.metadata.crawledUrls}` }),
          new Paragraph({ text: `- Forms Tested: ${scanResult.metadata.testedForms}` }),
          new Paragraph({ text: `- Requests Made: ${scanResult.metadata.requestsMade}` }),
          new Paragraph({
            text: `- Duration: ${(scanResult.duration / 1000).toFixed(2)} seconds`,
          }),
          new Paragraph({ text: "" }),

          new Paragraph({
            text: "Detailed Findings",
            heading: HeadingLevel.HEADING_2,
          }),
          ...scanResult.vulnerabilities.flatMap((vuln, index) => [
            new Paragraph({
              text: `${index + 1}. ${vuln.title} [${vuln.severity.toUpperCase()}]`,
              heading: HeadingLevel.HEADING_3,
            }),
            new Paragraph({ text: `URL: ${vuln.url}` }),
            new Paragraph({ text: `Type: ${vuln.type}` }),
            new Paragraph({ text: `Description: ${vuln.description}` }),
            ...(vuln.evidence ? [new Paragraph({ text: `Evidence: ${vuln.evidence}` })] : []),
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
  const reportsDir = outputDir || await ensureReportsDirectory();

  const timestamp = new Date().toISOString().replace(/[:.]/g, "-");
  const filename = outputFile || `report-${timestamp}.docx`;
  const filepath = path.isAbsolute(filename) ? filename : path.join(reportsDir, filename);

  await fs.writeFile(filepath, buffer);
  return filepath;
}

async function generateJsonReport(
  scanResult: ScanResult,
  outputFile?: string,
  aiSummary?: string,
  outputDir?: string
): Promise<string> {
  const reportsDir = outputDir || await ensureReportsDirectory();

  const timestamp = new Date().toISOString().replace(/[:.]/g, "-");
  const filename = outputFile || `report-${timestamp}.json`;
  const filepath = path.isAbsolute(filename) ? filename : path.join(reportsDir, filename);

  const finalResult = aiSummary ? { ...scanResult, aiSummary } : scanResult;
  await fs.writeFile(filepath, JSON.stringify(finalResult, null, 2));
  return filepath;
}

async function generateTxtReport(
  scanResult: ScanResult,
  outputFile?: string,
  aiSummary?: string,
  outputDir?: string
): Promise<string> {
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
  if (aiSummary) {
    lines.push(aiSummary);
  } else {
    lines.push(
      `Total Vulnerabilities: ${scanResult.summary.total} (${scanResult.summary.critical} Critical, ${scanResult.summary.high} High, ${scanResult.summary.medium} Medium, ${scanResult.summary.low} Low, ${scanResult.summary.info} Info)`
    );
  }
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

  scanResult.vulnerabilities.forEach((vuln, index) => {
    lines.push(`${index + 1}. ${vuln.title} [${vuln.severity.toUpperCase()}]`);
    lines.push(`   URL: ${vuln.url}`);
    lines.push(`   Type: ${vuln.type}`);
    lines.push(`   Description: ${vuln.description}`);
    if (vuln.evidence) {
      lines.push(`   Evidence: ${vuln.evidence}`);
    }
    if (vuln.remediation) {
      lines.push(`   Remediation: ${vuln.remediation}`);
    }
    if (vuln.cwe) {
      lines.push(`   CWE: ${vuln.cwe}`);
    }
    lines.push("");
  });

  lines.push("=".repeat(60));
  lines.push("End of Report");
  lines.push("=".repeat(60));

  const reportsDir = outputDir || await ensureReportsDirectory();

  const timestamp = new Date().toISOString().replace(/[:.]/g, "-");
  const filename = outputFile || `report-${timestamp}.txt`;
  const filepath = path.isAbsolute(filename) ? filename : path.join(reportsDir, filename);

  await fs.writeFile(filepath, lines.join("\n"));
  return filepath;
}

async function generateMarkdownReport(
  scanResult: ScanResult,
  outputFile?: string,
  aiSummary?: string,
  outputDir?: string
): Promise<string> {
  const lines: string[] = [];

  lines.push("# Security Assessment Report");
  lines.push("");
  lines.push(`**Target:** \`${scanResult.target}\``);
  lines.push(`**Date:** ${new Date(scanResult.timestamp).toLocaleString()}`);
  lines.push(`**Duration:** ${(scanResult.duration / 1000).toFixed(2)}s`);
  lines.push("");

  lines.push("## Executive Summary");
  if (aiSummary) {
    lines.push(aiSummary);
  } else {
    lines.push(
      `Total Vulnerabilities: **${scanResult.summary.total}** (${scanResult.summary.critical} Critical, ${scanResult.summary.high} High, ${scanResult.summary.medium} Medium, ${scanResult.summary.low} Low, ${scanResult.summary.info} Info)`
    );
  }
  lines.push("");

  lines.push("## Scan Statistics");
  lines.push(`- **URLs Crawled:** ${scanResult.metadata.crawledUrls}`);
  lines.push(`- **Forms Tested:** ${scanResult.metadata.testedForms}`);
  lines.push(`- **Requests Made:** ${scanResult.metadata.requestsMade}`);
  lines.push("");

  lines.push("## Detailed Findings");
  lines.push("");

  scanResult.vulnerabilities.forEach((vuln, index) => {
    lines.push(`### ${index + 1}. ${vuln.title} [${vuln.severity.toUpperCase()}]`);
    lines.push(`- **URL:** \`${vuln.url}\``);
    lines.push(`- **Type:** ${vuln.type}`);
    lines.push(`- **Description:** ${vuln.description}`);
    if (vuln.evidence) {
      lines.push(`- **Evidence:** \`${vuln.evidence}\``);
    }
    if (vuln.remediation) {
      lines.push(`- **Remediation:** ${vuln.remediation}`);
    }
    if (vuln.cwe) {
      lines.push(`- **CWE:** ${vuln.cwe}`);
    }
    lines.push("");
  });

  lines.push("---");
  lines.push("*Generated by KramScan*");

  const reportsDir = outputDir || await ensureReportsDirectory();

  const timestamp = new Date().toISOString().replace(/[:.]/g, "-");
  const filename = outputFile || `report-${timestamp}.md`;
  const filepath = path.isAbsolute(filename) ? filename : path.join(reportsDir, filename);

  await fs.writeFile(filepath, lines.join("\n"));
  return filepath;
}
