import { Command } from "commander";
import chalk from "chalk";
import { createAIClient } from "../core/ai-client";
import { ScanResult } from "../core/vulnerability-detector";
import { logger } from "../utils/logger";
import fs from "fs/promises";
import path from "path";
import os from "os";

export function registerAnalyzeCommand(program: Command): void {
    program
        .command("analyze [scan-file]")
        .description("AI-powered analysis of scan results")
        .option("-m, --model <name>", "Override default AI model")
        .option("-v, --verbose", "Show detailed analysis")
        .action(async (scanFile: string | undefined, options) => {
            console.log("");
            console.log(chalk.bold.cyan("🧠 AI Security Analysis"));
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

                    // Get most recent
                    scanFiles.sort().reverse();
                    filepath = path.join(scanDir, scanFiles[0]);
                    logger.info(`Using latest scan: ${scanFiles[0]}`);
                }

                const content = await fs.readFile(filepath, "utf-8");
                const scanResult: ScanResult = JSON.parse(content);

                if (scanResult.vulnerabilities.length === 0) {
                    logger.success("No vulnerabilities to analyze!");
                    return;
                }

                const spinner = logger.spinner("Analyzing vulnerabilities with AI...");

                // Create AI client
                const aiClient = await createAIClient();

                // Build analysis prompt
                const prompt = buildAnalysisPrompt(scanResult);

                // Get AI analysis
                const response = await aiClient.analyze(prompt);

                spinner.succeed("Analysis complete!");

                console.log("");
                console.log(chalk.bold("📝 AI Analysis"));
                console.log(chalk.gray("─".repeat(50)));
                console.log("");
                console.log(response.content);
                console.log("");

                if (response.usage) {
                    console.log(chalk.gray("─".repeat(50)));
                    console.log(
                        chalk.gray(
                            `Tokens used: ${response.usage.totalTokens} (${response.usage.promptTokens} prompt + ${response.usage.completionTokens} completion)`
                        )
                    );
                    console.log("");
                }

                // Save enhanced results
                const enhancedResult = {
                    ...scanResult,
                    aiAnalysis: {
                        timestamp: new Date().toISOString(),
                        analysis: response.content,
                        usage: response.usage,
                    },
                };

                await fs.writeFile(filepath, JSON.stringify(enhancedResult, null, 2));
                logger.success(`Enhanced results saved to ${filepath}`);
                console.log("");
            } catch (error) {
                logger.error((error as Error).message);
                process.exit(1);
            }
        });
}

function buildAnalysisPrompt(scanResult: ScanResult): string {
    const vulnList = scanResult.vulnerabilities
        .map(
            (v, i) =>
                `${i + 1}. [${v.severity.toUpperCase()}] ${v.title}
   URL: ${v.url}
   Description: ${v.description}
   ${v.evidence ? `Evidence: ${v.evidence}` : ""}
   ${v.cwe ? `CWE: ${v.cwe}` : ""}`
        )
        .join("\n\n");

    return `You are a security expert analyzing web application vulnerabilities.

Target: ${scanResult.target}
Scan Date: ${scanResult.timestamp}
Total Vulnerabilities: ${scanResult.summary.total}

Vulnerabilities Found:
${vulnList}

Please provide:
1. **Executive Summary**: Brief overview of the security posture
2. **Risk Assessment**: Overall risk level and business impact
3. **Priority Recommendations**: Top 3-5 vulnerabilities to fix first, with specific remediation steps
4. **Attack Scenarios**: How an attacker could chain these vulnerabilities
5. **Remediation Roadmap**: Step-by-step plan to address all findings

Format your response in clear markdown with headers and bullet points.`;
}
