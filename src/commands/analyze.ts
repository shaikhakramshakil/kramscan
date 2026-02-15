import { Command } from "commander";
import chalk from "chalk";
import { createAIClient } from "../core/ai-client";
import { ScanResult } from "../core/vulnerability-detector";
import { resolveScanFile } from "../core/scan-storage";
import { logger } from "../utils/logger";
import fs from "fs/promises";

export function registerAnalyzeCommand(program: Command): void {
  program
    .command("analyze [scan-file]")
    .description("AI-powered analysis of scan results")
    .option("-m, --model <name>", "Override default AI model")
    .option("-v, --verbose", "Show detailed analysis")
    .action(async (scanFile: string | undefined) => {
      console.log("");
      console.log(chalk.bold.cyan("AI Security Analysis"));
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

        if (scanResult.vulnerabilities.length === 0) {
          logger.success("No vulnerabilities to analyze!");
          return;
        }

        spinner = logger.spinner("Analyzing vulnerabilities with AI...");

        const aiClient = await createAIClient();
        const prompt = buildAnalysisPrompt(scanResult);
        const response = await aiClient.analyze(prompt);

        spinner.succeed("Analysis complete!");

        console.log("");
        console.log(chalk.bold("AI Analysis"));
        console.log(chalk.gray("-".repeat(50)));
        console.log("");
        console.log(response.content);
        console.log("");

        if (response.usage) {
          console.log(chalk.gray("-".repeat(50)));
          console.log(
            chalk.gray(
              `Tokens used: ${response.usage.totalTokens} (${response.usage.promptTokens} prompt + ${response.usage.completionTokens} completion)`
            )
          );
          console.log("");
        }

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
        if (spinner) {
          spinner.fail("Analysis failed");
        }
        logger.error((error as Error).message);
        process.exit(1);
      }
    });
}

function buildAnalysisPrompt(scanResult: ScanResult): string {
  const vulnList = scanResult.vulnerabilities
    .map(
      (v, i) =>
        `${i + 1}. [${v.severity.toUpperCase()}] ${v.title}\n` +
        `   URL: ${v.url}\n` +
        `   Description: ${v.description}\n` +
        `${v.evidence ? `   Evidence: ${v.evidence}\n` : ""}` +
        `${v.cwe ? `   CWE: ${v.cwe}` : ""}`
    )
    .join("\n\n");

  return `You are a security expert analyzing web application vulnerabilities.

Target: ${scanResult.target}
Scan Date: ${scanResult.timestamp}
Total Vulnerabilities: ${scanResult.summary.total}

Vulnerabilities Found:
${vulnList}

Please provide:
1. Executive Summary: Brief overview of the security posture
2. Risk Assessment: Overall risk level and business impact
3. Priority Recommendations: Top 3-5 vulnerabilities to fix first, with specific remediation steps
4. Attack Scenarios: How an attacker could chain these vulnerabilities
5. Remediation Roadmap: Step-by-step plan to address all findings

Format your response in clear markdown with headers and bullet points.`;
}
