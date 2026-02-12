/**
 * Confirmation Prompt System
 * Handles user confirmation for skill execution with detailed risk assessment
 */

import * as readline from "readline";
import { ConfirmationPrompt } from "./types";
import chalk from "chalk";

export interface ConfirmationResult {
  confirmed: boolean;
  showDetails: boolean;
  cancelled: boolean;
}

export class ConfirmationHandler {
  private rl: readline.Interface;

  constructor() {
    this.rl = readline.createInterface({
      input: process.stdin,
      output: process.stdout,
    });
  }

  /**
   * Display confirmation prompt and get user response
   */
  async prompt(confirmation: ConfirmationPrompt): Promise<ConfirmationResult> {
    console.log("");
    console.log(chalk.bold.yellow("⚠️  Action Requires Confirmation"));
    console.log(chalk.gray("─".repeat(50)));
    console.log("");

    // Display action details
    console.log(chalk.white("Action:"), chalk.cyan(confirmation.action));
    console.log(chalk.white("Description:"), confirmation.description);
    console.log("");

    // Display risk level with color coding
    const riskColor = this.getRiskColor(confirmation.risk);
    console.log(
      chalk.white("Risk Level:"),
      riskColor(confirmation.risk.toUpperCase())
    );
    console.log(chalk.white("Estimated Time:"), confirmation.estimatedTime);
    console.log("");

    // Display parameters
    console.log(chalk.white("Parameters:"));
    Object.entries(confirmation.parameters).forEach(([key, value]) => {
      const displayValue =
        typeof value === "object" ? JSON.stringify(value) : String(value);
      console.log(`  ${chalk.gray(key)}: ${chalk.white(displayValue)}`);
    });
    console.log("");

    // Risk warnings
    if (confirmation.risk === "high") {
      console.log(
        chalk.red.bold("⚠️  WARNING: This action may have significant impact.")
      );
    } else if (confirmation.risk === "medium") {
      console.log(
        chalk.yellow("⚠️  This action will interact with external systems.")
      );
    }
    console.log("");

    // Get user input
    return this.getUserInput();
  }

  /**
   * Quick confirmation for low-risk actions
   */
  async quickConfirm(action: string): Promise<boolean> {
    return new Promise((resolve) => {
      this.rl.question(
        chalk.gray(`${action} [Y/n]: `),
        (answer: string) => {
          const normalized = answer.trim().toLowerCase();
          resolve(normalized === "" || normalized === "y" || normalized === "yes");
        }
      );
    });
  }

  /**
   * Display detailed information about the action
   */
  showDetails(confirmation: ConfirmationPrompt): void {
    console.log("");
    console.log(chalk.bold.cyan("📋 Action Details"));
    console.log(chalk.gray("─".repeat(50)));
    console.log("");

    console.log(chalk.white("What will happen:"));
    console.log(chalk.gray(this.getDetailedDescription(confirmation.action)));
    console.log("");

    console.log(chalk.white("Safety considerations:"));
    console.log(chalk.gray(this.getSafetyInfo(confirmation.risk)));
    console.log("");

    if (confirmation.risk === "high") {
      console.log(chalk.yellow("Recommendations:"));
      console.log(chalk.gray("• Ensure you have proper authorization"));
      console.log(chalk.gray("• Verify the target is correct"));
      console.log(chalk.gray("• Consider testing in a safe environment first"));
      console.log("");
    }
  }

  /**
   * Close the readline interface
   */
  close(): void {
    this.rl.close();
  }

  private async getUserInput(): Promise<ConfirmationResult> {
    return new Promise((resolve) => {
      const askQuestion = () => {
        this.rl.question(
          chalk.gray("Proceed? [Y/n/details/cancel]: "),
          (answer: string) => {
            const normalized = answer.trim().toLowerCase();

            if (normalized === "" || normalized === "y" || normalized === "yes") {
              resolve({ confirmed: true, showDetails: false, cancelled: false });
            } else if (normalized === "n" || normalized === "no") {
              resolve({ confirmed: false, showDetails: false, cancelled: false });
            } else if (normalized === "details" || normalized === "d") {
              resolve({ confirmed: false, showDetails: true, cancelled: false });
            } else if (normalized === "cancel" || normalized === "c") {
              resolve({ confirmed: false, showDetails: false, cancelled: true });
            } else {
              console.log(chalk.gray("Please enter: Y, n, details, or cancel"));
              askQuestion();
            }
          }
        );
      };

      askQuestion();
    });
  }

  private getRiskColor(risk: string): (text: string) => string {
    switch (risk) {
      case "high":
        return chalk.red.bold;
      case "medium":
        return chalk.yellow;
      case "low":
        return chalk.green;
      default:
        return chalk.gray;
    }
  }

  private getDetailedDescription(action: string): string {
    const descriptions: Record<string, string> = {
      "Web Scan":
        "This will crawl the target website and test for common vulnerabilities including XSS, SQL injection, CSRF, and security header misconfigurations. The scan sends HTTP requests to the target.",
      "Analyze Findings":
        "This will use AI to analyze previously discovered vulnerabilities and provide detailed remediation recommendations.",
      "Generate Report":
        "This will create a professional security report document based on scan results.",
      "Check Environment":
        "This will verify your system configuration, API keys, and dependencies.",
      "View Configuration":
        "This will display your current KramScan configuration settings.",
    };

    return (
      descriptions[action] ||
      "This action will execute the requested security operation."
    );
  }

  private getSafetyInfo(risk: string): string {
    switch (risk) {
      case "high":
        return "This action may trigger security systems, generate significant network traffic, or have other notable effects. Use with caution.";
      case "medium":
        return "This action will make network requests to external systems. Ensure you have permission to test the target.";
      case "low":
        return "This is a safe, read-only operation that won't modify any external systems.";
      default:
        return "Please review the action details carefully before proceeding.";
    }
  }
}
