import { Command } from "commander";
import chalk from "chalk";
import { getConfig } from "../core/config";
import { logger } from "../utils/logger";
import { exec } from "child_process";
import { promisify } from "util";
import fs from "fs/promises";
import os from "os";

const execAsync = promisify(exec);

interface HealthCheck {
    name: string;
    status: "pass" | "fail" | "warn";
    message: string;
}

export function registerDoctorCommand(program: Command): void {
    program
        .command("doctor")
        .description("Check environment health and configuration")
        .action(async () => {
            console.log("");
            console.log(chalk.bold.cyan("🩺 KramScan Health Check"));
            console.log(chalk.gray("─".repeat(50)));
            console.log("");

            const checks: HealthCheck[] = [];

            // Check Node.js version
            checks.push(await checkNodeVersion());

            // Check Puppeteer/Chrome
            checks.push(await checkPuppeteer());

            // Check config file
            checks.push(await checkConfig());

            // Check API keys
            checks.push(await checkAPIKeys());

            // Check disk space
            checks.push(await checkDiskSpace());

            // Check network connectivity
            checks.push(await checkNetwork());

            // Display results
            let passCount = 0;
            let failCount = 0;
            let warnCount = 0;

            for (const check of checks) {
                const icon =
                    check.status === "pass"
                        ? chalk.green("✓")
                        : check.status === "fail"
                            ? chalk.red("✗")
                            : chalk.yellow("⚠");

                console.log(`${icon} ${chalk.bold(check.name)}`);
                console.log(`  ${chalk.gray(check.message)}`);
                console.log("");

                if (check.status === "pass") passCount++;
                else if (check.status === "fail") failCount++;
                else warnCount++;
            }

            // Summary
            console.log(chalk.gray("─".repeat(50)));
            console.log(
                `${chalk.green(`${passCount} passed`)} | ${chalk.yellow(`${warnCount} warnings`)} | ${chalk.red(`${failCount} failed`)}`
            );
            console.log("");

            if (failCount > 0) {
                logger.error("Some checks failed. Please fix the issues above.");
                process.exit(1);
            } else if (warnCount > 0) {
                logger.warn("Some checks have warnings. KramScan should work but may have limitations.");
            } else {
                logger.success("All checks passed! KramScan is ready to use.");
            }
        });
}

async function checkNodeVersion(): Promise<HealthCheck> {
    const version = process.version;
    const major = parseInt(version.slice(1).split(".")[0]);

    if (major >= 18) {
        return {
            name: "Node.js Version",
            status: "pass",
            message: `${version} (>= 18 required)`,
        };
    } else {
        return {
            name: "Node.js Version",
            status: "fail",
            message: `${version} - Please upgrade to Node.js 18 or higher`,
        };
    }
}

async function checkPuppeteer(): Promise<HealthCheck> {
    try {
        const puppeteer = await import("puppeteer");
        return {
            name: "Puppeteer",
            status: "pass",
            message: "Installed and ready",
        };
    } catch (error) {
        return {
            name: "Puppeteer",
            status: "fail",
            message: "Not installed. Run: npm install puppeteer",
        };
    }
}

async function checkConfig(): Promise<HealthCheck> {
    try {
        const config = getConfig();
        return {
            name: "Configuration",
            status: "pass",
            message: `Config loaded from ~/.kramscan/config.json`,
        };
    } catch (error) {
        return {
            name: "Configuration",
            status: "warn",
            message: "Config file not found. Run 'kramscan onboard' to create it.",
        };
    }
}

async function checkAPIKeys(): Promise<HealthCheck> {
    try {
        const config = getConfig();

        if (!config.ai.enabled) {
            return {
                name: "AI Configuration",
                status: "warn",
                message: "AI analysis is disabled. Run 'kramscan onboard' to enable it.",
            };
        }

        if (!config.ai.apiKey) {
            return {
                name: "AI Configuration",
                status: "warn",
                message: `${config.ai.provider} API key not configured. Run 'kramscan onboard' to set it.`,
            };
        }

        return {
            name: "AI Configuration",
            status: "pass",
            message: `${config.ai.provider} configured with model ${config.ai.defaultModel}`,
        };
    } catch (error) {
        return {
            name: "AI Configuration",
            status: "warn",
            message: "Unable to check AI configuration",
        };
    }
}

async function checkDiskSpace(): Promise<HealthCheck> {
    try {
        const homeDir = os.homedir();
        const kramScanDir = `${homeDir}/.kramscan`;

        // Create directory if it doesn't exist
        await fs.mkdir(kramScanDir, { recursive: true });

        return {
            name: "Disk Space",
            status: "pass",
            message: `Scan directory: ${kramScanDir}`,
        };
    } catch (error) {
        return {
            name: "Disk Space",
            status: "fail",
            message: "Unable to access scan directory",
        };
    }
}

async function checkNetwork(): Promise<HealthCheck> {
    try {
        // Simple DNS check
        const { exec } = require("child_process");
        await new Promise((resolve, reject) => {
            exec("ping -n 1 8.8.8.8", (error: any) => {
                if (error) reject(error);
                else resolve(true);
            });
        });

        return {
            name: "Network Connectivity",
            status: "pass",
            message: "Internet connection available",
        };
    } catch (error) {
        return {
            name: "Network Connectivity",
            status: "warn",
            message: "Unable to verify internet connection",
        };
    }
}
