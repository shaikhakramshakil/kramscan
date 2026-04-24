/**
 * Init Command
 * Generates a .kramscanrc project configuration file in the current directory.
 */

import { Command } from "commander";
import chalk from "chalk";
import inquirer from "inquirer";
import fs from "fs/promises";
import path from "path";
import { PROJECT_CONFIG_FILENAME, ProjectConfig } from "../core/project-config";
import { logger } from "../utils/logger";

export function registerInitCommand(program: Command): void {
    program
        .command("init")
        .description("Generate a .kramscanrc project configuration file")
        .option("-y, --yes", "Skip prompts and generate with defaults")
        .option("--force", "Overwrite existing .kramscanrc file")
        .action(async (options) => {
            const targetPath = path.join(process.cwd(), PROJECT_CONFIG_FILENAME);

            console.log("");
            console.log(chalk.bold.cyan("KramScan Project Setup"));
            console.log(chalk.gray("─".repeat(50)));
            console.log("");

            // Check if file already exists
            try {
                await fs.access(targetPath);
                if (!options.force) {
                    console.log(chalk.yellow(`  A ${PROJECT_CONFIG_FILENAME} file already exists in this directory.`));
                    console.log(chalk.gray(`  Use ${chalk.white("--force")} to overwrite it.`));
                    console.log("");
                    return;
                }
            } catch {
                // File doesn't exist — good
            }

            let config: ProjectConfig;

            if (options.yes) {
                config = getDefaultProjectConfig();
            } else {
                config = await runInteractiveSetup();
            }

            // Write the file
            const content = JSON.stringify(config, null, 2) + "\n";
            await fs.writeFile(targetPath, content, "utf-8");

            console.log("");
            logger.success(`Created ${PROJECT_CONFIG_FILENAME} in ${process.cwd()}`);
            console.log("");
            console.log(chalk.gray("  This file configures KramScan for this project."));
            console.log(chalk.gray("  Commit it to version control so your team shares the same settings."));
            console.log(chalk.gray(`  API keys are never stored here — use ${chalk.white("kramscan onboard")} or env vars.`));
            console.log("");
        });
}

function getDefaultProjectConfig(): ProjectConfig {
    return {
        scan: {
            defaultProfile: "balanced",
            defaultTimeout: 30000,
            strictScope: true,
            exclude: [
                "logout",
                "signout",
                "delete",
            ],
        },
        report: {
            defaultFormat: "markdown",
            companyName: "Your Company",
        },
        gate: {
            failOn: "high",
            maxVulns: 0,
        },
        plugins: {
            disabled: [],
        },
    };
}

async function runInteractiveSetup(): Promise<ProjectConfig> {
    const answers = await inquirer.prompt([
        {
            type: "list",
            name: "profile",
            message: "Default scan profile:",
            choices: [
                { name: "quick    — fast surface-level scan", value: "quick" },
                { name: "balanced — good coverage, moderate speed", value: "balanced" },
                { name: "deep     — thorough crawl, slower", value: "deep" },
            ],
            default: "balanced",
        },
        {
            type: "input",
            name: "timeout",
            message: "Default request timeout (ms):",
            default: "30000",
            validate: (input: string) => {
                const n = parseInt(input, 10);
                if (isNaN(n) || n < 1000) return "Must be a number >= 1000";
                return true;
            },
            filter: (input: string) => parseInt(input, 10),
        },
        {
            type: "confirm",
            name: "strictScope",
            message: "Stay within the target domain? (strict scope)",
            default: true,
        },
        {
            type: "input",
            name: "exclude",
            message: "URL patterns to exclude (comma-separated, e.g. logout,signout):",
            default: "logout,signout,delete",
            filter: (input: string) =>
                input
                    .split(",")
                    .map((s: string) => s.trim())
                    .filter(Boolean),
        },
        {
            type: "list",
            name: "reportFormat",
            message: "Default report format:",
            choices: [
                { name: "markdown", value: "markdown" },
                { name: "word (.docx)", value: "word" },
                { name: "json", value: "json" },
                { name: "txt", value: "txt" },
            ],
            default: "markdown",
        },
        {
            type: "input",
            name: "companyName",
            message: "Company or project name (for report headers):",
            default: path.basename(process.cwd()),
        },
        {
            type: "list",
            name: "gateFailOn",
            message: "CI/CD gate — fail on severity at or above:",
            choices: [
                { name: "critical — only block on critical issues", value: "critical" },
                { name: "high     — block on high and critical", value: "high" },
                { name: "medium   — block on medium and above", value: "medium" },
                { name: "low      — block on everything except info", value: "low" },
            ],
            default: "high",
        },
        {
            type: "input",
            name: "gateMaxVulns",
            message: "CI/CD gate — max allowed vulnerabilities before failing:",
            default: "0",
            validate: (input: string) => {
                const n = parseInt(input, 10);
                if (isNaN(n) || n < 0) return "Must be a non-negative number";
                return true;
            },
            filter: (input: string) => parseInt(input, 10),
        },
    ]);

    return {
        scan: {
            defaultProfile: answers.profile,
            defaultTimeout: answers.timeout,
            strictScope: answers.strictScope,
            exclude: answers.exclude,
        },
        report: {
            defaultFormat: answers.reportFormat,
            companyName: answers.companyName,
        },
        gate: {
            failOn: answers.gateFailOn,
            maxVulns: answers.gateMaxVulns,
        },
        plugins: {
            disabled: [],
        },
    };
}
