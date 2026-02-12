import { Command } from "commander";
import chalk from "chalk";
import inquirer from "inquirer";
import { getConfig, setConfig } from "../core/config";
import { logger } from "../utils/logger";

export function registerConfigCommand(program: Command): void {
    const configCmd = program
        .command("config")
        .description("View or edit configuration");

    configCmd
        .command("get <key>")
        .description("Get a configuration value")
        .action((key: string) => {
            const config = getConfig();
            const value = getNestedValue(config, key);

            if (value === undefined) {
                logger.error(`Configuration key '${key}' not found`);
                process.exit(1);
            }

            console.log(chalk.cyan(key), "=", chalk.white(JSON.stringify(value, null, 2)));
        });

    configCmd
        .command("set <key> <value>")
        .description("Set a configuration value")
        .action((key: string, value: string) => {
            const config = getConfig();

            // Parse value
            let parsedValue: any = value;
            if (value === "true") parsedValue = true;
            else if (value === "false") parsedValue = false;
            else if (!isNaN(Number(value))) parsedValue = Number(value);

            setNestedValue(config, key, parsedValue);
            setConfig(config);

            logger.success(`Set ${chalk.cyan(key)} = ${chalk.white(JSON.stringify(parsedValue))}`);
        });

    configCmd
        .command("list")
        .description("List all configuration")
        .action(() => {
            const config = getConfig();
            console.log("");
            console.log(chalk.bold.cyan("📋 Current Configuration"));
            console.log(chalk.gray("─".repeat(50)));
            console.log("");
            console.log(JSON.stringify(config, null, 2));
            console.log("");
        });

    configCmd
        .command("edit")
        .description("Interactively edit configuration")
        .action(async () => {
            const config = getConfig();

            console.log("");
            console.log(chalk.bold.cyan("⚙️  Configuration Editor"));
            console.log(chalk.gray("─".repeat(50)));
            console.log("");

            const answers = await inquirer.prompt([
                {
                    type: "confirm",
                    name: "aiEnabled",
                    message: "Enable AI analysis?",
                    default: config.ai.enabled,
                },
                {
                    type: "list",
                    name: "aiProvider",
                    message: "AI provider:",
                    choices: ["openai", "anthropic"],
                    default: config.ai.provider,
                    when: (answers) => answers.aiEnabled,
                },
                {
                    type: "input",
                    name: "apiKey",
                    message: "API key:",
                    default: config.ai.apiKey,
                    when: (answers) => answers.aiEnabled,
                },
                {
                    type: "input",
                    name: "model",
                    message: "Default AI model:",
                    default: config.ai.defaultModel,
                    when: (answers) => answers.aiEnabled,
                },
                {
                    type: "list",
                    name: "reportFormat",
                    message: "Default report format:",
                    choices: ["word", "json", "txt"],
                    default: config.report.defaultFormat,
                },
                {
                    type: "number",
                    name: "rateLimit",
                    message: "Requests per second rate limit:",
                    default: config.scan.rateLimitPerSecond,
                },
            ]);

            // Update config
            if (answers.aiEnabled !== undefined) config.ai.enabled = answers.aiEnabled;
            if (answers.aiProvider) config.ai.provider = answers.aiProvider;
            if (answers.apiKey) config.ai.apiKey = answers.apiKey;
            if (answers.model) config.ai.defaultModel = answers.model;
            if (answers.reportFormat) config.report.defaultFormat = answers.reportFormat;
            if (answers.rateLimit) config.scan.rateLimitPerSecond = answers.rateLimit;

            setConfig(config);

            console.log("");
            logger.success("Configuration updated successfully!");
            console.log("");
        });
}

function getNestedValue(obj: any, path: string): any {
    return path.split(".").reduce((current, key) => current?.[key], obj);
}

function setNestedValue(obj: any, path: string, value: any): void {
    const keys = path.split(".");
    const lastKey = keys.pop()!;
    const target = keys.reduce((current, key) => {
        if (!current[key]) current[key] = {};
        return current[key];
    }, obj);
    target[lastKey] = value;
}
