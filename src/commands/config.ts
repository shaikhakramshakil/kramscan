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
    .action(async (key: string) => {
      const config = await getConfig();
      const value = getNestedValue(config, key);

      if (value === undefined) {
        logger.error(`Configuration key '${key}' not found`);
        process.exit(1);
      }

      const displayValue =
        key === "ai.apiKey" && typeof value === "string" && value
          ? "***configured***"
          : value;

      console.log(chalk.cyan(key), "=", chalk.white(JSON.stringify(displayValue, null, 2)));
    });

  configCmd
    .command("set <key> <value>")
    .description("Set a configuration value")
    .action(async (key: string, value: string) => {
      const config = await getConfig();

      let parsedValue: unknown = value;
      if (value === "true") {
        parsedValue = true;
      } else if (value === "false") {
        parsedValue = false;
      } else if (!Number.isNaN(Number(value))) {
        parsedValue = Number(value);
      }

      setNestedValue(config, key, parsedValue);
      await setConfig(config);

      logger.success(
        `Set ${chalk.cyan(key)} = ${chalk.white(JSON.stringify(parsedValue))}`
      );
    });

  configCmd
    .command("list")
    .description("List all configuration")
    .action(async () => {
      const config = await getConfig();
      const sanitizedConfig = {
        ...config,
        ai: {
          ...config.ai,
          apiKey: config.ai.apiKey ? "***configured***" : "",
        },
      };

      console.log("");
      console.log(chalk.bold.cyan("Current Configuration"));
      console.log(chalk.gray("-".repeat(50)));
      console.log("");
      console.log(JSON.stringify(sanitizedConfig, null, 2));
      console.log("");
    });

  configCmd
    .command("edit")
    .description("Interactively edit configuration")
    .action(async () => {
      const config = await getConfig();

      console.log("");
      console.log(chalk.bold.cyan("Configuration Editor"));
      console.log(chalk.gray("-".repeat(50)));
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
          choices: ["openai", "anthropic", "gemini", "openrouter", "mistral", "kimi", "groq"],
          default: config.ai.provider,
          when: (ans) => ans.aiEnabled,
        },
        {
          type: "input",
          name: "apiKey",
          message: "API key (leave blank to keep current):",
          default: "",
          when: (ans) => ans.aiEnabled,
        },
        {
          type: "input",
          name: "model",
          message: "Default AI model:",
          default: config.ai.defaultModel,
          when: (ans) => ans.aiEnabled,
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
          validate: (value: number) =>
            Number.isFinite(value) && value > 0
              ? true
              : "Rate limit must be a positive number",
        },
      ]);

      if (answers.aiEnabled !== undefined) {
        config.ai.enabled = answers.aiEnabled;
      }
      if (answers.aiProvider) {
        config.ai.provider = answers.aiProvider;
      }
      if (answers.apiKey) {
        config.ai.apiKey = answers.apiKey;
      }
      if (answers.model) {
        config.ai.defaultModel = answers.model;
      }
      if (answers.reportFormat) {
        config.report.defaultFormat = answers.reportFormat;
      }
      if (Number.isFinite(answers.rateLimit) && answers.rateLimit > 0) {
        config.scan.rateLimitPerSecond = answers.rateLimit;
      }

      await setConfig(config);

      console.log("");
      logger.success("Configuration updated successfully!");
      console.log("");
    });
}

function getNestedValue(obj: unknown, keyPath: string): unknown {
  return keyPath
    .split(".")
    .reduce<unknown>((current, key) => (current as Record<string, unknown> | undefined)?.[key], obj);
}

function setNestedValue(obj: unknown, keyPath: string, value: unknown): void {
  const keys = keyPath.split(".");
  const lastKey = keys.pop();
  if (!lastKey) {
    return;
  }

  const target = keys.reduce<Record<string, unknown>>((current, key) => {
    if (!current[key] || typeof current[key] !== "object") {
      current[key] = {};
    }
    return current[key] as Record<string, unknown>;
  }, obj as Record<string, unknown>);

  target[lastKey] = value;
}
