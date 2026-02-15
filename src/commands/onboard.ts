import { Command } from "commander";
import inquirer from "inquirer";
import axios from "axios";
import OpenAI from "openai";
import { Config, getConfig, setConfig } from "../core/config";
import { logger } from "../utils/logger";

function getDefaultModel(provider: Config["ai"]["provider"]): string {
  switch (provider) {
    case "anthropic":
      return "claude-3-5-sonnet-20241022";
    case "gemini":
      return "gemini-2.0-flash";
    case "openrouter":
      return "anthropic/claude-3.5-sonnet";
    case "mistral":
      return "mistral-large-latest";
    case "kimi":
      return "moonshot-v1-8k";
    case "groq":
      return "llama-3.1-8b-instant";
    default:
      return "gpt-4";
  }
}

function getEnvApiKey(provider: string): string {
  const envVars: Record<string, string | undefined> = {
    openai: process.env.OPENAI_API_KEY,
    anthropic: process.env.ANTHROPIC_API_KEY,
    gemini: process.env.GEMINI_API_KEY,
    mistral: process.env.MISTRAL_API_KEY,
    openrouter: process.env.OPENROUTER_API_KEY,
    kimi: process.env.KIMI_API_KEY,
    groq: process.env.GROQ_API_KEY,
  };
  return envVars[provider] || "";
}

async function modelExists(
  provider: string,
  apiKey: string,
  model: string
): Promise<boolean> {
  if (!apiKey || !model) {
    return true;
  }

  if (provider === "gemini") {
    const resp = await axios.get(
      "https://generativelanguage.googleapis.com/v1beta/models",
      { params: { key: apiKey } }
    );

    const models: Array<{
      name: string;
      supportedGenerationMethods?: string[];
    }> = resp.data?.models || [];

    return models.some((m) => {
      const id = m.name?.startsWith("models/")
        ? m.name.slice("models/".length)
        : m.name;
      return (
        id === model &&
        (m.supportedGenerationMethods || []).includes("generateContent")
      );
    });
  }

  if (
    provider === "openai" ||
    provider === "openrouter" ||
    provider === "kimi" ||
    provider === "groq"
  ) {
    const baseURL =
      provider === "openrouter"
        ? "https://openrouter.ai/api/v1"
        : provider === "kimi"
        ? "https://api.moonshot.cn/v1"
        : provider === "groq"
        ? "https://api.groq.com/openai/v1"
        : undefined;

    const client = new OpenAI(baseURL ? { apiKey, baseURL } : { apiKey });
    const resp = await client.models.list();
    return (resp.data || []).some((m) => m.id === model);
  }

  return true;
}

export function registerOnboardCommand(program: Command): void {
  program
    .command("onboard")
    .description("First-time setup wizard")
    .action(async () => {
      const config = await getConfig();

      console.log("");
      console.log("=== KramScan Setup Wizard ===");
      console.log("Configure your scanning environment");
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
          message: "Select AI provider",
          choices: [
            "openai",
            "anthropic",
            "gemini",
            "openrouter",
            "mistral",
            "kimi",
            "groq",
          ],
          default: config.ai.provider,
          when: (a) => a.aiEnabled,
        },
        {
          type: "password",
          name: "apiKey",
          message: "API key (leave blank to keep existing)",
          default: "",
          mask: "*",
          when: (a) => a.aiEnabled,
        },
        {
          type: "input",
          name: "model",
          message: "Default AI model",
          default: (a: any) =>
            config.ai.defaultModel ||
            getDefaultModel((a.aiProvider || config.ai.provider) as any),
          when: (a) => a.aiEnabled,
        },
        {
          type: "list",
          name: "reportFormat",
          message: "Default report format",
          choices: ["word", "txt", "json"],
          default: config.report.defaultFormat,
        },
        {
          type: "confirm",
          name: "strictScope",
          message: "Enable strict scope enforcement?",
          default: config.scan.strictScope,
        },
        {
          type: "number",
          name: "rateLimit",
          message: "Requests per second rate limit",
          default: config.scan.rateLimitPerSecond,
          validate: (v: number) =>
            Number.isFinite(v) && v > 0 ? true : "Enter a positive number",
        },
      ]);

      config.ai.enabled = !!answers.aiEnabled;

      if (config.ai.enabled) {
        config.ai.provider = answers.aiProvider;
        if (answers.apiKey) {
          config.ai.apiKey = answers.apiKey;
        }

        const keyForCheck = config.ai.apiKey || getEnvApiKey(config.ai.provider);
        let chosenModel = String(
          answers.model || getDefaultModel(config.ai.provider)
        );

        if (keyForCheck) {
          try {
            const ok = await modelExists(
              config.ai.provider,
              keyForCheck,
              chosenModel
            );
            if (!ok) {
              logger.warn(
                `Model '${chosenModel}' is not available for provider '${config.ai.provider}'.`
              );
              logger.warn("Tip: run 'kramscan ai models' to see valid models.");

              const retry = await inquirer.prompt([
                {
                  type: "confirm",
                  name: "retry",
                  message: "Enter a different model now?",
                  default: true,
                },
              ]);

              if (retry.retry) {
                const modelAns = await inquirer.prompt([
                  {
                    type: "input",
                    name: "model",
                    message: "Default AI model",
                    default: getDefaultModel(config.ai.provider),
                  },
                ]);
                chosenModel = String(modelAns.model || chosenModel);
              }
            }
          } catch (error) {
            logger.warn(
              `Model preflight check failed: ${(error as Error).message}`
            );
          }
        }

        config.ai.defaultModel = chosenModel;
      }

      config.report.defaultFormat = answers.reportFormat;
      config.scan.strictScope = !!answers.strictScope;
      config.scan.rateLimitPerSecond = answers.rateLimit;

      await setConfig(config);

      console.log("");
      logger.success("Onboarding complete! Your configuration has been saved.");
      console.log("Config location: ~/.kramscan/config.json");
      console.log("Run 'kramscan' to get started.");
      console.log("");
    });
}

