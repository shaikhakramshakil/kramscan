import { Command } from "commander";
import * as readline from "readline";
import axios from "axios";
import OpenAI from "openai";
import { Config, getConfig, setConfig } from "../core/config";
import { logger } from "../utils/logger";

const c = {
  reset: "\x1b[0m",
  bold: "\x1b[1m",
  dim: "\x1b[2m",
  cyan: "\x1b[36m",
  gray: "\x1b[90m",
  brightCyan: "\x1b[96m",
};

function ask(
  rl: readline.Interface,
  question: string,
  defaultVal?: string
): Promise<string> {
  const defaultHint = defaultVal ? ` ${c.gray}(${defaultVal})${c.reset}` : "";
  return new Promise((resolve) => {
    rl.question(
      `  ${c.cyan}?${c.reset} ${question}${defaultHint} `,
      (answer: string) => {
        resolve(answer.trim() || defaultVal || "");
      }
    );
  });
}

function askConfirm(
  rl: readline.Interface,
  question: string,
  defaultVal = true
): Promise<boolean> {
  const hint = defaultVal ? `${c.gray}(Y/n)${c.reset}` : `${c.gray}(y/N)${c.reset}`;
  return new Promise((resolve) => {
    rl.question(`  ${c.cyan}?${c.reset} ${question} ${hint} `, (answer: string) => {
      const normalized = answer.trim().toLowerCase();
      if (!normalized) {
        resolve(defaultVal);
        return;
      }
      resolve(normalized === "y" || normalized === "yes");
    });
  });
}

function askList(
  rl: readline.Interface,
  question: string,
  choices: string[],
  defaultVal?: string
): Promise<string> {
  const choicesStr = choices
    .map((choice, index) => {
      const isDefault = choice === defaultVal;
      return `    ${isDefault ? c.brightCyan + ">" : " "} ${index + 1}. ${choice}${c.reset}`;
    })
    .join("\n");

  return new Promise((resolve) => {
    console.log(`  ${c.cyan}?${c.reset} ${question}`);
    console.log(choicesStr);
    rl.question(`  ${c.gray}Enter choice:${c.reset} `, (answer: string) => {
      const normalized = answer.trim().toLowerCase();
      const index = Number.parseInt(normalized, 10);

      if (Number.isFinite(index) && index >= 1 && index <= choices.length) {
        resolve(choices[index - 1]);
        return;
      }

      const byValue = choices.find((choice) => choice.toLowerCase() === normalized);
      resolve(byValue || defaultVal || choices[0]);
    });
  });
}

function askPassword(rl: readline.Interface, question: string): Promise<string> {
  return new Promise((resolve) => {
    rl.question(
      `  ${c.cyan}?${c.reset} ${question} ${c.gray}(hidden)${c.reset} `,
      (answer: string) => {
        resolve(answer.trim());
      }
    );
  });
}

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

async function modelExists(provider: string, apiKey: string, model: string): Promise<boolean> {
  if (!apiKey || !model) {
    return true;
  }

  if (provider === "gemini") {
    const resp = await axios.get("https://generativelanguage.googleapis.com/v1beta/models", {
      params: { key: apiKey },
    });

    const models: Array<{ name: string; supportedGenerationMethods?: string[] }> = resp.data?.models || [];
    return models.some((m) => {
      const id = m.name?.startsWith("models/") ? m.name.slice("models/".length) : m.name;
      return id === model && (m.supportedGenerationMethods || []).includes("generateContent");
    });
  }

  if (provider === "openai" || provider === "openrouter" || provider === "kimi" || provider === "groq") {
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

      const rl = readline.createInterface({
        input: process.stdin,
        output: process.stdout,
      });

      console.log("");
      console.log(`  ${c.bold}${c.brightCyan}=== KramScan Setup Wizard ===${c.reset}`);
      console.log(`  ${c.gray}Configure your scanning environment${c.reset}`);
      console.log("");

      const aiEnabled = await askConfirm(rl, "Enable AI analysis?", config.ai.enabled);
      config.ai.enabled = aiEnabled;

      if (aiEnabled) {
        const provider = (await askList(
          rl,
          "Select AI provider",
          ["openai", "anthropic", "gemini", "openrouter", "mistral", "kimi", "groq"],
          config.ai.provider
        )) as Config["ai"]["provider"];

        config.ai.provider = provider;

        const apiKey = await askPassword(rl, "API key (leave blank to keep existing)");
        if (apiKey) {
          config.ai.apiKey = apiKey;
        }

        const defaultModel = getDefaultModel(provider);
        const keyForCheck = config.ai.apiKey || getEnvApiKey(provider);

        let chosenModel = await ask(
          rl,
          "Default AI model",
          config.ai.defaultModel || defaultModel
        );

        if (keyForCheck) {
          for (let attempt = 0; attempt < 2; attempt++) {
            try {
              const ok = await modelExists(provider, keyForCheck, chosenModel);
              if (ok) {
                break;
              }

              logger.warn(`Model '${chosenModel}' is not available for provider '${provider}'.`);
              logger.warn("Tip: run 'kramscan ai models' to see valid models.");

              const retry = await askConfirm(rl, "Enter a different model now?", true);
              if (!retry) {
                break;
              }

              chosenModel = await ask(rl, "Default AI model", defaultModel);
            } catch (error) {
              logger.warn(`Model preflight check failed: ${(error as Error).message}`);
              break;
            }
          }
        }

        config.ai.defaultModel = chosenModel;
      }

      config.report.defaultFormat = (await askList(
        rl,
        "Default report format",
        ["word", "txt", "json"],
        config.report.defaultFormat
      )) as Config["report"]["defaultFormat"];

      config.scan.strictScope = await askConfirm(
        rl,
        "Enable strict scope enforcement?",
        config.scan.strictScope
      );

      const rateLimitStr = await ask(
        rl,
        "Requests per second rate limit",
        String(config.scan.rateLimitPerSecond)
      );
      const parsedRateLimit = Number.parseInt(rateLimitStr, 10);
      config.scan.rateLimitPerSecond =
        Number.isFinite(parsedRateLimit) && parsedRateLimit > 0
          ? parsedRateLimit
          : config.scan.rateLimitPerSecond;

      rl.close();
      await setConfig(config);

      console.log("");
      logger.success("Onboarding complete! Your configuration has been saved.");
      console.log(`  ${c.gray}Config location: ~/.kramscan/config.json${c.reset}`);
      console.log(`  ${c.gray}Run ${c.cyan}kramscan${c.gray} to get started.${c.reset}`);
      console.log("");
    });
}
