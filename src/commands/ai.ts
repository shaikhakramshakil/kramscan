import { Command } from "commander";
import chalk from "chalk";
import axios from "axios";
import OpenAI from "openai";
import { getConfig } from "../core/config";
import { createAIClient } from "../core/ai-client";
import { logger } from "../utils/logger";

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

export function registerAiCommand(program: Command): void {
  const ai = program.command("ai").description("AI helpers and diagnostics");

  ai
    .command("models")
    .description("List available models for the configured AI provider")
    .option("-n, --limit <number>", "How many models to show", "50")
    .action(async (options) => {
      const config = await getConfig();

      if (!config.ai.enabled) {
        logger.error("AI analysis is disabled. Run 'kramscan onboard' to enable it.");
        process.exit(1);
      }

      const provider = config.ai.provider;
      const apiKey = config.ai.apiKey || getEnvApiKey(provider);
      if (!apiKey) {
        logger.error(`No API key configured for ${provider}.`);
        process.exit(1);
      }

      const limit = Number.parseInt(options.limit, 10);
      const max = Number.isFinite(limit) ? limit : 50;

      console.log("");
      console.log(chalk.bold.cyan("Available Models"));
      console.log(chalk.gray("-".repeat(60)));
      console.log(chalk.gray("Provider:"), chalk.cyan(provider));
      console.log(chalk.gray("Configured default model:"), chalk.white(config.ai.defaultModel));
      console.log("");

      if (provider === "gemini") {
        const resp = await axios.get(
          "https://generativelanguage.googleapis.com/v1beta/models",
          { params: { key: apiKey } }
        );

        const models: Array<{
          name: string;
          displayName?: string;
          supportedGenerationMethods?: string[];
        }> = resp.data?.models || [];

        const usable = models.filter((m) =>
          (m.supportedGenerationMethods || []).includes("generateContent")
        );

        const show = usable.slice(0, max);
        for (const m of show) {
          const id = m.name?.startsWith("models/") ? m.name.slice("models/".length) : m.name;
          const dn = m.displayName ? ` (${m.displayName})` : "";
          console.log(chalk.white(id) + chalk.gray(dn));
        }

        if (usable.length === 0) {
          logger.warn("No models returned with generateContent support.");
        } else if (usable.length > show.length) {
          console.log("");
          console.log(chalk.gray(`... and ${usable.length - show.length} more`));
        }

        return;
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
        const ids = (resp.data || []).map((m) => m.id).slice(0, max);
        ids.forEach((id) => console.log(chalk.white(id)));
        if ((resp.data || []).length > ids.length) {
          console.log("");
          console.log(chalk.gray(`... and ${(resp.data || []).length - ids.length} more`));
        }
        return;
      }

      logger.warn(`Model listing not implemented for provider: ${provider}`);
      console.log(chalk.gray("Tip: run 'kramscan doctor' or try a small 'kramscan analyze' to validate the model."));
    });

  ai
    .command("test")
    .description("Test the configured AI provider/model with a small request")
    .action(async () => {
      console.log("");
      console.log(chalk.bold.cyan("AI Connectivity Test"));
      console.log(chalk.gray("-".repeat(60)));
      console.log("");

      const spinner = logger.spinner("Sending test request...");
      try {
        const client = await createAIClient();
        const resp = await client.analyze("Say 'OK' and nothing else.");
        spinner.succeed("AI request succeeded");
        console.log(chalk.gray("Response:"), chalk.white(resp.content.trim() || "(empty)"));
      } catch (error) {
        spinner.fail("AI request failed");
        logger.error((error as Error).message);
        process.exit(1);
      }
    });
}
