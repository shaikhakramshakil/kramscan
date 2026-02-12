import { Command } from "commander";
import * as readline from "readline";
import { getConfigStore } from "../core/config";
import { createLogger } from "../core/logger";

// ─── ANSI Helpers ──────────────────────────────────────────────────
const c = {
  reset: "\x1b[0m",
  bold: "\x1b[1m",
  dim: "\x1b[2m",
  cyan: "\x1b[36m",
  green: "\x1b[32m",
  yellow: "\x1b[33m",
  gray: "\x1b[90m",
  white: "\x1b[37m",
  brightCyan: "\x1b[96m",
};

// ─── Prompt Utilities ──────────────────────────────────────────────
function ask(rl: readline.Interface, question: string, defaultVal?: string): Promise<string> {
  const defaultHint = defaultVal ? ` ${c.gray}(${defaultVal})${c.reset}` : "";
  return new Promise((resolve) => {
    rl.question(`  ${c.cyan}?${c.reset} ${question}${defaultHint} `, (answer: string) => {
      resolve(answer.trim() || defaultVal || "");
    });
  });
}

function askConfirm(rl: readline.Interface, question: string, defaultVal = true): Promise<boolean> {
  const hint = defaultVal ? `${c.gray}(Y/n)${c.reset}` : `${c.gray}(y/N)${c.reset}`;
  return new Promise((resolve) => {
    rl.question(`  ${c.cyan}?${c.reset} ${question} ${hint} `, (answer: string) => {
      const a = answer.trim().toLowerCase();
      if (a === "") resolve(defaultVal);
      else resolve(a === "y" || a === "yes");
    });
  });
}

function askList(rl: readline.Interface, question: string, choices: string[], defaultVal?: string): Promise<string> {
  const choicesStr = choices
    .map((ch, i) => {
      const isDefault = ch === defaultVal;
      return `    ${isDefault ? c.brightCyan + "❯" : " "} ${ch}${c.reset}`;
    })
    .join("\n");

  return new Promise((resolve) => {
    console.log(`  ${c.cyan}?${c.reset} ${question}`);
    console.log(choicesStr);
    rl.question(`  ${c.gray}Enter choice:${c.reset} `, (answer: string) => {
      const trimmed = answer.trim();
      if (choices.includes(trimmed)) {
        resolve(trimmed);
      } else {
        resolve(defaultVal || choices[0]);
      }
    });
  });
}

function askPassword(rl: readline.Interface, question: string): Promise<string> {
  return new Promise((resolve) => {
    rl.question(`  ${c.cyan}?${c.reset} ${question} ${c.gray}(hidden)${c.reset} `, (answer: string) => {
      resolve(answer.trim());
    });
  });
}

// ─── Command Registration ─────────────────────────────────────────
export function registerOnboardCommand(program: Command): void {
  program
    .command("onboard")
    .description("First-time setup wizard")
    .action(async () => {
      const logger = createLogger();
      const store = getConfigStore();

      const rl = readline.createInterface({
        input: process.stdin,
        output: process.stdout,
      });

      console.log("");
      console.log(`  ${c.bold}${c.brightCyan}━━━ KramScan Setup Wizard ━━━${c.reset}`);
      console.log(`  ${c.gray}Configure your scanning environment${c.reset}`);
      console.log("");

      // AI Configuration
      const aiEnabled = await askConfirm(rl, "Enable AI analysis?", false);
      store.set("ai.enabled", aiEnabled);

      if (aiEnabled) {
        const aiProvider = await askList(rl, "Select AI provider", ["openai", "anthropic"], "openai");
        store.set("ai.provider", aiProvider);

        const apiKey = await askPassword(rl, "API key (leave blank to skip)");
        if (apiKey) {
          store.set("ai.apiKey", apiKey);
        }

        const model = await ask(rl, "Default AI model", aiProvider === "openai" ? "gpt-4" : "claude-3-opus-20240229");
        store.set("ai.model", model);
      }

      // Report Configuration
      const reportFormat = await askList(rl, "Default report format", ["word", "txt", "json"], "word");
      store.set("report.defaultFormat", reportFormat);

      // Scan Configuration
      const strictScope = await askConfirm(rl, "Enable strict scope enforcement?", true);
      store.set("scan.strictScope", strictScope);

      const rateLimitStr = await ask(rl, "Requests per second rate limit", "5");
      const rateLimit = parseInt(rateLimitStr, 10) || 5;
      store.set("scan.rateLimitPerSecond", rateLimit);

      rl.close();

      console.log("");
      logger.success("Onboarding complete! Your configuration has been saved.");
      console.log(`  ${c.gray}Config location: ~/.kramscan/config.json${c.reset}`);
      console.log(`  ${c.gray}Run ${c.cyan}kramscan${c.gray} to get started.${c.reset}`);
      console.log("");
    });
}
