/**
 * Agent Command
 * Interactive AI-powered security assistant CLI
 */

import { Command } from "commander";
import chalk from "chalk";
import {
  AgentOrchestrator,
  SkillRegistry,
  WebScanSkill,
  AnalyzeFindingsSkill,
  GenerateReportSkill,
  HealthCheckSkill,
} from "../agent";
import { logger } from "../utils/logger";
import * as readline from "readline";

export function registerAgentCommand(program: Command): void {
  program
    .command("agent")
    .description("Start interactive AI security assistant")
    .option("-m, --message <text>", "Send a single message and exit")
    .option("--no-confirm", "Skip confirmation prompts for medium risk actions")
    .action(async (options) => {
      // Initialize skill registry with all skills
      const skillRegistry = new SkillRegistry();
      skillRegistry.register(new WebScanSkill());
      skillRegistry.register(new AnalyzeFindingsSkill());
      skillRegistry.register(new GenerateReportSkill());
      skillRegistry.register(new HealthCheckSkill());

      // Initialize orchestrator
      const orchestrator = new AgentOrchestrator(skillRegistry, {
        enableConfirmation: options.confirm !== false,
      });

      try {
        await orchestrator.initialize();

        if (options.message) {
          // Single message mode
          console.log("");
          console.log(chalk.bold.cyan("🛡️  KramScan Security Agent"));
          console.log(chalk.gray("─".repeat(50)));
          console.log("");

          const response = await orchestrator.processUserMessage(options.message);
          console.log(chalk.bold("Agent:"), response.message);
          console.log("");

          await orchestrator.shutdown();
          return;
        }

        // Interactive mode
        await runInteractiveMode(orchestrator);
      } catch (error) {
        logger.error(
          `Failed to start agent: ${error instanceof Error ? error.message : String(error)}`
        );
        process.exit(1);
      }
    });
}

async function runInteractiveMode(
  orchestrator: AgentOrchestrator
): Promise<void> {
  // Ensure we aren't in raw mode from other interactive flows.
  if (process.stdin.isTTY) {
    try {
      process.stdin.setRawMode(false);
    } catch {
      // ignore
    }
  }

  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout,
  });

  printWelcomeBanner();
  printAvailableSkills(orchestrator);

  // Share this readline interface with confirmations to avoid double-reading stdin.
  orchestrator.setReadlineInterface(rl);
  orchestrator.start();

  console.log(chalk.gray("Type 'help' for commands or 'exit' to quit.\n"));

  let closed = false;
  rl.on('SIGINT', () => rl.close());
  rl.on('close', () => { closed = true; });

  const question = (prompt: string): Promise<string> =>
    new Promise((resolve) => rl.question(prompt, resolve));

  while (!closed) {
    const input = await question(chalk.gray('You: '));
    if (closed) break;

    const trimmed = input.trim();
    if (!trimmed) continue;

    const commandResult = await handleSpecialCommand(trimmed, orchestrator, rl);
    if (commandResult.handled) {
      if (commandResult.shouldExit) break;
      continue;
    }

    console.log('');

    try {
      const response = await orchestrator.processUserMessage(trimmed);

      console.log(chalk.bold.cyan('Agent:'));
      console.log(response.message);

      if (response.toolCalls && response.toolCalls.length > 0) {
        console.log('');
        console.log(chalk.gray('Tools executed:'));
        response.toolCalls.forEach((call) => {
          const result = response.toolCallResults?.find((r) => r.toolCallId === call.id);
          const icon = result?.success ? chalk.green('OK') : chalk.red('X');
          console.log(chalk.gray('  ' + icon + ' ' + call.name));
        });
      }

      console.log('');
    } catch (error) {
      console.log(chalk.red('Error:'), error instanceof Error ? error.message : String(error));
      console.log('');
    }
  }

  console.log(chalk.gray('\nGoodbye!\n'));
  await orchestrator.shutdown();
  rl.close();
}

async function handleSpecialCommand(
  input: string,
  orchestrator: AgentOrchestrator,
  rl: readline.Interface
): Promise<{ handled: boolean; shouldExit: boolean }> {
  const command = input.toLowerCase();

  switch (command) {
    case "exit":
    case "quit":
    case "/exit":
    case "/quit":
      rl.close();
      return { handled: true, shouldExit: true };

    case "help":
    case "/help":
      printHelp();
      return { handled: true, shouldExit: false };

    case "clear":
    case "/clear":
    case "/new":
      orchestrator.clearConversation();
      console.log(chalk.gray("\nConversation history cleared.\n"));
      return { handled: true, shouldExit: false };

    case "status":
    case "/status":
      printStatus(orchestrator);
      return { handled: true, shouldExit: false };

    case "skills":
    case "/skills":
      printAvailableSkills(orchestrator);
      return { handled: true, shouldExit: false };

    default:
      return { handled: false, shouldExit: false };
  }
}

function printWelcomeBanner(): void {
  console.log("");
  console.log(
    chalk.bold.cyan(`
 ██╗  ██╗██████╗  █████╗ ███╗   ███╗███████╗ ██████╗ █████╗ ███╗   ██╗
 ██║ ██╔╝██╔══██╗██╔══██╗████╗ ████║██╔════╝██╔════╝██╔══██╗████╗  ██║
 █████╔╝ ██████╔╝███████║██╔████╔██║███████╗██║     ███████║██╔██╗ ██║
 ██╔═██╗ ██╔══██╗██╔══██║██║╚██╔╝██║╚════██║██║     ██╔══██║██║╚██╗██║
 ██║  ██╗██║  ██║██║  ██║██║ ╚═╝ ██║███████║╚██████╗██║  ██║██║ ╚████║
 ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝     ╚═╝╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝
 `)
  );
  console.log(chalk.gray("─".repeat(70)));
  console.log(
    chalk.bold.white("  AI-Powered Security Assistant"),
    chalk.gray("|"),
    chalk.cyan("v0.1.0")
  );
  console.log(chalk.gray("─".repeat(70)));
  console.log("");
}

function printAvailableSkills(orchestrator: AgentOrchestrator): void {
  const skills = orchestrator.getAvailableSkills();

  console.log(chalk.bold("Available Security Skills:"));
  console.log("");

  skills.forEach((skill) => {
    const riskColor =
      skill.risk === "high"
        ? chalk.red
        : skill.risk === "medium"
        ? chalk.yellow
        : chalk.green;

    console.log(chalk.bold.white(`  ${skill.name}`));
    console.log(chalk.gray(`    ${skill.description}`));
    console.log(
      chalk.gray(`    Risk: ${riskColor(skill.risk.toUpperCase())}`),
      skill.requiresConfirmation ? chalk.yellow("[Requires Confirmation]") : ""
    );
    console.log("");
  });
}

function printHelp(): void {
  console.log("");
  console.log(chalk.bold("Commands:"));
  console.log("");
  console.log(chalk.white("  help      "), chalk.gray("- Show this help message"));
  console.log(chalk.white("  status    "), chalk.gray("- Show session status"));
  console.log(chalk.white("  skills    "), chalk.gray("- List available skills"));
  console.log(
    chalk.white("  clear     "),
    chalk.gray("- Clear conversation history")
  );
  console.log(chalk.white("  exit      "), chalk.gray("- Exit the agent"));
  console.log("");
  console.log(chalk.bold("Examples:"));
  console.log("");
  console.log(chalk.gray("  Scan a website:"));
  console.log(chalk.cyan('  scan https://example.com'));
  console.log("");
  console.log(chalk.gray("  Analyze findings:"));
  console.log(chalk.cyan('  analyze the results'));
  console.log("");
  console.log(chalk.gray("  Generate report:"));
  console.log(chalk.cyan('  create a report'));
  console.log("");
  console.log(chalk.gray("  Check system health:"));
  console.log(chalk.cyan('  health check'));
  console.log("");
}

function printStatus(orchestrator: AgentOrchestrator): void {
  const summary = orchestrator.getConversationSummary();

  console.log("");
  console.log(chalk.bold("Session Status:"));
  console.log("");
  console.log(chalk.gray(`  Messages:     ${summary.totalMessages}`));
  console.log(chalk.gray(`  Duration:     ${summary.sessionDuration}`));
  if (summary.currentTarget) {
    console.log(chalk.gray(`  Target:       ${summary.currentTarget}`));
  }
  console.log(
    chalk.gray(`  Scan Results: ${summary.hasScanResults ? "Yes" : "No"}`)
  );
  console.log("");
}
