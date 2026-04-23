import { Command } from "commander";
import inquirer from "inquirer";
import { registerOnboardCommand } from "./commands/onboard";
import { registerScanCommand } from "./commands/scan";
import { registerAnalyzeCommand } from "./commands/analyze";
import { registerReportCommand } from "./commands/report";
import { registerConfigCommand } from "./commands/config";
import { registerDoctorCommand } from "./commands/doctor";
import { registerAgentCommand } from "./commands/agent";
import { registerScansCommand } from "./commands/scans";
import { registerAiCommand } from "./commands/ai";
import { registerDevCommand } from "./commands/dev";
import { registerGateCommand } from "./commands/gate";
import { isDebugEnabled } from "./core/config";
import { printBanner, printInfo, theme, CLI_VERSION } from "./utils/theme";

let verboseMode = false;
let debugMode = false;

export function isVerbose(): boolean {
  return verboseMode;
}

export function isDebug(): boolean {
  return debugMode || isDebugEnabled();
}

export function debugLog(...args: unknown[]): void {
  if (debugMode || isDebugEnabled()) {
    console.log("[DEBUG]", ...args);
  }
}

// ─── Interactive Menu ──────────────────────────────────────────────
interface MenuChoice {
  label: string;
  value: string;
  description: string;
  icon: string;
  status: "active" | "coming_soon";
}

const menuChoices: MenuChoice[] = [
  { label: "Agent", value: "agent", description: "AI-powered interactive security assistant", icon: "🤖", status: "active" },
  { label: "Onboard", value: "onboard", description: "First-time setup wizard", icon: "⚡", status: "active" },
  { label: "Scan", value: "scan", description: "Scan a target URL for vulnerabilities", icon: "🔍", status: "active" },
  { label: "Dev", value: "dev", description: "Watch-mode scanning for localhost dev servers", icon: "🛠️", status: "active" },
  { label: "Gate", value: "gate", description: "CI/CD security quality gate", icon: "🚧", status: "active" },
  { label: "Analyze", value: "analyze", description: "Deep AI analysis of scan results", icon: "🧠", status: "active" },
  { label: "Report", value: "report", description: "Generate a professional report", icon: "📄", status: "active" },
  { label: "Config", value: "config", description: "View or edit your configuration", icon: "⚙️", status: "active" },
  { label: "Doctor", value: "doctor", description: "Check environment health", icon: "🩺", status: "active" },
  { label: "Exit", value: "exit", description: "Quit KramScan", icon: "👋", status: "active" },
];

async function showInteractiveMenu(): Promise<void> {
  printBanner();
  printInfo();

  const choices = menuChoices.map((choice) => ({
    name: `${choice.icon}  ${choice.label.padEnd(10)} - ${choice.description}${choice.status === "coming_soon" ? " [coming soon]" : ""}`,
    value: choice.value,
    disabled: choice.status === "coming_soon",
  }));

  const { action } = await inquirer.prompt([
    {
      type: "list",
      name: "action",
      message: theme.cyan("What would you like to do?"),
      choices,
      pageSize: 10,
    },
  ]);

  if (action === "exit") {
    console.log(theme.gray("\n  Goodbye! 👋\n"));
    return;
  }

  const selected = menuChoices.find((c) => c.value === action);
  if (selected && selected.status === "coming_soon") {
    console.log(theme.yellow(`\n  [!] ${selected.label} is coming soon. Stay tuned!`));
    console.log(theme.gray(`  Run ${theme.cyan("kramscan --help")} for available commands.\n`));
    return;
  }

  let args: string[] = [action];

  // Specific handling for commands that need input
  if (action === "scan") {
    const { url } = await inquirer.prompt([
      {
        type: "input",
        name: "url",
        message: theme.cyan("Enter the URL to scan:"),
        validate: (input) => {
          try {
            const urlToTest = /^https?:\/\//i.test(input) ? input : `http://${input}`;
            new URL(urlToTest);
            return true;
          } catch {
            return "Please enter a valid URL (e.g., https://example.com)";
          }
        }
      }
    ]);
    args.push(url);
  } else if (action === "analyze" || action === "report") {
    const { listScans } = await import("./core/scan-index");
    const scans = await listScans(10);

    if (scans.length > 0) {
      const { scanFile } = await inquirer.prompt([
        {
          type: "list",
          name: "scanFile",
          message: theme.cyan(`Select a scan to ${action}:`),
          choices: [
            ...scans.map(s => ({
              name: `${s.timestamp} - ${s.hostname} (${s.summary.total} findings)`,
              value: s.jsonPath
            })),
            { name: "Back to menu", value: "back" }
          ]
        }
      ]);

      if (scanFile === "back") {
        return showInteractiveMenu();
      }
      args.push(scanFile);
    } else {
      console.log(theme.yellow(`\n  [!] No recent scans found. Please run a scan first.\n`));
      await new Promise(r => setTimeout(r, 1500));
      return showInteractiveMenu();
    }
  }

  console.log(theme.green(`\n  > Launching ${selected?.label || action}...\n`));

  const program = createProgram();
  try {
    await program.parseAsync(["node", "kramscan", ...args]);

    // After execution, ask if they want to go back to the menu
    const { back } = await inquirer.prompt([
      {
        type: "confirm",
        name: "back",
        message: theme.cyan("Return to main menu?"),
        default: true
      }
    ]);

    if (back) {
      return showInteractiveMenu();
    }
  } catch (error) {
    // Error handling is managed by the commands themselves or global handlers
  }
}

async function showDirectCommandInput(): Promise<void> {
  printBanner();
  printInfo();

  const { command } = await inquirer.prompt([
    {
      type: "input",
      name: "command",
      message: theme.cyan("Enter a command (e.g., 'scan https://example.com'):"),
      filter: (input: string) => input.trim(),
    },
  ]);

  if (!command) {
    return;
  }

  const tokens = command.match(/(?:[^\s"]+|"[^"]*")+/g)?.map((token: string) => token.replace(/^"(.*)"$/, "$1")) ?? [];
  const args = tokens[0]?.toLowerCase() === "kramscan" ? tokens.slice(1) : tokens;

  if (args.length > 0) {
    console.log("");
    const program = createProgram();
    await program.parseAsync(["node", "kramscan", ...args]);
  }
}

// ─── Program Setup ─────────────────────────────────────────────────
function createProgram(): Command {
  const program = new Command();

  program
    .name("kramscan")
    .description("KramScan — AI-powered web app security testing")
    .version(CLI_VERSION)
    .option("-v, --verbose", "Enable verbose output")
    .option("--debug", "Enable debug mode")
    .hook("preAction", (thisCommand) => {
      const opts = thisCommand.opts();
      verboseMode = opts.verbose || false;
      debugMode = opts.debug || false;
    })
    .enablePositionalOptions();

  registerOnboardCommand(program);
  registerScanCommand(program);
  registerAnalyzeCommand(program);
  registerReportCommand(program);
  registerConfigCommand(program);
  registerDoctorCommand(program);
  registerAgentCommand(program);
  registerScansCommand(program);
  registerAiCommand(program);
  registerDevCommand(program);
  registerGateCommand(program);

  // Version subcommand with detailed environment info
  program
    .command("version")
    .description("Show detailed version and environment information")
    .action(async () => {
      const os = await import("os");
      let aiProvider = "not configured";
      try {
        const { getConfig } = await import("./core/config");
        const config = await getConfig();
        if (config.ai.enabled) {
          aiProvider = `${config.ai.provider} (${config.ai.defaultModel})`;
        }
      } catch {
        // Config not available
      }

      console.log("");
      console.log(theme.brightWhite.bold("KramScan") + " " + theme.cyan(`v${CLI_VERSION}`));
      console.log(theme.gray("─".repeat(40)));
      console.log(theme.white("  Node.js:    ") + theme.cyan(process.version));
      console.log(theme.white("  Platform:   ") + theme.cyan(`${os.platform()} ${os.arch()}`));
      console.log(theme.white("  OS:         ") + theme.cyan(os.release()));
      console.log(theme.white("  AI Provider:") + " " + theme.cyan(aiProvider));
      console.log("");
    });

  return program;
}

// ─── Entry Point ───────────────────────────────────────────────────
export async function run(): Promise<void> {
  const args = process.argv.slice(2);

  // If no command is provided, show the interactive menu
  if (args.length === 0) {
    await showInteractiveMenu();
  } else {
    const program = createProgram();
    await program.parseAsync();
  }
}
