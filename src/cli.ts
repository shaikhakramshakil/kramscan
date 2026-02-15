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
import { isDebugEnabled } from "./core/config";
import { printBanner, printInfo, theme } from "./utils/theme";

const CLI_VERSION = "0.1.1";

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

  console.log(theme.green(`\n  > Launching ${selected?.label || action}...\n`));

  const program = createProgram();
  await program.parseAsync(["node", "kramscan", action]);
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
