import { Command } from "commander";
import { registerOnboardCommand } from "./commands/onboard";
import { registerScanCommand } from "./commands/scan";
import { registerAnalyzeCommand } from "./commands/analyze";
import { registerReportCommand } from "./commands/report";
import { registerConfigCommand } from "./commands/config";
import { registerDoctorCommand } from "./commands/doctor";
import { registerAgentCommand } from "./commands/agent";

const CLI_VERSION = "0.1.0";

// ─── ANSI Color Helpers ────────────────────────────────────────────
const c = {
  reset: "\x1b[0m",
  bold: "\x1b[1m",
  dim: "\x1b[2m",
  red: "\x1b[31m",
  green: "\x1b[32m",
  yellow: "\x1b[33m",
  blue: "\x1b[34m",
  magenta: "\x1b[35m",
  cyan: "\x1b[36m",
  white: "\x1b[37m",
  gray: "\x1b[90m",
  bgBlue: "\x1b[44m",
  bgMagenta: "\x1b[45m",
  brightCyan: "\x1b[96m",
  brightMagenta: "\x1b[95m",
  brightBlue: "\x1b[94m",
  brightGreen: "\x1b[92m",
  brightYellow: "\x1b[93m",
  brightWhite: "\x1b[97m",
};

// ─── ASCII Art Banner ──────────────────────────────────────────────
function printBanner(): void {
  // Sleek ANSI Shadow style — KRAMSCAN
  const lines = [
    `██╗  ██╗██████╗  █████╗ ███╗   ███╗███████╗ ██████╗ █████╗ ███╗   ██╗`,
    `██║ ██╔╝██╔══██╗██╔══██╗████╗ ████║██╔════╝██╔════╝██╔══██╗████╗  ██║`,
    `█████╔╝ ██████╔╝███████║██╔████╔██║███████╗██║     ███████║██╔██╗ ██║`,
    `██╔═██╗ ██╔══██╗██╔══██║██║╚██╔╝██║╚════██║██║     ██╔══██║██║╚██╗██║`,
    `██║  ██╗██║  ██║██║  ██║██║ ╚═╝ ██║███████║╚██████╗██║  ██║██║ ╚████║`,
    `╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝     ╚═╝╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝`,
  ];

  console.log("");
  lines.forEach((line, i) => {
    const shade = i % 2 === 0 ? c.brightWhite : c.gray;
    console.log(`  ${shade}${line}${c.reset}`);
  });
  console.log("");
}

// ─── Dashboard Info ────────────────────────────────────────────────
function printInfo(): void {
  console.log(
    `  ${c.gray}${c.dim}───────────────────────────────────────────────────────${c.reset}`
  );
  console.log(
    `  ${c.brightWhite}${c.bold} KramScan${c.reset} ${c.gray}v${CLI_VERSION}${c.reset}  ${c.dim}${c.gray}|${c.reset}  ${c.cyan}AI-Powered Web Security Scanner${c.reset}`
  );
  console.log(
    `  ${c.gray}${c.dim}───────────────────────────────────────────────────────${c.reset}`
  );
  console.log("");
  console.log(`  ${c.brightYellow}${c.bold}Tips for getting started:${c.reset}`);
  console.log(`  ${c.white}1.${c.reset} ${c.gray}Run${c.reset} ${c.cyan}kramscan onboard${c.reset} ${c.gray}to configure your API keys.${c.reset}`);
  console.log(`  ${c.white}2.${c.reset} ${c.gray}Run${c.reset} ${c.cyan}kramscan scan <url>${c.reset} ${c.gray}to scan a target.${c.reset}`);
  console.log(`  ${c.white}3.${c.reset} ${c.gray}Run${c.reset} ${c.cyan}kramscan --help${c.reset} ${c.gray}for all commands.${c.reset}`);
  console.log("");
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

  // Use readline for a simple, CommonJS-compatible interactive menu
  const readline = await import("readline");
  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout,
  });

  function renderMenu(selectedIndex: number): void {
    // Move cursor up to redraw the menu (clear previous render)
    if (selectedIndex >= 0) {
      process.stdout.write(`\x1b[${menuChoices.length + 2}A`);
    }

    console.log(`  ${c.brightWhite}${c.bold}What would you like to do?${c.reset}`);
    console.log("");

    menuChoices.forEach((choice, i) => {
      const isSelected = i === selectedIndex;
      const statusTag = choice.status === "coming_soon"
        ? ` ${c.yellow}[coming soon]${c.reset}`
        : "";

      if (isSelected) {
        console.log(
          `  ${c.brightCyan}${c.bold}❯ ${choice.icon}  ${choice.label}${c.reset}${statusTag}  ${c.dim}${c.gray}— ${choice.description}${c.reset}`
        );
      } else {
        console.log(
          `    ${choice.icon}  ${c.white}${choice.label}${c.reset}${statusTag}  ${c.dim}${c.gray}— ${choice.description}${c.reset}`
        );
      }
    });
  }

  return new Promise<void>((resolve) => {
    let selectedIndex = 0;

    // Enable raw mode for arrow key support
    if (process.stdin.isTTY) {
      process.stdin.setRawMode(true);
    }
    process.stdin.resume();

    renderMenu(-1); // Initial render (no cursor-up needed)

    process.stdin.on("data", async (key: Buffer) => {
      const str = key.toString();

      if (str === "\x1b[A") {
        // Arrow Up
        selectedIndex = (selectedIndex - 1 + menuChoices.length) % menuChoices.length;
        renderMenu(selectedIndex);
      } else if (str === "\x1b[B") {
        // Arrow Down
        selectedIndex = (selectedIndex + 1) % menuChoices.length;
        renderMenu(selectedIndex);
      } else if (str === "\r" || str === "\n") {
        // Enter
        if (process.stdin.isTTY) {
          process.stdin.setRawMode(false);
        }
        process.stdin.pause();
        rl.close();

        const selected = menuChoices[selectedIndex];
        console.log("");

        if (selected.value === "exit") {
          console.log(`  ${c.gray}${c.dim}Goodbye! 👋${c.reset}`);
          console.log("");
          resolve();
          return;
        }

        if (selected.status === "coming_soon") {
          console.log(
            `  ${c.yellow}⚠  ${selected.label}${c.reset} ${c.gray}is coming soon. Stay tuned!${c.reset}`
          );
          console.log(`  ${c.gray}Run ${c.cyan}kramscan --help${c.gray} for available commands.${c.reset}`);
          console.log("");
          resolve();
          return;
        }

        // Execute the selected command
        console.log(
          `  ${c.brightGreen}▶${c.reset} ${c.bold}Launching ${selected.label}...${c.reset}`
        );
        console.log("");

        // Re-run with the command argument
        process.argv.push(selected.value);
        const program = createProgram();
        await program.parseAsync(process.argv);
        resolve();
      } else if (str === "\x03") {
        // Ctrl+C
        if (process.stdin.isTTY) {
          process.stdin.setRawMode(false);
        }
        process.stdin.pause();
        rl.close();
        console.log(`\n  ${c.gray}${c.dim}Interrupted. Goodbye! 👋${c.reset}\n`);
        process.exit(0);
      }
    });
  });
}

// ─── Program Setup ─────────────────────────────────────────────────
function createProgram(): Command {
  const program = new Command();

  program
    .name("kramscan")
    .description("KramScan — AI-powered web app security testing")
    .version(CLI_VERSION);

  registerOnboardCommand(program);
  registerScanCommand(program);
  registerAnalyzeCommand(program);
  registerReportCommand(program);
  registerConfigCommand(program);
  registerDoctorCommand(program);
  registerAgentCommand(program);

  return program;
}

// ─── Entry Point ───────────────────────────────────────────────────
export async function run(): Promise<void> {
  const args = process.argv.slice(2);

  // If no command is provided, show the interactive dashboard
  if (args.length === 0) {
    await showInteractiveMenu();
  } else {
    const program = createProgram();
    await program.parseAsync();
  }
}
