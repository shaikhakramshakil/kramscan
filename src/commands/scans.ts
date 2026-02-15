import { Command } from "commander";
import chalk from "chalk";
import { getLatestScan, listScans } from "../core/scan-index";
import { logger } from "../utils/logger";

export function registerScansCommand(program: Command): void {
  const scans = program.command("scans").description("Manage saved scans");

  scans
    .command("list")
    .description("List recent scans")
    .option("-n, --limit <number>", "How many scans to show", "20")
    .action(async (options) => {
      const limit = Number.parseInt(options.limit, 10);
      const entries = await listScans(Number.isFinite(limit) ? limit : 20);

      if (entries.length === 0) {
        logger.warn("No scans found in index yet. Run 'kramscan scan <url>' first.");
        return;
      }

      console.log("");
      console.log(chalk.bold.cyan("Recent Scans"));
      console.log(chalk.gray("-".repeat(60)));

      for (const entry of entries) {
        console.log(chalk.white(entry.timestamp), chalk.gray("-"), chalk.cyan(entry.hostname));
        console.log(chalk.gray("  JSON:"), chalk.white(entry.jsonPath));
        if (entry.pdfPath) {
          console.log(chalk.gray("  PDF :"), chalk.white(entry.pdfPath));
        }
        console.log(
          chalk.gray("  Findings:"),
          chalk.white(
            `${entry.summary.total} total (${entry.summary.critical}C ${entry.summary.high}H ${entry.summary.medium}M ${entry.summary.low}L ${entry.summary.info}I)`
          )
        );
        console.log("");
      }
    });

  scans
    .command("latest")
    .description("Show the latest scan paths")
    .action(async () => {
      const latest = await getLatestScan();
      if (!latest) {
        logger.warn("No scans found in index yet. Run 'kramscan scan <url>' first.");
        return;
      }

      console.log(chalk.bold("Latest scan:"));
      console.log(chalk.gray("Target:"), chalk.cyan(latest.target));
      console.log(chalk.gray("Time  :"), chalk.white(latest.timestamp));
      console.log(chalk.gray("JSON  :"), chalk.white(latest.jsonPath));
      console.log(chalk.gray("PDF   :"), chalk.white(latest.pdfPath || "N/A"));
    });
}

