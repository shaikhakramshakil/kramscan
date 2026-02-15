import chalk from "chalk";
import ora, { Ora } from "ora";

function debugEnabled(): boolean {
  return (
    process.env.DEBUG === "1" ||
    process.env.DEBUG === "true" ||
    process.env.KRAMSCAN_DEBUG === "1" ||
    process.env.KRAMSCAN_DEBUG === "true"
  );
}

export const logger = {
  info: (message: string) => {
    console.log(chalk.blue("i"), message);
  },

  success: (message: string) => {
    console.log(chalk.green("OK"), message);
  },

  warn: (message: string) => {
    console.log(chalk.yellow("!"), message);
  },

  error: (message: string) => {
    console.log(chalk.red("x"), message);
  },

  debug: (message: string) => {
    if (debugEnabled()) {
      console.log(chalk.gray("->"), message);
    }
  },

  spinner: (text: string): Ora => {
    return ora({
      text,
      color: "cyan",
      spinner: "dots",
    }).start();
  },
};
