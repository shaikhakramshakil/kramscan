// ANSI color helpers (replaces ESM-only chalk)
const c = {
  reset: "\x1b[0m",
  cyan: "\x1b[36m",
  yellow: "\x1b[33m",
  red: "\x1b[31m",
  green: "\x1b[32m",
  gray: "\x1b[90m",
  bold: "\x1b[1m",
};

export interface Logger {
  info(message: string): void;
  warn(message: string): void;
  error(message: string): void;
  success(message: string): void;
  spinner(message: string): { stop: () => void; succeed: (msg?: string) => void; fail: (msg?: string) => void };
}

export function createLogger(): Logger {
  return {
    info(message: string) {
      console.log(`${c.cyan}ℹ ${message}${c.reset}`);
    },
    warn(message: string) {
      console.log(`${c.yellow}⚠ ${message}${c.reset}`);
    },
    error(message: string) {
      console.error(`${c.red}✖ ${message}${c.reset}`);
    },
    success(message: string) {
      console.log(`${c.green}✔ ${message}${c.reset}`);
    },
    spinner(message: string) {
      const frames = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];
      let i = 0;
      const id = setInterval(() => {
        process.stdout.write(`\r${c.cyan}${frames[i % frames.length]}${c.reset} ${message}`);
        i++;
      }, 80);

      return {
        stop() {
          clearInterval(id);
          process.stdout.write("\r\x1b[K"); // Clear line
        },
        succeed(msg?: string) {
          clearInterval(id);
          console.log(`\r${c.green}✔${c.reset} ${msg || message}`);
        },
        fail(msg?: string) {
          clearInterval(id);
          console.log(`\r${c.red}✖${c.reset} ${msg || message}`);
        },
      };
    },
  };
}
