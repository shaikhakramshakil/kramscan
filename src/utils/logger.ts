import chalk from "chalk";
import ora, { Ora } from "ora";

export enum LogLevel {
  DEBUG = 0,
  INFO = 1,
  SUCCESS = 2,
  WARN = 3,
  ERROR = 4,
}

export interface LogEntry {
  timestamp: string;
  level: string;
  message: string;
  context?: Record<string, unknown>;
}

export interface LoggerOptions {
  level?: LogLevel;
  jsonOutput?: boolean;
  includeTimestamp?: boolean;
  includeContext?: boolean;
}

function getLogLevel(): LogLevel {
  const envLevel = process.env.LOG_LEVEL?.toUpperCase();
  switch (envLevel) {
    case "DEBUG":
      return LogLevel.DEBUG;
    case "INFO":
      return LogLevel.INFO;
    case "WARN":
    case "WARNING":
      return LogLevel.WARN;
    case "ERROR":
      return LogLevel.ERROR;
    default:
      return process.env.KRAMSCAN_DEBUG === "1" || process.env.KRAMSCAN_DEBUG === "true"
        ? LogLevel.DEBUG
        : LogLevel.INFO;
  }
}

function debugEnabled(): boolean {
  return getLogLevel() <= LogLevel.DEBUG;
}

function isJsonOutput(): boolean {
  return process.env.LOG_JSON === "1" || process.env.LOG_JSON === "true";
}

function shouldLog(level: LogLevel): boolean {
  return level >= getLogLevel();
}

function formatLogEntry(level: string, message: string, context?: Record<string, unknown>): LogEntry {
  return {
    timestamp: new Date().toISOString(),
    level,
    message,
    context,
  };
}

function outputLog(entry: LogEntry): void {
  if (isJsonOutput()) {
    console.log(JSON.stringify(entry));
  } else {
    const { message, context: ctx } = entry;
    let output = message;
    if (process.env.LOG_INCLUDE_CONTEXT === "true" && ctx && Object.keys(ctx).length > 0) {
      output += ` ${JSON.stringify(ctx)}`;
    }
    console.log(output);
  }
}

// Simple human-readable logger (original behavior)
export const logger = {
  info: (message: string) => {
    if (shouldLog(LogLevel.INFO)) {
      console.log(chalk.blue("i"), message);
    }
  },

  success: (message: string) => {
    if (shouldLog(LogLevel.SUCCESS)) {
      console.log(chalk.green("✓"), message);
    }
  },

  warn: (message: string) => {
    if (shouldLog(LogLevel.WARN)) {
      console.log(chalk.yellow("⚠"), message);
    }
  },

  error: (message: string) => {
    if (shouldLog(LogLevel.ERROR)) {
      console.log(chalk.red("✗"), message);
    }
  },

  debug: (message: string, context?: Record<string, unknown>) => {
    if (debugEnabled()) {
      if (isJsonOutput()) {
        const entry = formatLogEntry("DEBUG", message, context);
        console.log(JSON.stringify(entry));
      } else {
        console.log(chalk.gray("→"), message, context ? JSON.stringify(context) : "");
      }
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

// Structured JSON logger for log aggregation systems
export const structuredLogger = {
  debug: (message: string, context?: Record<string, unknown>): void => {
    if (shouldLog(LogLevel.DEBUG)) {
      outputLog(formatLogEntry("DEBUG", message, context));
    }
  },

  info: (message: string, context?: Record<string, unknown>): void => {
    if (shouldLog(LogLevel.INFO)) {
      outputLog(formatLogEntry("INFO", message, context));
    }
  },

  warn: (message: string, context?: Record<string, unknown>): void => {
    if (shouldLog(LogLevel.WARN)) {
      outputLog(formatLogEntry("WARN", message, context));
    }
  },

  error: (message: string, context?: Record<string, unknown>): void => {
    if (shouldLog(LogLevel.ERROR)) {
      outputLog(formatLogEntry("ERROR", message, context));
    }
  },

  // Log with custom level
  log: (level: LogLevel, message: string, context?: Record<string, unknown>): void => {
    if (shouldLog(level)) {
      const levelName = LogLevel[level];
      outputLog(formatLogEntry(levelName, message, context));
    }
  },
};

// Convenience function to create a child logger with additional context
export function createChildLogger(defaultContext: Record<string, unknown>) {
  return {
    debug: (message: string, context?: Record<string, unknown>) => {
      structuredLogger.debug(message, { ...defaultContext, ...context });
    },
    info: (message: string, context?: Record<string, unknown>) => {
      structuredLogger.info(message, { ...defaultContext, ...context });
    },
    warn: (message: string, context?: Record<string, unknown>) => {
      structuredLogger.warn(message, { ...defaultContext, ...context });
    },
    error: (message: string, context?: Record<string, unknown>) => {
      structuredLogger.error(message, { ...defaultContext, ...context });
    },
  };
}
