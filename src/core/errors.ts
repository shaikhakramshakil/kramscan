/**
 * Custom Error Types for KramScan
 * Provides structured error handling with error codes
 */

export enum ErrorCode {
  // Scanner errors (SCN-xxx)
  SCN_INIT_FAILED = "SCN_INIT_FAILED",
  SCN_CRAWL_FAILED = "SCN_CRAWL_FAILED",
  SCN_TIMEOUT = "SCN_TIMEOUT",
  SCN_INVALID_URL = "SCN_INVALID_URL",
  SCN_SCOPE_VIOLATION = "SCN_SCOPE_VIOLATION",
  SCN_BROWSER_ERROR = "SCN_BROWSER_ERROR",

  // Plugin errors (PLG-xxx)
  PLG_INIT_FAILED = "PLG_INIT_FAILED",
  PLG_EXECUTION_FAILED = "PLG_EXECUTION_FAILED",
  PLG_NOT_FOUND = "PLG_NOT_FOUND",
  PLG_DISABLED = "PLG_DISABLED",
  PLG_TIMEOUT = "PLG_TIMEOUT",

  // Config errors (CFG-xxx)
  CFG_INVALID = "CFG_INVALID",
  CFG_NOT_FOUND = "CFG_NOT_FOUND",
  CFG_WRITE_FAILED = "CFG_WRITE_FAILED",

  // Network errors (NET-xxx)
  NET_REQUEST_FAILED = "NET_REQUEST_FAILED",
  NET_RATE_LIMITED = "NET_RATE_LIMITED",
  NET_SSL_ERROR = "NET_SSL_ERROR",

  // AI errors (AI-xxx)
  AI_INIT_FAILED = "AI_INIT_FAILED",
  AI_REQUEST_FAILED = "AI_REQUEST_FAILED",
  AI_QUOTA_EXCEEDED = "AI_QUOTA_EXCEEDED",

  // Report errors (RPT-xxx)
  RPT_GENERATION_FAILED = "RPT_GENERATION_FAILED",
  RPT_INVALID_FORMAT = "RPT_INVALID_FORMAT",
}

export interface KramScanErrorOptions {
  code: ErrorCode;
  statusCode?: number;
  retryable?: boolean;
  context?: Record<string, unknown>;
}

export class KramScanError extends Error {
  public readonly code: ErrorCode;
  public readonly statusCode?: number;
  public readonly retryable: boolean;
  public readonly context?: Record<string, unknown>;
  public readonly timestamp: string;

  constructor(message: string, options: KramScanErrorOptions) {
    super(message);
    this.name = "KramScanError";
    this.code = options.code;
    this.statusCode = options.statusCode;
    this.retryable = options.retryable ?? false;
    this.context = options.context;
    this.timestamp = new Date().toISOString();

    // Maintains proper stack trace in V8 environments
    if (Error.captureStackTrace) {
      Error.captureStackTrace(this, KramScanError);
    }
  }

  toJSON(): Record<string, unknown> {
    return {
      name: this.name,
      message: this.message,
      code: this.code,
      statusCode: this.statusCode,
      retryable: this.retryable,
      context: this.context,
      timestamp: this.timestamp,
      stack: this.stack,
    };
  }
}

// Convenience error classes for common scenarios
export class ScannerError extends KramScanError {
  constructor(message: string, code: ErrorCode = ErrorCode.SCN_CRAWL_FAILED, context?: Record<string, unknown>) {
    super(message, { code, retryable: true, context });
    this.name = "ScannerError";
  }
}

export class PluginError extends KramScanError {
  constructor(message: string, code: ErrorCode = ErrorCode.PLG_EXECUTION_FAILED, context?: Record<string, unknown>) {
    super(message, { code, retryable: false, context });
    this.name = "PluginError";
  }
}

export class ConfigError extends KramScanError {
  constructor(message: string, code: ErrorCode = ErrorCode.CFG_INVALID, context?: Record<string, unknown>) {
    super(message, { code, retryable: false, context });
    this.name = "ConfigError";
  }
}

export class NetworkError extends KramScanError {
  constructor(message: string, code: ErrorCode = ErrorCode.NET_REQUEST_FAILED, context?: Record<string, unknown>) {
    super(message, { code, retryable: true, context });
    this.name = "NetworkError";
  }
}

export class AiError extends KramScanError {
  constructor(message: string, code: ErrorCode = ErrorCode.AI_REQUEST_FAILED, context?: Record<string, unknown>) {
    super(message, { code, retryable: true, context });
    this.name = "AiError";
  }
}

export class ReportError extends KramScanError {
  constructor(message: string, code: ErrorCode = ErrorCode.RPT_GENERATION_FAILED, context?: Record<string, unknown>) {
    super(message, { code, retryable: false, context });
    this.name = "ReportError";
  }
}

// Error handler utilities
export interface ErrorHandlerConfig {
  maxRetries: number;
  baseDelay: number;
  maxDelay: number;
  retryableCodes: ErrorCode[];
}

const defaultErrorHandlerConfig: ErrorHandlerConfig = {
  maxRetries: 3,
  baseDelay: 1000,
  maxDelay: 10000,
  retryableCodes: [
    ErrorCode.SCN_CRAWL_FAILED,
    ErrorCode.SCN_TIMEOUT,
    ErrorCode.SCN_BROWSER_ERROR,
    ErrorCode.NET_REQUEST_FAILED,
    ErrorCode.PLG_EXECUTION_FAILED,
    ErrorCode.AI_REQUEST_FAILED,
  ],
};

export function isRetryable(error: KramScanError, config: ErrorHandlerConfig = defaultErrorHandlerConfig): boolean {
  if (!error.retryable) return false;
  return config.retryableCodes.includes(error.code);
}

export function shouldRetry(error: KramScanError, attempt: number, config: ErrorHandlerConfig = defaultErrorHandlerConfig): boolean {
  return attempt < config.maxRetries && isRetryable(error, config);
}

export function getRetryDelay(error: KramScanError, attempt: number, config: ErrorHandlerConfig = defaultErrorHandlerConfig): number {
  const delay = Math.min(
    config.baseDelay * Math.pow(2, attempt),
    config.maxDelay
  );
  // Add jitter to prevent thundering herd
  const jitter = Math.random() * 0.3 * delay;
  return Math.floor(delay + jitter);
}

// Global error handler for uncaught errors
export function setupGlobalErrorHandlers(): void {
  process.on("uncaughtException", (error: Error) => {
    console.error("[FATAL] Uncaught Exception:");
    console.error(error.message);
    if (error.stack) {
      console.error(error.stack);
    }
    process.exit(1);
  });

  process.on("unhandledRejection", (reason: unknown, promise: Promise<unknown>) => {
    console.error("[FATAL] Unhandled Promise Rejection:");
    console.error("Reason:", reason);
    console.error("Promise:", promise);
    process.exit(1);
  });
}
