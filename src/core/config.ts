import * as fs from "fs";
import * as path from "path";
import * as os from "os";

export type AiProviderName = "openai" | "anthropic" | "gemini" | "openrouter" | "mistral" | "kimi";
export type ReportFormat = "word" | "txt" | "json";

export interface Config {
  ai: {
    provider: AiProviderName;
    apiKey: string;
    defaultModel: string;
    enabled: boolean;
  };
  scan: {
    defaultTimeout: number;
    maxThreads: number;
    userAgent: string;
    followRedirects: boolean;
    verifySSL: boolean;
    rateLimitPerSecond: number;
    strictScope: boolean;
  };
  report: {
    defaultFormat: ReportFormat;
    companyName: string;
    includeScreenshots: boolean;
    severityThreshold: "info" | "low" | "medium" | "high" | "critical";
  };
  skills: Record<string, { enabled: boolean; timeout?: number }>;
  proxy?: string;
}

const defaults: Config = {
  ai: {
    provider: "openai" as AiProviderName,
    apiKey: "",
    defaultModel: "gpt-4",
    enabled: false,
  },
  scan: {
    defaultTimeout: 60,
    maxThreads: 5,
    userAgent: "KramScan/0.1.0",
    followRedirects: true,
    verifySSL: true,
    rateLimitPerSecond: 5,
    strictScope: true
  },
  report: {
    defaultFormat: "word",
    companyName: "Your Company",
    includeScreenshots: false,
    severityThreshold: "low"
  },
  skills: {
    sqli: { enabled: true, timeout: 120 },
    xss: { enabled: true, timeout: 90 },
    headers: { enabled: true },
    csrf: { enabled: true },
    idor: { enabled: true },
    jwt: { enabled: true }
  }
};

function getEnvApiKey(provider: AiProviderName): string {
  const envVars: Record<string, string> = {
    openai: process.env.OPENAI_API_KEY || "",
    anthropic: process.env.ANTHROPIC_API_KEY || "",
    gemini: process.env.GEMINI_API_KEY || "",
    mistral: process.env.MISTRAL_API_KEY || "",
    openrouter: process.env.OPENROUTER_API_KEY || "",
    kimi: process.env.KIMI_API_KEY || "",
  };
  return envVars[provider] || "";
}

export function isDebugEnabled(): boolean {
  return process.env.KRAMSCAN_DEBUG === "true" || process.env.KRAMSCAN_DEBUG === "1";
}

// Simple JSON-file config store (replaces ESM-only 'conf' package)
class ConfigStore {
  private configPath: string;
  private data: Config;

  constructor(projectName: string, defaultConfig: Config) {
    const configDir = path.join(os.homedir(), `.${projectName}`);
    if (!fs.existsSync(configDir)) {
      fs.mkdirSync(configDir, { recursive: true });
    }
    this.configPath = path.join(configDir, "config.json");

    if (fs.existsSync(this.configPath)) {
      try {
        const raw = fs.readFileSync(this.configPath, "utf-8");
        this.data = { ...defaultConfig, ...JSON.parse(raw) };
      } catch {
        this.data = { ...defaultConfig };
      }
    } else {
      this.data = { ...defaultConfig };
    }
  }

  get store(): Config {
    return this.data;
  }

  get(key: string): unknown {
    const keys = key.split(".");
    let current: unknown = this.data;
    for (const k of keys) {
      if (current && typeof current === "object" && k in current) {
        current = (current as Record<string, unknown>)[k];
      } else {
        return undefined;
      }
    }
    return current;
  }

  set(key: string, value: unknown): void {
    const keys = key.split(".");
    let current: Record<string, unknown> = this.data as unknown as Record<string, unknown>;
    for (let i = 0; i < keys.length - 1; i++) {
      if (!(keys[i] in current) || typeof current[keys[i]] !== "object") {
        current[keys[i]] = {};
      }
      current = current[keys[i]] as Record<string, unknown>;
    }
    current[keys[keys.length - 1]] = value;
    this.save();
  }

  private save(): void {
    fs.writeFileSync(this.configPath, JSON.stringify(this.data, null, 2), "utf-8");
  }
}

const store = new ConfigStore("kramscan", defaults);

export function getConfigStore(): ConfigStore {
  return store;
}

export function getConfig(): Config {
  return store.store;
}

export function getConfigValue(key: string): unknown {
  return store.get(key);
}

export function setConfigValue(key: string, value: unknown): void {
  store.set(key, value);
}

export function setConfig(config: Config): void {
  Object.assign(store.store, config);
  (store as any).save();
}
