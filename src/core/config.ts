import * as fs from "fs";
import * as path from "path";
import * as os from "os";

export type AiProviderName =
  | "openai"
  | "anthropic"
  | "gemini"
  | "openrouter"
  | "mistral"
  | "kimi"
  | "groq";
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

export function isDebugEnabled(): boolean {
  return process.env.KRAMSCAN_DEBUG === "true" || process.env.KRAMSCAN_DEBUG === "1";
}

// Secure credential manager using OS keychain
class SecureCredentialManager {
  private serviceName: string;
  private useKeychain: boolean;
  private fallbackPath: string;

  constructor(serviceName: string) {
    this.serviceName = serviceName;
    this.useKeychain = this.detectKeychainSupport();
    
    const configDir = path.join(os.homedir(), `.${serviceName}`);
    if (!fs.existsSync(configDir)) {
      fs.mkdirSync(configDir, { recursive: true });
    }
    this.fallbackPath = path.join(configDir, ".secure");
  }

  private detectKeychainSupport(): boolean {
    try {
      // Check if we're in a CI environment or if keytar is available
      if (process.env.CI || process.env.KRAMSCAN_DISABLE_KEYCHAIN) {
        return false;
      }
      require("keytar");
      return true;
    } catch {
      return false;
    }
  }

  async getPassword(account: string): Promise<string | null> {
    if (this.useKeychain) {
      try {
        // eslint-disable-next-line @typescript-eslint/no-var-requires
        const keytar = await import("keytar");
        return await keytar.getPassword(this.serviceName, account);
      } catch (error) {
        // Fallback to file-based storage
        return this.getFromFallback(account);
      }
    }
    return this.getFromFallback(account);
  }

  async setPassword(account: string, password: string): Promise<void> {
    if (this.useKeychain) {
      try {
        // eslint-disable-next-line @typescript-eslint/no-var-requires
        const keytar = await import("keytar");
        await keytar.setPassword(this.serviceName, account, password);
        return;
      } catch (error) {
        // Fallback to file-based storage
      }
    }
    await this.saveToFallback(account, password);
  }

  async deletePassword(account: string): Promise<boolean> {
    if (this.useKeychain) {
      try {
        // eslint-disable-next-line @typescript-eslint/no-var-requires
        const keytar = await import("keytar");
        return await keytar.deletePassword(this.serviceName, account);
      } catch (error) {
        return this.deleteFromFallback(account);
      }
    }
    return this.deleteFromFallback(account);
  }

  private getFromFallback(account: string): string | null {
    try {
      if (!fs.existsSync(this.fallbackPath)) {
        return null;
      }
      const data = JSON.parse(fs.readFileSync(this.fallbackPath, "utf-8"));
      const encrypted = data[account];
      if (!encrypted) return null;
      return this.decrypt(encrypted);
    } catch {
      return null;
    }
  }

  private async saveToFallback(account: string, password: string): Promise<void> {
    let data: Record<string, string> = {};
    try {
      if (fs.existsSync(this.fallbackPath)) {
        data = JSON.parse(fs.readFileSync(this.fallbackPath, "utf-8"));
      }
    } catch {
      // File doesn't exist or is corrupt, start fresh
    }
    
    data[account] = this.encrypt(password);
    
    // Set restrictive permissions (owner read/write only)
    fs.writeFileSync(this.fallbackPath, JSON.stringify(data, null, 2), { mode: 0o600 });
  }

  private deleteFromFallback(account: string): boolean {
    try {
      if (!fs.existsSync(this.fallbackPath)) {
        return false;
      }
      const data = JSON.parse(fs.readFileSync(this.fallbackPath, "utf-8"));
      if (!(account in data)) {
        return false;
      }
      delete data[account];
      fs.writeFileSync(this.fallbackPath, JSON.stringify(data, null, 2), { mode: 0o600 });
      return true;
    } catch {
      return false;
    }
  }

  private encrypt(text: string): string {
    // Simple XOR encryption with a machine-specific key
    // This is not high-security but better than plaintext for fallback storage
    const key = this.getMachineKey();
    const buffer = Buffer.from(text);
    const encrypted = Uint8Array.from(buffer, (byte, i) => byte ^ key[i % key.length]);
    return Buffer.from(encrypted).toString("base64");
  }

  private decrypt(encrypted: string): string {
    const key = this.getMachineKey();
    const buffer = Buffer.from(encrypted, "base64");
    const decrypted = Uint8Array.from(buffer, (byte, i) => byte ^ key[i % key.length]);
    return Buffer.from(decrypted).toString("utf-8");
  }

  private getMachineKey(): Buffer {
    // Use machine-specific data to generate a key
    // This makes the encrypted data harder to decrypt on other machines
    const data = [
      os.hostname(),
      os.userInfo().username,
      os.platform(),
    ].join("|");
    return Buffer.from(data.repeat(4).slice(0, 32));
  }
}

// Simple JSON-file config store with encrypted sensitive values
class ConfigStore {
  private configPath: string;
  private data: Config;
  private credentialManager: SecureCredentialManager;

  constructor(projectName: string, defaultConfig: Config) {
    const configDir = path.join(os.homedir(), `.${projectName}`);
    if (!fs.existsSync(configDir)) {
      fs.mkdirSync(configDir, { recursive: true });
    }
    this.configPath = path.join(configDir, "config.json");
    this.credentialManager = new SecureCredentialManager(projectName);

    if (fs.existsSync(this.configPath)) {
      try {
        const raw = fs.readFileSync(this.configPath, "utf-8");
        this.data = { ...defaultConfig, ...JSON.parse(raw) };
      } catch {
        this.data = JSON.parse(JSON.stringify(defaultConfig));
      }
    } else {
      this.data = JSON.parse(JSON.stringify(defaultConfig));
    }
  }

  async initialize(): Promise<void> {
    // Load API key from secure storage
    const storedKey = await this.credentialManager.getPassword("apiKey");
    if (storedKey) {
      this.data.ai.apiKey = storedKey;
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

  async set(key: string, value: unknown): Promise<void> {
    const keys = key.split(".");
    let current: Record<string, unknown> = this.data as unknown as Record<string, unknown>;
    for (let i = 0; i < keys.length - 1; i++) {
      if (!(keys[i] in current) || typeof current[keys[i]] !== "object") {
        current[keys[i]] = {};
      }
      current = current[keys[i]] as Record<string, unknown>;
    }
    current[keys[keys.length - 1]] = value;
    
    // If setting API key, store it securely
    if (key === "ai.apiKey" && typeof value === "string") {
      if (value) {
        await this.credentialManager.setPassword("apiKey", value);
      } else {
        await this.credentialManager.deletePassword("apiKey");
      }
    }
    
    await this.save();
  }

  private async save(): Promise<void> {
    // Create a copy without the API key for the config file
    const configToSave = {
      ...this.data,
      ai: {
        ...this.data.ai,
        apiKey: "", // Don't save API key in plain text
      }
    };
    fs.writeFileSync(this.configPath, JSON.stringify(configToSave, null, 2), "utf-8");
  }

  async setConfig(config: Config): Promise<void> {
    Object.assign(this.data, config);
    
    // Save API key securely if present
    if (typeof config.ai?.apiKey === "string") {
      if (config.ai.apiKey) {
        await this.credentialManager.setPassword("apiKey", config.ai.apiKey);
      } else {
        await this.credentialManager.deletePassword("apiKey");
      }
      this.data.ai.apiKey = config.ai.apiKey;
    }
    
    await this.save();
  }
}

const store = new ConfigStore("kramscan", defaults);

// Initialize async
let initialized = false;
async function ensureInitialized(): Promise<void> {
  if (!initialized) {
    await store.initialize();
    initialized = true;
  }
}

export function getConfigStore(): ConfigStore {
  return store;
}

export async function getConfig(): Promise<Config> {
  await ensureInitialized();
  return store.store;
}

export async function getConfigValue(key: string): Promise<unknown> {
  await ensureInitialized();
  return store.get(key);
}

export async function setConfigValue(key: string, value: unknown): Promise<void> {
  await ensureInitialized();
  await store.set(key, value);
}

export async function setConfig(config: Config): Promise<void> {
  await ensureInitialized();
  await store.setConfig(config);
}
