import { z } from "zod";

// ─── Zod Schemas ───────────────────────────────────────────────────
export const AiProviderNameSchema = z.enum([
  "openai",
  "anthropic",
  "gemini",
  "openrouter",
  "mistral",
  "kimi",
  "groq",
]);

export const ReportFormatSchema = z.enum(["word", "txt", "json"]);

export const SeverityThresholdSchema = z.enum(["info", "low", "medium", "high", "critical"]);

export const ScanProfileSchema = z.object({
  depth: z.number().int().min(1).max(5),
  timeout: z.number().int().min(1000),
  maxPages: z.number().int().min(1),
  maxLinksPerPage: z.number().int().min(1),
});

export type ScanProfile = z.infer<typeof ScanProfileSchema>;

// Default scan profiles
export const defaultScanProfiles: Record<string, ScanProfile> = {
  quick: { depth: 1, timeout: 15000, maxPages: 10, maxLinksPerPage: 20 },
  balanced: { depth: 2, timeout: 30000, maxPages: 30, maxLinksPerPage: 50 },
  deep: { depth: 3, timeout: 60000, maxPages: 100, maxLinksPerPage: 100 },
};

export const ConfigSchema = z.object({
  ai: z.object({
    provider: AiProviderNameSchema.default("openai"),
    apiKey: z.string().default(""),
    defaultModel: z.string().default("gpt-4"),
    enabled: z.boolean().default(false),
  }),
  scan: z.object({
    defaultTimeout: z.number().int().min(1000).default(30000),
    maxThreads: z.number().int().min(1).max(20).default(5),
    userAgent: z.string().default("KramScan/0.1.1"),
    followRedirects: z.boolean().default(true),
    verifySSL: z.boolean().default(true),
    rateLimitPerSecond: z.number().int().min(1).max(100).default(5),
    strictScope: z.boolean().default(true),
    profiles: z.record(ScanProfileSchema).default(defaultScanProfiles),
    defaultProfile: z.string().default("balanced"),
  }),
  report: z.object({
    defaultFormat: ReportFormatSchema.default("word"),
    companyName: z.string().default("Your Company"),
    includeScreenshots: z.boolean().default(false),
    severityThreshold: SeverityThresholdSchema.default("low"),
  }),
  skills: z.record(z.object({
    enabled: z.boolean().default(true),
    timeout: z.number().int().optional(),
  })).default({}),
  proxy: z.string().optional(),
});

export type Config = z.infer<typeof ConfigSchema>;
export type AiProviderName = z.infer<typeof AiProviderNameSchema>;
export type ReportFormat = z.infer<typeof ReportFormatSchema>;

// Validation function
export function validateConfig(config: unknown): Config {
  return ConfigSchema.parse(config);
}

export function validateScanProfile(profile: unknown): ScanProfile {
  return ScanProfileSchema.parse(profile);
}

// Export default profiles for backward compatibility
export { defaultScanProfiles as scanProfiles };
