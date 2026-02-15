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

export const ConfigSchema = z.object({
  ai: z.object({
    provider: AiProviderNameSchema,
    apiKey: z.string(),
    defaultModel: z.string(),
    enabled: z.boolean(),
  }),
  scan: z.object({
    defaultTimeout: z.number().int().min(1000),
    maxThreads: z.number().int().min(1).max(20),
    userAgent: z.string(),
    followRedirects: z.boolean(),
    verifySSL: z.boolean(),
    rateLimitPerSecond: z.number().int().min(1).max(100),
    strictScope: z.boolean(),
    profiles: z.record(ScanProfileSchema),
    defaultProfile: z.string(),
  }),
  report: z.object({
    defaultFormat: ReportFormatSchema,
    companyName: z.string(),
    includeScreenshots: z.boolean(),
    severityThreshold: SeverityThresholdSchema,
  }),
  skills: z.record(z.object({
    enabled: z.boolean(),
    timeout: z.number().int().optional(),
  })),
  proxy: z.string().optional(),
});

export type Config = z.infer<typeof ConfigSchema>;
export type AiProviderName = z.infer<typeof AiProviderNameSchema>;
export type ReportFormat = z.infer<typeof ReportFormatSchema>;
export type ScanProfile = z.infer<typeof ScanProfileSchema>;

// Default scan profiles
export const defaultScanProfiles: Record<string, ScanProfile> = {
  quick: { depth: 1, timeout: 15000, maxPages: 10, maxLinksPerPage: 20 },
  balanced: { depth: 2, timeout: 30000, maxPages: 30, maxLinksPerPage: 50 },
  deep: { depth: 3, timeout: 60000, maxPages: 100, maxLinksPerPage: 100 },
};

// Validation function
export function validateConfig(config: unknown): Config {
  return ConfigSchema.parse(config);
}

export function validateScanProfile(profile: unknown): ScanProfile {
  return ScanProfileSchema.parse(profile);
}

// Export default profiles for backward compatibility
export { defaultScanProfiles as scanProfiles };
