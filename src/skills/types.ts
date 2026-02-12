export type Severity = "info" | "low" | "medium" | "high" | "critical";

export interface Finding {
  id: string;
  skillId: string;
  title: string;
  severity: Severity;
  description: string;
  evidence?: string;
  recommendation?: string;
  references?: string[];
  metadata?: Record<string, unknown>;
}

export interface SkillMetadata {
  id: string;
  name: string;
  description: string;
  tags: string[];
  category?: string;
}

export interface SkillContext {
  targetUrl: string;
  timeoutSeconds: number;
  logger: {
    info(message: string): void;
    warn(message: string): void;
    error(message: string): void;
  };
  http: {
    get: <T = unknown>(url: string) => Promise<{ data: T; headers: Record<string, string> }>;
  };
}

export interface SkillResult {
  skillId: string;
  findings: Finding[];
  metadata?: Record<string, unknown>;
}

export interface Skill {
  id: string;
  name: string;
  description: string;
  tags: string[];
  run(context: SkillContext): Promise<SkillResult>;
}
