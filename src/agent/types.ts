/**
 * Core types for the KramScan AI Agent system
 * Defines interfaces for skills, tool calling, conversation context, and agent responses
 */

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

export interface ToolParameter {
  name: string;
  type: "string" | "number" | "boolean" | "array" | "object";
  description: string;
  required: boolean;
  default?: unknown;
  enum?: string[];
}

export interface ToolDefinition {
  name: string;
  description: string;
  parameters: ToolParameter[];
}

export interface ToolCall {
  id: string;
  name: string;
  arguments: Record<string, unknown>;
}

export interface ToolCallResult {
  toolCallId: string;
  success: boolean;
  result?: SkillResult | unknown;
  error?: string;
  executionTime: number;
}

export interface ConversationMessage {
  id: string;
  role: "user" | "assistant" | "system" | "tool";
  content: string;
  timestamp: Date;
  toolCalls?: ToolCall[];
  toolCallResults?: ToolCallResult[];
}

export interface AgentContext {
  sessionId: string;
  userId: string;
  startTime: Date;
  currentTarget?: string;
  lastScanResults?: SkillResult;
  workingDirectory: string;
  environment: {
    nodeVersion: string;
    platform: string;
  };
}

export interface AgentResponse {
  message: string;
  toolCalls?: ToolCall[];
  toolCallResults?: ToolCallResult[];
  requiresConfirmation: boolean;
  pendingAction?: {
    toolName: string;
    description: string;
    parameters: Record<string, unknown>;
    risk: "low" | "medium" | "high";
  };
}

export interface AgentSkill extends Skill {
  /** Tool definition for AI function calling */
  toolDefinition: ToolDefinition;
  
  /** Whether this skill requires user confirmation before execution */
  requiresConfirmation: boolean;
  
  /** Risk level of the skill */
  riskLevel: "low" | "medium" | "high";
  
  /** Estimated execution time in seconds */
  estimatedDuration: number;
  
  /** Validate parameters before execution */
  validateParameters(params: Record<string, unknown>): { valid: boolean; errors: string[] };
  
  /** Execute the skill with given parameters */
  execute(params: Record<string, unknown>, context: AgentContext): Promise<SkillResult>;
}

export interface ConfirmationPrompt {
  action: string;
  description: string;
  parameters: Record<string, unknown>;
  risk: "low" | "medium" | "high";
  estimatedTime: string;
}

export interface AgentConfig {
  maxConversationHistory: number;
  enableConfirmation: boolean;
  autoConfirmLowRisk: boolean;
  maxTokensPerRequest: number;
  temperature: number;
  model: string;
  systemPrompt: string;
}

export const DEFAULT_AGENT_CONFIG: AgentConfig = {
  maxConversationHistory: 20,
  enableConfirmation: true,
  autoConfirmLowRisk: false,
  maxTokensPerRequest: 4096,
  temperature: 0.3,
  model: "claude-3-opus-4-6",
  systemPrompt: ``, // Will be loaded from prompts/system.ts
};
