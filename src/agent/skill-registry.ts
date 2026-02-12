/**
 * Skill Registry and Execution System
 * Manages AI-callable security skills with validation, confirmation, and execution
 */

import {
  AgentSkill,
  ToolDefinition,
  ToolCall,
  ToolCallResult,
  AgentContext,
  ConfirmationPrompt,
} from "./types";
import { logger } from "../utils/logger";
import { SkillResult } from "../skills/types";

export class SkillRegistry {
  private skills: Map<string, AgentSkill> = new Map();
  private executionHistory: Array<{
    timestamp: Date;
    skillName: string;
    success: boolean;
    duration: number;
  }> = [];

  /**
   * Register a skill with the registry
   */
  register(skill: AgentSkill): void {
    if (this.skills.has(skill.id)) {
      logger.warn(`Skill ${skill.id} is already registered. Overwriting.`);
    }
    this.skills.set(skill.id, skill);
    logger.debug(`Registered skill: ${skill.id}`);
  }

  /**
   * Unregister a skill
   */
  unregister(skillId: string): boolean {
    return this.skills.delete(skillId);
  }

  /**
   * Get a skill by ID
   */
  get(skillId: string): AgentSkill | undefined {
    return this.skills.get(skillId);
  }

  /**
   * Get all registered skills
   */
  getAll(): AgentSkill[] {
    return Array.from(this.skills.values());
  }

  /**
   * Get all tool definitions for AI function calling
   */
  getToolDefinitions(): ToolDefinition[] {
    return this.getAll().map((skill) => skill.toolDefinition);
  }

  /**
   * Validate tool call parameters
   */
  validateToolCall(toolCall: ToolCall): { valid: boolean; errors: string[] } {
    const skill = this.get(toolCall.name);
    if (!skill) {
      return {
        valid: false,
        errors: [`Unknown skill: ${toolCall.name}`],
      };
    }

    return skill.validateParameters(toolCall.arguments);
  }

  /**
   * Check if a tool call requires confirmation
   */
  requiresConfirmation(toolName: string): boolean {
    const skill = this.get(toolName);
    if (!skill) return false;
    return skill.requiresConfirmation;
  }

  /**
   * Get confirmation prompt for a tool call
   */
  getConfirmationPrompt(toolCall: ToolCall): ConfirmationPrompt | null {
    const skill = this.get(toolCall.name);
    if (!skill) return null;

    return {
      action: skill.name,
      description: skill.description,
      parameters: toolCall.arguments,
      risk: skill.riskLevel,
      estimatedTime: this.formatDuration(skill.estimatedDuration),
    };
  }

  /**
   * Execute a skill by tool call
   */
  async execute(
    toolCall: ToolCall,
    context: AgentContext
  ): Promise<ToolCallResult> {
    const skill = this.get(toolCall.name);
    if (!skill) {
      return {
        toolCallId: toolCall.id,
        success: false,
        error: `Unknown skill: ${toolCall.name}`,
        executionTime: 0,
      };
    }

    // Validate parameters
    const validation = skill.validateParameters(toolCall.arguments);
    if (!validation.valid) {
      return {
        toolCallId: toolCall.id,
        success: false,
        error: `Validation failed: ${validation.errors.join(", ")}`,
        executionTime: 0,
      };
    }

    const startTime = Date.now();
    let result: SkillResult;
    let success = false;
    let error: string | undefined;

    try {
      logger.info(`Executing skill: ${skill.id}`);
      result = await skill.execute(toolCall.arguments, context);
      success = true;
      logger.success(`Skill ${skill.id} completed successfully`);
    } catch (err) {
      error = err instanceof Error ? err.message : String(err);
      logger.error(`Skill ${skill.id} failed: ${error}`);
      result = {
        skillId: skill.id,
        findings: [],
        metadata: { error },
      };
    }

    const executionTime = Date.now() - startTime;

    // Record execution history
    this.executionHistory.push({
      timestamp: new Date(),
      skillName: skill.id,
      success,
      duration: executionTime,
    });

    return {
      toolCallId: toolCall.id,
      success,
      result,
      error,
      executionTime,
    };
  }

  /**
   * Execute multiple skills in parallel
   */
  async executeBatch(
    toolCalls: ToolCall[],
    context: AgentContext
  ): Promise<ToolCallResult[]> {
    const promises = toolCalls.map((call) => this.execute(call, context));
    return Promise.all(promises);
  }

  /**
   * Get execution statistics
   */
  getStats(): {
    totalExecutions: number;
    successfulExecutions: number;
    failedExecutions: number;
    averageDuration: number;
    skillUsage: Record<string, number>;
  } {
    const total = this.executionHistory.length;
    const successful = this.executionHistory.filter((e) => e.success).length;
    const failed = total - successful;
    const avgDuration =
      total > 0
        ? this.executionHistory.reduce((sum, e) => sum + e.duration, 0) / total
        : 0;

    const skillUsage: Record<string, number> = {};
    for (const entry of this.executionHistory) {
      skillUsage[entry.skillName] = (skillUsage[entry.skillName] || 0) + 1;
    }

    return {
      totalExecutions: total,
      successfulExecutions: successful,
      failedExecutions: failed,
      averageDuration: Math.round(avgDuration),
      skillUsage,
    };
  }

  /**
   * Clear execution history
   */
  clearHistory(): void {
    this.executionHistory = [];
  }

  /**
   * List available skills with descriptions
   */
  listSkills(): Array<{
    id: string;
    name: string;
    description: string;
    risk: string;
    requiresConfirmation: boolean;
  }> {
    return this.getAll().map((skill) => ({
      id: skill.id,
      name: skill.name,
      description: skill.description,
      risk: skill.riskLevel,
      requiresConfirmation: skill.requiresConfirmation,
    }));
  }

  private formatDuration(seconds: number): string {
    if (seconds < 60) {
      return `${seconds}s`;
    }
    const minutes = Math.floor(seconds / 60);
    const remainingSeconds = seconds % 60;
    if (remainingSeconds === 0) {
      return `${minutes}m`;
    }
    return `${minutes}m ${remainingSeconds}s`;
  }
}

// Global skill registry instance
export const skillRegistry = new SkillRegistry();
