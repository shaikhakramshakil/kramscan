/**
 * Conversation Context Manager
 * Manages conversation history, user context, and session state
 */

import { ConversationMessage, AgentContext, AgentConfig, DEFAULT_AGENT_CONFIG } from "./types";
import { v4 as uuidv4 } from "uuid";
import * as os from "os";
import * as path from "path";
import * as fs from "fs/promises";

export class ConversationContext {
  private messages: ConversationMessage[] = [];
  private context: AgentContext;
  private config: AgentConfig;
  private historyFile: string;

  constructor(config: Partial<AgentConfig> = {}) {
    this.config = { ...DEFAULT_AGENT_CONFIG, ...config };
    this.context = this.initializeContext();
    this.historyFile = path.join(
      os.homedir(),
      ".kramscan",
      "agent-history.json"
    );
  }

  private initializeContext(): AgentContext {
    return {
      sessionId: uuidv4(),
      userId: os.userInfo().username,
      startTime: new Date(),
      workingDirectory: process.cwd(),
      environment: {
        nodeVersion: process.version,
        platform: process.platform,
      },
    };
  }

  /**
   * Get the current agent context
   */
  getContext(): AgentContext {
    return { ...this.context };
  }

  /**
   * Update the current target URL
   */
  setCurrentTarget(target: string): void {
    this.context.currentTarget = target;
  }

  /**
   * Get the current target URL
   */
  getCurrentTarget(): string | undefined {
    return this.context.currentTarget;
  }

  /**
   * Store last scan results
   */
  setLastScanResults(results: unknown): void {
    this.context.lastScanResults = results as any;
  }

  /**
   * Get last scan results
   */
  getLastScanResults(): unknown | undefined {
    return this.context.lastScanResults;
  }

  /**
   * Add a message to the conversation
   */
  addMessage(
    role: ConversationMessage["role"],
    content: string,
    toolCalls?: any[],
    toolCallResults?: any[]
  ): ConversationMessage {
    const message: ConversationMessage = {
      id: uuidv4(),
      role,
      content,
      timestamp: new Date(),
      toolCalls,
      toolCallResults,
    };

    this.messages.push(message);
    this.trimHistory();
    return message;
  }

  /**
   * Get all conversation messages
   */
  getMessages(): ConversationMessage[] {
    return [...this.messages];
  }

  /**
   * Get recent messages (for AI context)
   */
  getRecentMessages(count: number = this.config.maxConversationHistory): ConversationMessage[] {
    return this.messages.slice(-count);
  }

  /**
   * Get the last message
   */
  getLastMessage(): ConversationMessage | undefined {
    return this.messages[this.messages.length - 1];
  }

  /**
   * Get conversation summary for display
   */
  getSummary(): {
    totalMessages: number;
    sessionDuration: string;
    currentTarget?: string;
    hasScanResults: boolean;
  } {
    const duration = Date.now() - this.context.startTime.getTime();
    const hours = Math.floor(duration / (1000 * 60 * 60));
    const minutes = Math.floor((duration % (1000 * 60 * 60)) / (1000 * 60));
    const seconds = Math.floor((duration % (1000 * 60)) / 1000);

    let sessionDuration: string;
    if (hours > 0) {
      sessionDuration = `${hours}h ${minutes}m ${seconds}s`;
    } else if (minutes > 0) {
      sessionDuration = `${minutes}m ${seconds}s`;
    } else {
      sessionDuration = `${seconds}s`;
    }

    return {
      totalMessages: this.messages.length,
      sessionDuration,
      currentTarget: this.context.currentTarget,
      hasScanResults: !!this.context.lastScanResults,
    };
  }

  /**
   * Clear conversation history
   */
  clear(): void {
    this.messages = [];
    this.context.currentTarget = undefined;
    this.context.lastScanResults = undefined;
  }

  /**
   * Trim history to max length
   */
  private trimHistory(): void {
    if (this.messages.length > this.config.maxConversationHistory * 2) {
      // Keep system message if present, then last N messages
      const systemMessages = this.messages.filter((m) => m.role === "system");
      const recentMessages = this.messages.slice(-this.config.maxConversationHistory);
      this.messages = [...systemMessages, ...recentMessages];
    }
  }

  /**
   * Persist conversation to disk
   */
  async save(): Promise<void> {
    try {
      const data = {
        context: this.context,
        messages: this.messages,
        timestamp: new Date().toISOString(),
      };

      const dir = path.dirname(this.historyFile);
      await fs.mkdir(dir, { recursive: true });
      await fs.writeFile(this.historyFile, JSON.stringify(data, null, 2));
    } catch (error) {
      console.error("Failed to save conversation history:", error);
    }
  }

  /**
   * Load conversation from disk
   */
  async load(): Promise<boolean> {
    try {
      const data = await fs.readFile(this.historyFile, "utf-8");
      const parsed = JSON.parse(data);

      if (parsed.context) {
        this.context = { ...this.context, ...parsed.context };
      }
      if (parsed.messages) {
        this.messages = parsed.messages.map((m: any) => ({
          ...m,
          timestamp: new Date(m.timestamp),
        }));
      }

      return true;
    } catch {
      return false;
    }
  }

  /**
   * Format messages for AI provider (OpenAI/Anthropic format)
   */
  formatForAI(): Array<{ role: string; content: string }> {
    return this.messages
      .filter((m) => m.role !== "system")
      .map((m) => ({
        role: m.role,
        content: m.content,
      }));
  }
}
