/**
 * Agent Orchestrator
 * Coordinates AI conversations, tool calling, skill execution, and user interactions
 */

import { ConversationContext } from "./context";
import { SkillRegistry } from "./skill-registry";
import { ConfirmationHandler } from "./confirmation";
import { getSystemPrompt } from "./prompts/system";
import {
  AgentConfig,
  DEFAULT_AGENT_CONFIG,
  AgentResponse,
  ToolCall,
  ConversationMessage,
} from "./types";
import { createAIClient, AIClient } from "../core/ai-client";
import { logger } from "../utils/logger";
import chalk from "chalk";

export class AgentOrchestrator {
  private context: ConversationContext;
  private skillRegistry: SkillRegistry;
  private confirmationHandler: ConfirmationHandler;
  private config: AgentConfig;
  private aiClient: AIClient | null = null;
  private isRunning = false;

  constructor(
    skillRegistry: SkillRegistry,
    config: Partial<AgentConfig> = {}
  ) {
    this.skillRegistry = skillRegistry;
    this.config = { ...DEFAULT_AGENT_CONFIG, ...config };
    this.context = new ConversationContext(this.config);
    this.confirmationHandler = new ConfirmationHandler();
  }

  /**
   * Initialize the orchestrator and AI client
   */
  async initialize(): Promise<void> {
    try {
      this.aiClient = createAIClient();
      logger.success("AI client initialized successfully");
    } catch (error) {
      logger.error(
        "Failed to initialize AI client. Run 'kramscan onboard' first."
      );
      throw error;
    }

    // Add system message
    this.context.addMessage("system", getSystemPrompt());

    // Try to load previous conversation
    await this.context.load();
  }

  /**
   * Process a user message and generate a response
   */
  async processUserMessage(userInput: string): Promise<AgentResponse> {
    // Add user message to context
    this.context.addMessage("user", userInput);

    // Get AI response
    const aiResponse = await this.getAIResponse();

    // Check for tool calls in the response
    const toolCalls = this.parseToolCalls(aiResponse);

    if (toolCalls.length > 0) {
      // Handle tool execution with confirmation
      return this.handleToolExecution(toolCalls, aiResponse);
    }

    // No tool calls - just return the message
    this.context.addMessage("assistant", aiResponse);

    return {
      message: aiResponse,
      requiresConfirmation: false,
    };
  }

  /**
   * Execute a specific tool/skill directly
   */
  async executeTool(
    toolName: string,
    parameters: Record<string, unknown>,
    skipConfirmation = false
  ): Promise<AgentResponse> {
    const toolCall: ToolCall = {
      id: `manual-${Date.now()}`,
      name: toolName,
      arguments: parameters,
    };

    if (!skipConfirmation && this.skillRegistry.requiresConfirmation(toolName)) {
      const confirmation = this.skillRegistry.getConfirmationPrompt(toolCall);
      if (confirmation) {
        const result = await this.confirmationHandler.prompt(confirmation);

        if (result.showDetails) {
          this.confirmationHandler.showDetails(confirmation);
          return {
            message: "Please confirm to proceed after reviewing the details.",
            requiresConfirmation: true,
            pendingAction: {
              toolName,
              description: confirmation.description,
              parameters,
              risk: confirmation.risk,
            },
          };
        }

        if (!result.confirmed || result.cancelled) {
          return {
            message: result.cancelled
              ? "Action cancelled."
              : "Action not confirmed. You can ask me to perform this action again when you're ready.",
            requiresConfirmation: false,
          };
        }
      }
    }

    // Execute the tool
    const result = await this.skillRegistry.execute(
      toolCall,
      this.context.getContext()
    );

    // Format response
    const responseMessage = this.formatToolResult(result);

    this.context.addMessage(
      "assistant",
      responseMessage,
      [toolCall],
      [result]
    );

    // Store scan results if applicable
    if (toolName === "web_scan" && result.success && result.result) {
      this.context.setLastScanResults(result.result);
      const target = parameters.targetUrl as string;
      this.context.setCurrentTarget(target);
    }

    return {
      message: responseMessage,
      toolCalls: [toolCall],
      toolCallResults: [result],
      requiresConfirmation: false,
    };
  }

  /**
   * Get conversation summary
   */
  getConversationSummary(): ReturnType<ConversationContext["getSummary"]> {
    return this.context.getSummary();
  }

  /**
   * Clear conversation history
   */
  clearConversation(): void {
    this.context.clear();
    this.context.addMessage("system", getSystemPrompt());
    logger.info("Conversation history cleared");
  }

  /**
   * Save conversation state
   */
  async saveState(): Promise<void> {
    await this.context.save();
  }

  /**
   * Get available skills list
   */
  getAvailableSkills(): ReturnType<SkillRegistry["listSkills"]> {
    return this.skillRegistry.listSkills();
  }

  /**
   * Shutdown the orchestrator
   */
  async shutdown(): Promise<void> {
    this.isRunning = false;
    this.confirmationHandler.close();
    await this.saveState();
  }

  /**
   * Check if orchestrator is running
   */
  isActive(): boolean {
    return this.isRunning;
  }

  /**
   * Start the agent session
   */
  start(): void {
    this.isRunning = true;
  }

  // Private methods

  private async getAIResponse(): Promise<string> {
    if (!this.aiClient) {
      throw new Error("AI client not initialized");
    }

    try {
      const messages = this.context.formatForAI();
      const prompt = this.buildPromptWithTools(messages);

      const response = await this.aiClient.analyze(prompt);
      return response.content;
    } catch (error) {
      logger.error(`Failed to get AI response: ${error}`);
      return "I apologize, but I'm having trouble processing your request right now. Please try again.";
    }
  }

  private buildPromptWithTools(
    messages: Array<{ role: string; content: string }>
  ): string {
    const conversation = messages
      .map((m) => `${m.role}: ${m.content}`)
      .join("\n\n");

    const tools = this.skillRegistry.getToolDefinitions();
    const toolsDescription = tools
      .map(
        (tool) => `
Tool: ${tool.name}
Description: ${tool.description}
Parameters:
${tool.parameters
  .map(
    (p) =>
      `  - ${p.name} (${p.type}${p.required ? ", required" : ""}): ${p.description}${p.default !== undefined ? ` (default: ${p.default})` : ""}`
  )
  .join("\n")}
`
      )
      .join("\n");

    return `${conversation}

Available Tools:
${toolsDescription}

When you need to use a tool, format your response exactly like this:

<tool_call>
{
  "name": "tool_name",
  "arguments": {
    "param1": "value1",
    "param2": "value2"
  }
}
</tool_call>

If you don't need a tool, just respond naturally.`;
  }

  private parseToolCalls(response: string): ToolCall[] {
    const toolCalls: ToolCall[] = [];
    const regex = /<tool_call>\s*([\s\S]*?)\s*<\/tool_call>/g;
    let match;

    while ((match = regex.exec(response)) !== null) {
      try {
        const parsed = JSON.parse(match[1]);
        toolCalls.push({
          id: `tool-${Date.now()}-${toolCalls.length}`,
          name: parsed.name,
          arguments: parsed.arguments || {},
        });
      } catch (error) {
        logger.warn(`Failed to parse tool call: ${match[1]}`);
      }
    }

    return toolCalls;
  }

  private async handleToolExecution(
    toolCalls: ToolCall[],
    aiMessage: string
  ): Promise<AgentResponse> {
    // Extract message without tool calls
    const cleanMessage = aiMessage.replace(/<tool_call>[\s\S]*?<\/tool_call>/g, "").trim();

    // Check if any tool requires confirmation
    const needsConfirmation = toolCalls.some((call) =>
      this.skillRegistry.requiresConfirmation(call.name)
    );

    if (needsConfirmation && this.config.enableConfirmation) {
      // Get confirmation for first tool (simplify UX)
      const firstTool = toolCalls.find((call) =>
        this.skillRegistry.requiresConfirmation(call.name)
      )!;
      const confirmation = this.skillRegistry.getConfirmationPrompt(firstTool);

      if (confirmation) {
        const result = await this.confirmationHandler.prompt(confirmation);

        if (result.showDetails) {
          this.confirmationHandler.showDetails(confirmation);
          return {
            message: cleanMessage || "Please review the details and confirm to proceed.",
            requiresConfirmation: true,
            pendingAction: {
              toolName: firstTool.name,
              description: confirmation.description,
              parameters: firstTool.arguments,
              risk: confirmation.risk,
            },
          };
        }

        if (!result.confirmed) {
          return {
            message: result.cancelled
              ? "Action cancelled."
              : "Action not confirmed. Let me know when you're ready to proceed.",
            requiresConfirmation: false,
          };
        }
      }
    }

    // Execute all tools
    console.log(chalk.gray("\nExecuting tools...\n"));
    const results = await this.skillRegistry.executeBatch(
      toolCalls,
      this.context.getContext()
    );

    // Format results
    const resultMessage = results
      .map((result) => this.formatToolResult(result))
      .join("\n\n");

    const fullMessage = cleanMessage
      ? `${cleanMessage}\n\n${resultMessage}`
      : resultMessage;

    this.context.addMessage("assistant", fullMessage, toolCalls, results);

    // Update context with scan results
    const scanResult = results.find((r) =>
      r.toolCallId.includes("web_scan")
    );
    if (scanResult?.success && scanResult.result) {
      this.context.setLastScanResults(scanResult.result);
      const target = toolCalls.find((t) => t.name === "web_scan")?.arguments
        .targetUrl as string;
      if (target) {
        this.context.setCurrentTarget(target);
      }
    }

    return {
      message: fullMessage,
      toolCalls,
      toolCallResults: results,
      requiresConfirmation: false,
    };
  }

  private formatToolResult(result: {
    toolCallId: string;
    success: boolean;
    result?: unknown;
    error?: string;
    executionTime: number;
  }): string {
    if (!result.success) {
      return chalk.red(`❌ Error: ${result.error || "Unknown error"}`);
    }

    const skillResult = result.result as {
      skillId: string;
      findings: any[];
      metadata?: any;
    };

    if (!skillResult) {
      return chalk.gray("✓ Completed");
    }

    const findings = skillResult.findings || [];
    if (findings.length === 0) {
      return chalk.green("✓ No issues found");
    }

    const critical = findings.filter((f) => f.severity === "critical").length;
    const high = findings.filter((f) => f.severity === "high").length;
    const medium = findings.filter((f) => f.severity === "medium").length;
    const low = findings.filter((f) => f.severity === "low").length;

    const parts = [];
    if (critical > 0) parts.push(chalk.red(`${critical} Critical`));
    if (high > 0) parts.push(chalk.red(`${high} High`));
    if (medium > 0) parts.push(chalk.yellow(`${medium} Medium`));
    if (low > 0) parts.push(chalk.blue(`${low} Low`));

    return `Found: ${parts.join(", ") || chalk.green("None")}`;
  }
}
