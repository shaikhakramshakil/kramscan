/**
 * Analyze Findings Skill
 * AI-powered analysis of security scan results with remediation recommendations
 */

import { AgentSkill, ToolDefinition, AgentContext } from "../types";
import { SkillResult, Finding } from "../../skills/types";
import { createAIClient } from "../../core/ai-client";
import { logger } from "../../utils/logger";

export class AnalyzeFindingsSkill implements AgentSkill {
  id = "analyze_findings";
  name = "Analyze Findings";
  description =
    "Uses AI to analyze security scan results and provide expert insights, risk assessment, and remediation recommendations.";
  tags = ["analysis", "ai", "reporting", "recommendations"];
  requiresConfirmation = false;
  riskLevel = "low" as const;
  estimatedDuration = 15; // seconds

  toolDefinition: ToolDefinition = {
    name: "analyze_findings",
    description:
      "Analyze security scan findings using AI to provide expert insights and remediation recommendations",
    parameters: [
      {
        name: "useLastScan",
        type: "boolean",
        description:
          "Use results from the most recent scan. If true, scanResults parameter is optional.",
        required: false,
        default: true,
      },
      {
        name: "scanResults",
        type: "object",
        description:
          "Scan results to analyze (if not using last scan). Must contain findings array.",
        required: false,
      },
      {
        name: "focus",
        type: "string",
        description:
          "Optional focus area for analysis: 'executive', 'technical', 'remediation', or 'all'",
        required: false,
        default: "all",
        enum: ["executive", "technical", "remediation", "all"],
      },
    ],
  };

  validateParameters(params: Record<string, unknown>): {
    valid: boolean;
    errors: string[];
  } {
    const errors: string[] = [];

    // If not using last scan, must provide scanResults
    if (params.useLastScan === false && !params.scanResults) {
      errors.push(
        "scanResults is required when useLastScan is false"
      );
    }

    // Validate focus if provided
    if (params.focus) {
      const validFocus = ["executive", "technical", "remediation", "all"];
      if (!validFocus.includes(params.focus as string)) {
        errors.push(`focus must be one of: ${validFocus.join(", ")}`);
      }
    }

    return {
      valid: errors.length === 0,
      errors,
    };
  }

  async execute(
    params: Record<string, unknown>,
    context: AgentContext
  ): Promise<SkillResult> {
    const useLastScan = (params.useLastScan as boolean) ?? true;
    const focus = (params.focus as string) ?? "all";

    let scanData: {
      findings: Finding[];
      target?: string;
      timestamp?: string;
    };

    // Get scan data
    if (useLastScan) {
      const lastResults = context.lastScanResults;
      if (!lastResults) {
        return {
          skillId: this.id,
          findings: [],
          metadata: {
            error:
              "No previous scan results found. Please run a scan first.",
          },
        };
      }
      scanData = lastResults as any;
    } else {
      scanData = params.scanResults as any;
    }

    if (!scanData.findings || scanData.findings.length === 0) {
      return {
        skillId: this.id,
        findings: [],
        metadata: {
          message: "No vulnerabilities to analyze.",
          target: scanData.target,
        },
      };
    }

    logger.info(
      `Analyzing ${scanData.findings.length} findings with focus: ${focus}`
    );

    try {
      const aiClient = createAIClient();
      const prompt = this.buildAnalysisPrompt(scanData, focus);

      const response = await aiClient.analyze(prompt);

      // Create a finding for the analysis itself
      const analysisFinding: Finding = {
        id: `analysis-${Date.now()}`,
        skillId: this.id,
        title: "AI Security Analysis",
        severity: "info",
        description: response.content,
        metadata: {
          focus,
          target: scanData.target,
          timestamp: new Date().toISOString(),
          totalFindings: scanData.findings.length,
          tokensUsed: response.usage,
        },
      };

      logger.success("Analysis complete");

      return {
        skillId: this.id,
        findings: [analysisFinding],
        metadata: {
          target: scanData.target,
          focus,
          totalFindings: scanData.findings.length,
          tokensUsed: response.usage,
          timestamp: new Date().toISOString(),
        },
      };
    } catch (error) {
      const errorMessage =
        error instanceof Error ? error.message : String(error);
      logger.error(`Analysis failed: ${errorMessage}`);

      return {
        skillId: this.id,
        findings: [],
        metadata: {
          error: errorMessage,
          target: scanData.target,
        },
      };
    }
  }

  private buildAnalysisPrompt(
    scanData: { findings: Finding[]; target?: string; timestamp?: string },
    focus: string
  ): string {
    const vulnList = scanData.findings
      .map(
        (f, i) =>
          `${i + 1}. [${f.severity.toUpperCase()}] ${f.title}
   Description: ${f.description}
   ${f.evidence ? `Evidence: ${f.evidence}` : ""}
   ${f.recommendation ? `Current recommendation: ${f.recommendation}` : ""}
   ${f.metadata?.cwe ? `CWE: ${f.metadata.cwe}` : ""}`
      )
      .join("\n\n");

    let focusInstructions = "";
    switch (focus) {
      case "executive":
        focusInstructions =
          "Focus on business impact and high-level recommendations. Keep technical details minimal.";
        break;
      case "technical":
        focusInstructions =
          "Provide detailed technical analysis including root causes and specific code/configuration fixes.";
        break;
      case "remediation":
        focusInstructions =
          "Focus primarily on step-by-step remediation actions and prioritization.";
        break;
      default:
        focusInstructions =
          "Provide comprehensive analysis covering all aspects.";
    }

    return `You are a senior security analyst reviewing web application vulnerabilities.

Target: ${scanData.target || "Unknown"}
Scan Date: ${scanData.timestamp || new Date().toISOString()}
Total Vulnerabilities: ${scanData.findings.length}

Vulnerabilities Found:
${vulnList}

Please provide a detailed analysis:

1. **Executive Summary**: Brief overview of security posture and business risk
2. **Risk Assessment**: Overall risk level with justification
3. **Prioritized Recommendations**: Top 3-5 issues to fix first with specific actions
4. **Attack Scenarios**: How vulnerabilities could be chained or exploited
5. **Remediation Roadmap**: Step-by-step plan with effort estimates

${focusInstructions}

Format in clear markdown with headers and bullet points.`;
  }

  async run(): Promise<SkillResult> {
    throw new Error(
      "Use execute() method with AgentContext for analyze findings skill"
    );
  }
}
