/**
 * Web Scan Skill
 * Comprehensive web application security scanner as an AI-callable skill
 * Tests for XSS, SQL injection, CSRF, and security header vulnerabilities
 */

import { AgentSkill, ToolDefinition, AgentContext } from "../types";
import { SkillResult, Finding } from "../../skills/types";
import { Scanner } from "../../core/scanner";
import { logger } from "../../utils/logger";

export class WebScanSkill implements AgentSkill {
  id = "web_scan";
  name = "Web Scan";
  description =
    "Performs a comprehensive security scan of a web application. Tests for XSS, SQL injection, CSRF, and security header misconfigurations.";
  tags = ["scanning", "web", "security", "vulnerability"];
  requiresConfirmation = true;
  riskLevel = "medium" as const;
  estimatedDuration = 60; // seconds

  toolDefinition: ToolDefinition = {
    name: "web_scan",
    description:
      "Scan a web application for security vulnerabilities including XSS, SQL injection, CSRF, and security headers",
    parameters: [
      {
        name: "targetUrl",
        type: "string",
        description:
          "The URL of the web application to scan (e.g., https://example.com)",
        required: true,
      },
      {
        name: "depth",
        type: "number",
        description: "How many levels deep to crawl (1-5). Higher values scan more pages but take longer.",
        required: false,
        default: 2,
      },
      {
        name: "timeout",
        type: "number",
        description: "Request timeout in milliseconds (10000-120000)",
        required: false,
        default: 30000,
      },
      {
        name: "headless",
        type: "boolean",
        description: "Run browser in headless mode (no visible window)",
        required: false,
        default: true,
      },
    ],
  };

  validateParameters(params: Record<string, unknown>): {
    valid: boolean;
    errors: string[];
  } {
    const errors: string[] = [];

    // Validate targetUrl
    if (!params.targetUrl) {
      errors.push("targetUrl is required");
    } else if (typeof params.targetUrl !== "string") {
      errors.push("targetUrl must be a string");
    } else {
      try {
        const url = new URL(params.targetUrl);
        if (!["http:", "https:"].includes(url.protocol)) {
          errors.push("targetUrl must use HTTP or HTTPS protocol");
        }
      } catch {
        errors.push("targetUrl must be a valid URL");
      }
    }

    // Validate depth
    if (params.depth !== undefined) {
      const depth = Number(params.depth);
      if (isNaN(depth) || depth < 1 || depth > 5) {
        errors.push("depth must be a number between 1 and 5");
      }
    }

    // Validate timeout
    if (params.timeout !== undefined) {
      const timeout = Number(params.timeout);
      if (isNaN(timeout) || timeout < 10000 || timeout > 120000) {
        errors.push("timeout must be a number between 10000 and 120000");
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
    const targetUrl = params.targetUrl as string;
    const depth = (params.depth as number) ?? 2;
    const timeout = (params.timeout as number) ?? 30000;
    const headless = (params.headless as boolean) ?? true;

    logger.info(`Starting web scan of ${targetUrl}`);

    const scanner = new Scanner();

    try {
      const scanResult = await scanner.scan(targetUrl, {
        depth,
        timeout,
        headless,
      });

      // Convert vulnerabilities to findings
      const findings: Finding[] = scanResult.vulnerabilities.map((vuln) => ({
        id: `${vuln.type}-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
        skillId: this.id,
        title: vuln.title,
        severity: vuln.severity,
        description: vuln.description,
        evidence: vuln.evidence,
        recommendation: vuln.remediation,
        references: [],
        metadata: {
          url: vuln.url,
          type: vuln.type,
          cwe: vuln.cwe,
        },
      }));

      logger.success(
        `Scan complete. Found ${findings.length} vulnerabilities.`
      );

      return {
        skillId: this.id,
        findings,
        metadata: {
          target: scanResult.target,
          timestamp: scanResult.timestamp,
          duration: scanResult.duration,
          summary: scanResult.summary,
          crawledUrls: scanResult.metadata.crawledUrls,
          testedForms: scanResult.metadata.testedForms,
          requestsMade: scanResult.metadata.requestsMade,
        },
      };
    } catch (error) {
      const errorMessage =
        error instanceof Error ? error.message : String(error);
      logger.error(`Scan failed: ${errorMessage}`);

      return {
        skillId: this.id,
        findings: [],
        metadata: {
          error: errorMessage,
          target: targetUrl,
          timestamp: new Date().toISOString(),
        },
      };
    } finally {
      await scanner.close();
    }
  }

  async run(): Promise<SkillResult> {
    // This method is required by Skill interface but not used in agent context
    throw new Error(
      "Use execute() method with AgentContext for web scan skill"
    );
  }
}
