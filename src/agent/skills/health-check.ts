/**
 * Health Check Skill
 * Verifies system configuration, dependencies, and environment setup
 */

import { AgentSkill, ToolDefinition, AgentContext, SkillResult, Finding } from "../types";
import { getConfig, Config } from "../../core/config";
import { logger } from "../../utils/logger";
import * as fs from "fs";
import * as path from "path";
import * as os from "os";

interface HealthCheck {
  name: string;
  status: "ok" | "warning" | "error";
  message: string;
  details?: string;
}

export class HealthCheckSkill implements AgentSkill {
  id = "health_check";
  name = "Health Check";
  description =
    "Verifies system configuration, API keys, dependencies, and overall environment health.";
  tags = ["diagnostics", "configuration", "setup"];
  requiresConfirmation = false;
  riskLevel = "low" as const;
  estimatedDuration = 5; // seconds

  toolDefinition: ToolDefinition = {
    name: "health_check",
    description:
      "Check system health, configuration, and dependencies. Reports on API keys, Node version, and required packages.",
    parameters: [
      {
        name: "verbose",
        type: "boolean",
        description: "Show detailed diagnostic information",
        required: false,
        default: false,
      },
    ],
  };

  validateParameters(params: Record<string, unknown>): {
    valid: boolean;
    errors: string[];
  } {
    // No required parameters
    return { valid: true, errors: [] };
  }

  async execute(
    params: Record<string, unknown>,
    context: AgentContext
  ): Promise<SkillResult> {
    const verbose = (params.verbose as boolean) ?? false;

    logger.info("Running health check...");

    const checks: HealthCheck[] = [];
    const findings: Finding[] = [];

    // Check Node version
    const nodeCheck = this.checkNodeVersion();
    checks.push(nodeCheck);
    if (nodeCheck.status !== "ok") {
      findings.push(this.createFinding(nodeCheck));
    }

    // Check configuration
    const configCheck = this.checkConfiguration();
    checks.push(configCheck);
    if (configCheck.status !== "ok") {
      findings.push(this.createFinding(configCheck));
    }

    // Check AI provider
    const aiCheck = await this.checkAIProvider();
    checks.push(aiCheck);
    if (aiCheck.status !== "ok") {
      findings.push(this.createFinding(aiCheck));
    }

    // Check dependencies
    const depsCheck = this.checkDependencies();
    checks.push(depsCheck);
    if (depsCheck.status !== "ok") {
      findings.push(this.createFinding(depsCheck));
    }

    // Check directories
    const dirCheck = this.checkDirectories();
    checks.push(dirCheck);
    if (dirCheck.status !== "ok") {
      findings.push(this.createFinding(dirCheck));
    }

    // Summary
    const errors = checks.filter((c) => c.status === "error").length;
    const warnings = checks.filter((c) => c.status === "warning").length;

    let overallStatus: "ok" | "warning" | "error" = "ok";
    if (errors > 0) overallStatus = "error";
    else if (warnings > 0) overallStatus = "warning";

    logger.success(
      `Health check complete: ${errors} errors, ${warnings} warnings`
    );

    return {
      skillId: this.id,
      findings,
      metadata: {
        overallStatus,
        totalChecks: checks.length,
        errors,
        warnings,
        checks: verbose ? checks : undefined,
        timestamp: new Date().toISOString(),
      },
    };
  }

  private checkNodeVersion(): HealthCheck {
    const version = process.version;
    const majorVersion = parseInt(version.slice(1).split(".")[0], 10);

    if (majorVersion >= 22) {
      return {
        name: "Node.js Version",
        status: "ok",
        message: `Node.js ${version} (>=22 recommended)`,
      };
    } else if (majorVersion >= 18) {
      return {
        name: "Node.js Version",
        status: "warning",
        message: `Node.js ${version} (>=22 recommended)`,
        details: "Upgrade to Node.js 22 or later for best compatibility",
      };
    } else {
      return {
        name: "Node.js Version",
        status: "error",
        message: `Node.js ${version} (>=18 required)`,
        details: "Node.js 18 or later is required to run KramScan",
      };
    }
  }

  private checkConfiguration(): HealthCheck {
    try {
      const config = getConfig();

      if (!config.ai.enabled) {
        return {
          name: "Configuration",
          status: "warning",
          message: "AI features not configured",
          details: "Run 'kramscan onboard' to configure AI provider",
        };
      }

      if (!config.ai.apiKey) {
        return {
          name: "Configuration",
          status: "error",
          message: "AI API key not set",
          details: `Configure ${config.ai.provider} API key`,
        };
      }

      return {
        name: "Configuration",
        status: "ok",
        message: `AI configured (${config.ai.provider})`,
      };
    } catch (error) {
      return {
        name: "Configuration",
        status: "error",
        message: "Failed to load configuration",
        details: error instanceof Error ? error.message : String(error),
      };
    }
  }

  private async checkAIProvider(): Promise<HealthCheck> {
    const config = getConfig();

    if (!config.ai.enabled || !config.ai.apiKey) {
      return {
        name: "AI Provider",
        status: "warning",
        message: "AI provider not configured",
        details: "Skipping AI connectivity check",
      };
    }

    try {
      // Try to create AI client
      const { createAIClient } = await import("../../core/ai-client");
      const client = createAIClient();

      // Simple test prompt
      const response = await client.analyze("Hello");

      if (response.content) {
        return {
          name: "AI Provider",
          status: "ok",
          message: `${config.ai.provider} connection successful`,
          details: `Model: ${config.ai.defaultModel}`,
        };
      } else {
        return {
          name: "AI Provider",
          status: "warning",
          message: `${config.ai.provider} connected but no response`,
        };
      }
    } catch (error) {
      return {
        name: "AI Provider",
        status: "error",
        message: `Failed to connect to ${config.ai.provider}`,
        details: error instanceof Error ? error.message : String(error),
      };
    }
  }

  private checkDependencies(): HealthCheck {
    const requiredPackages = [
      "puppeteer",
      "commander",
      "chalk",
      "ora",
      "inquirer",
    ];

    const missing: string[] = [];

    for (const pkg of requiredPackages) {
      try {
        require.resolve(pkg);
      } catch {
        missing.push(pkg);
      }
    }

    if (missing.length === 0) {
      return {
        name: "Dependencies",
        status: "ok",
        message: "All required packages installed",
      };
    } else {
      return {
        name: "Dependencies",
        status: "error",
        message: `${missing.length} packages missing`,
        details: `Missing: ${missing.join(", ")}. Run: npm install`,
      };
    }
  }

  private checkDirectories(): HealthCheck {
    const kramscanDir = path.join(os.homedir(), ".kramscan");
    const requiredDirs = ["scans", "reports", "skills"];
    const missing: string[] = [];

    for (const dir of requiredDirs) {
      const fullPath = path.join(kramscanDir, dir);
      if (!fs.existsSync(fullPath)) {
        missing.push(dir);
        try {
          fs.mkdirSync(fullPath, { recursive: true });
        } catch {
          // Ignore errors, will report as missing
        }
      }
    }

    if (missing.length === 0) {
      return {
        name: "Directories",
        status: "ok",
        message: "All required directories exist",
      };
    } else {
      return {
        name: "Directories",
        status: "warning",
        message: `Created ${missing.length} missing directories`,
        details: `Created: ${missing.join(", ")}`,
      };
    }
  }

  private createFinding(check: HealthCheck): Finding {
    return {
      id: `health-${check.name.toLowerCase().replace(/\s+/g, "-")}-${Date.now()}`,
      skillId: this.id,
      title: `${check.name}: ${check.status.toUpperCase()}`,
      severity: check.status === "error" ? "high" : "medium",
      description: check.message,
      evidence: check.details,
      recommendation: this.getRecommendation(check),
      metadata: {
        checkName: check.name,
        status: check.status,
      },
    };
  }

  private getRecommendation(check: HealthCheck): string {
    const recommendations: Record<string, string> = {
      "Node.js Version": "Install Node.js 22 or later from https://nodejs.org/",
      Configuration:
        "Run 'kramscan onboard' to configure your AI provider and API keys",
      "AI Provider":
        "Verify your API key is correct and the provider service is accessible",
      Dependencies: "Run 'npm install' to install missing packages",
      Directories: "Run 'kramscan doctor' to fix directory permissions",
    };

    return recommendations[check.name] || "Check the details above for guidance";
  }

  async run(): Promise<SkillResult> {
    throw new Error(
      "Use execute() method with AgentContext for health check skill"
    );
  }
}
