/**
 * Generate Report Skill
 * Creates professional security reports in multiple formats (DOCX, TXT, JSON)
 */

import { AgentSkill, ToolDefinition, AgentContext } from "../types";
import { SkillResult, Finding } from "../../skills/types";
import { logger } from "../../utils/logger";
import * as fs from "fs/promises";
import * as path from "path";
import * as os from "os";

// Dynamic imports for report generation libraries
let docx: any;

try {
  docx = require("docx");
} catch {
  // docx not available
}

export class GenerateReportSkill implements AgentSkill {
  id = "generate_report";
  name = "Generate Report";
  description =
    "Creates a professional security report in DOCX, TXT, or JSON format based on scan results.";
  tags = ["reporting", "documentation", "export"];
  requiresConfirmation = false;
  riskLevel = "low" as const;
  estimatedDuration = 10; // seconds

  toolDefinition: ToolDefinition = {
    name: "generate_report",
    description:
      "Generate a professional security report from scan results in various formats",
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
          "Scan results to include in report (if not using last scan)",
        required: false,
      },
      {
        name: "format",
        type: "string",
        description: "Report format: 'docx' (Word), 'txt' (text), or 'json'",
        required: false,
        default: "docx",
        enum: ["docx", "txt", "json"],
      },
      {
        name: "outputPath",
        type: "string",
        description:
          "Custom output path for the report. If not provided, saves to ~/.kramscan/reports/",
        required: false,
      },
      {
        name: "includeAnalysis",
        type: "boolean",
        description: "Include AI analysis in the report if available",
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

    // Validate format
    if (params.format) {
      const validFormats = ["docx", "txt", "json"];
      if (!validFormats.includes(params.format as string)) {
        errors.push(`format must be one of: ${validFormats.join(", ")}`);
      }
    }

    // Check scan data availability
    if (params.useLastScan === false && !params.scanResults) {
      errors.push(
        "scanResults is required when useLastScan is false"
      );
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
    const format = (params.format as string) ?? "docx";
    const customPath = params.outputPath as string | undefined;
    const includeAnalysis = (params.includeAnalysis as boolean) ?? true;

    let scanData: {
      findings: Finding[];
      target?: string;
      timestamp?: string;
      metadata?: any;
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

    logger.info(`Generating ${format.toUpperCase()} report`);

    try {
      // Determine output path
      let outputPath: string;
      if (customPath) {
        outputPath = customPath;
      } else {
        const reportsDir = path.join(os.homedir(), ".kramscan", "reports");
        await fs.mkdir(reportsDir, { recursive: true });

        const timestamp = new Date().toISOString().replace(/[:.]/g, "-");
        const targetName = scanData.target
          ? new URL(scanData.target).hostname
          : "scan";
        outputPath = path.join(
          reportsDir,
          `${targetName}-security-report-${timestamp}.${format}`
        );
      }

      // Generate report based on format
      switch (format.toLowerCase()) {
        case "docx":
          await this.generateDocxReport(scanData, outputPath, includeAnalysis);
          break;
        case "txt":
          await this.generateTxtReport(scanData, outputPath, includeAnalysis);
          break;
        case "json":
          await this.generateJsonReport(scanData, outputPath);
          break;
        default:
          throw new Error(`Unsupported format: ${format}`);
      }

      logger.success(`Report saved to: ${outputPath}`);

      return {
        skillId: this.id,
        findings: [],
        metadata: {
          outputPath,
          format,
          target: scanData.target,
          totalFindings: scanData.findings?.length || 0,
          timestamp: new Date().toISOString(),
        },
      };
    } catch (error) {
      const errorMessage =
        error instanceof Error ? error.message : String(error);
      logger.error(`Report generation failed: ${errorMessage}`);

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

  private async generateDocxReport(
    scanData: any,
    outputPath: string,
    includeAnalysis: boolean
  ): Promise<void> {
    if (!docx) {
      throw new Error(
        "DOCX generation requires the 'docx' package. Please install it: npm install docx"
      );
    }

    const {
      Document,
      Paragraph,
      TextRun,
      HeadingLevel,
      Table,
      TableCell,
      TableRow,
      WidthType,
      BorderStyle,
    } = docx;

    const findings = scanData.findings || [];
    const analysisFinding = includeAnalysis
      ? findings.find((f: Finding) => f.skillId === "analyze_findings")
      : null;
    const vulnerabilities = findings.filter(
      (f: Finding) => f.skillId !== "analyze_findings"
    );

    // Create document sections
    const children: any[] = [
      new Paragraph({
        text: "Security Assessment Report",
        heading: HeadingLevel.TITLE,
      }),
      new Paragraph({
        text: `Target: ${scanData.target || "N/A"}`,
        spacing: { after: 200 },
      }),
      new Paragraph({
        text: `Generated: ${new Date().toLocaleString()}`,
        spacing: { after: 400 },
      }),
    ];

    // Executive Summary
    children.push(
      new Paragraph({
        text: "Executive Summary",
        heading: HeadingLevel.HEADING_1,
      })
    );

    const severityCount = this.getSeverityCount(vulnerabilities);
    children.push(
      new Paragraph({
        children: [
          new TextRun({
            text: `Total Vulnerabilities Found: ${vulnerabilities.length}`,
            bold: true,
          }),
        ],
        spacing: { after: 200 },
      })
    );

    if (severityCount.critical > 0) {
      children.push(
        new Paragraph({
          text: `Critical: ${severityCount.critical}`,
          spacing: { after: 100 },
        })
      );
    }
    if (severityCount.high > 0) {
      children.push(
        new Paragraph({
          text: `High: ${severityCount.high}`,
          spacing: { after: 100 },
        })
      );
    }
    if (severityCount.medium > 0) {
      children.push(
        new Paragraph({
          text: `Medium: ${severityCount.medium}`,
          spacing: { after: 100 },
        })
      );
    }
    if (severityCount.low > 0) {
      children.push(
        new Paragraph({
          text: `Low: ${severityCount.low}`,
          spacing: { after: 100 },
        })
      );
    }

    // AI Analysis section
    if (analysisFinding) {
      children.push(
        new Paragraph({
          text: "AI Analysis",
          heading: HeadingLevel.HEADING_1,
          spacing: { before: 400 },
        })
      );
      children.push(
        new Paragraph({
          text: analysisFinding.description,
          spacing: { after: 400 },
        })
      );
    }

    // Detailed Findings
    if (vulnerabilities.length > 0) {
      children.push(
        new Paragraph({
          text: "Detailed Findings",
          heading: HeadingLevel.HEADING_1,
          spacing: { before: 400 },
        })
      );

      vulnerabilities.forEach((vuln: Finding, index: number) => {
        children.push(
          new Paragraph({
            text: `${index + 1}. ${vuln.title}`,
            heading: HeadingLevel.HEADING_2,
            spacing: { before: 300 },
          })
        );

        children.push(
          new Paragraph({
            children: [
              new TextRun({ text: "Severity: ", bold: true }),
              new TextRun({
                text: vuln.severity.toUpperCase(),
                color: this.getSeverityColor(vuln.severity),
              }),
            ],
            spacing: { after: 100 },
          })
        );

        children.push(
          new Paragraph({
            text: vuln.description,
            spacing: { after: 200 },
          })
        );

        if (vuln.evidence) {
          children.push(
            new Paragraph({
              children: [new TextRun({ text: "Evidence:", bold: true })],
              spacing: { before: 100 },
            })
          );
          children.push(
            new Paragraph({
              text: vuln.evidence,
              spacing: { after: 200 },
            })
          );
        }

        if (vuln.recommendation) {
          children.push(
            new Paragraph({
              children: [
                new TextRun({ text: "Recommendation:", bold: true }),
              ],
              spacing: { before: 100 },
            })
          );
          children.push(
            new Paragraph({
              text: vuln.recommendation,
              spacing: { after: 200 },
            })
          );
        }

        if (vuln.references && vuln.references.length > 0) {
          children.push(
            new Paragraph({
              children: [new TextRun({ text: "References:", bold: true })],
              spacing: { before: 100 },
            })
          );
          vuln.references.forEach((ref: string) => {
            children.push(
              new Paragraph({
                text: ref,
                spacing: { after: 100 },
              })
            );
          });
        }
      });
    }

    const doc = new Document({
      sections: [
        {
          properties: {},
          children,
        },
      ],
    });

    const buffer = await docx.Packer.toBuffer(doc);
    await fs.writeFile(outputPath, buffer);
  }

  private async generateTxtReport(
    scanData: any,
    outputPath: string,
    includeAnalysis: boolean
  ): Promise<void> {
    const findings = scanData.findings || [];
    const analysisFinding = includeAnalysis
      ? findings.find((f: Finding) => f.skillId === "analyze_findings")
      : null;
    const vulnerabilities = findings.filter(
      (f: Finding) => f.skillId !== "analyze_findings"
    );

    let content = "SECURITY ASSESSMENT REPORT\n";
    content += "=" .repeat(50) + "\n\n";
    content += `Target: ${scanData.target || "N/A"}\n`;
    content += `Generated: ${new Date().toLocaleString()}\n\n`;

    content += "EXECUTIVE SUMMARY\n";
    content += "-".repeat(50) + "\n";
    content += `Total Vulnerabilities Found: ${vulnerabilities.length}\n`;

    const severityCount = this.getSeverityCount(vulnerabilities);
    if (severityCount.critical > 0)
      content += `Critical: ${severityCount.critical}\n`;
    if (severityCount.high > 0) content += `High: ${severityCount.high}\n`;
    if (severityCount.medium > 0)
      content += `Medium: ${severityCount.medium}\n`;
    if (severityCount.low > 0) content += `Low: ${severityCount.low}\n`;

    content += "\n";

    if (analysisFinding) {
      content += "AI ANALYSIS\n";
      content += "-".repeat(50) + "\n";
      content += analysisFinding.description + "\n\n";
    }

    if (vulnerabilities.length > 0) {
      content += "DETAILED FINDINGS\n";
      content += "-".repeat(50) + "\n\n";

      vulnerabilities.forEach((vuln: Finding, index: number) => {
        content += `${index + 1}. ${vuln.title}\n`;
        content += `   Severity: ${vuln.severity.toUpperCase()}\n`;
        content += `   Description: ${vuln.description}\n`;

        if (vuln.evidence) {
          content += `   Evidence: ${vuln.evidence}\n`;
        }

        if (vuln.recommendation) {
          content += `   Recommendation: ${vuln.recommendation}\n`;
        }

        if (vuln.references && vuln.references.length > 0) {
          content += `   References:\n`;
          vuln.references.forEach((ref: string) => {
            content += `     - ${ref}\n`;
          });
        }

        content += "\n";
      });
    }

    await fs.writeFile(outputPath, content);
  }

  private async generateJsonReport(
    scanData: any,
    outputPath: string
  ): Promise<void> {
    const report = {
      generatedAt: new Date().toISOString(),
      target: scanData.target,
      scanTimestamp: scanData.timestamp,
      metadata: scanData.metadata,
      findings: scanData.findings,
    };

    await fs.writeFile(outputPath, JSON.stringify(report, null, 2));
  }

  private getSeverityCount(findings: Finding[]): {
    critical: number;
    high: number;
    medium: number;
    low: number;
  } {
    return {
      critical: findings.filter((f) => f.severity === "critical").length,
      high: findings.filter((f) => f.severity === "high").length,
      medium: findings.filter((f) => f.severity === "medium").length,
      low: findings.filter((f) => f.severity === "low").length,
    };
  }

  private getSeverityColor(severity: string): string {
    switch (severity) {
      case "critical":
        return "FF0000";
      case "high":
        return "FF4500";
      case "medium":
        return "FFA500";
      case "low":
        return "FFD700";
      default:
        return "808080";
    }
  }

  async run(): Promise<SkillResult> {
    throw new Error(
      "Use execute() method with AgentContext for generate report skill"
    );
  }
}
