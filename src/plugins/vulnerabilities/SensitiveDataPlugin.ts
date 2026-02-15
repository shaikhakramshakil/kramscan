import { BaseVulnerabilityPlugin, PluginContext } from "../types";
import { Vulnerability } from "../../core/vulnerability-detector";

export class SensitiveDataPlugin extends BaseVulnerabilityPlugin {
  readonly name = "Sensitive Data Detector";
  readonly type = "sensitive_data" as const;
  readonly description = "Detects exposed sensitive data in responses";
  
  private readonly patterns = [
    { regex: /sk-[a-zA-Z0-9]{48}/g, name: "OpenAI API Key", severity: "critical" as const },
    { regex: /ghp_[a-zA-Z0-9]{36}/g, name: "GitHub Token", severity: "critical" as const },
    { regex: /AKIA[0-9A-Z]{16}/g, name: "AWS Access Key", severity: "critical" as const },
    { regex: /xox[baprs]-[0-9a-zA-Z]{10,}/g, name: "Slack Token", severity: "high" as const },
    { regex: /eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*/g, name: "JWT Token", severity: "high" as const },
    { regex: /AIza[0-9A-Za-z_-]{35}/g, name: "Google API Key", severity: "high" as const },
    { regex: /password["\s:=]+[^\s"]{6,}/gi, name: "Hardcoded Password", severity: "high" as const },
    { regex: /api[_-]?key["\s:=]+[\w-]{20,}/gi, name: "Generic API Key", severity: "medium" as const },
    { regex: /-----BEGIN (RSA |EC )?PRIVATE KEY-----/g, name: "Private Key", severity: "critical" as const },
    { regex: /database[_-]?url["\s:=]+.*(?:mysql|postgres|mongodb):\/\//gi, name: "Database Connection String", severity: "high" as const },
  ];
  
  async analyzeContent(context: PluginContext, content: string): Promise<Vulnerability[]> {
    const vulnerabilities: Vulnerability[] = [];
    
    for (const pattern of this.patterns) {
      const matches = content.match(pattern.regex);
      if (matches && matches.length > 0) {
        vulnerabilities.push(
          this.createVulnerability(
            `Exposed ${pattern.name}`,
            `Sensitive ${pattern.name} found in response. This could lead to account compromise or data breach.`,
            context.url,
            pattern.severity,
            `Found: ${matches[0].substring(0, 30)}...`,
            "Remove sensitive data from client-side code. Use environment variables and secure secret management.",
            "CWE-200"
          )
        );
      }
    }
    
    return vulnerabilities;
  }
}
