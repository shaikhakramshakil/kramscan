import { BaseVulnerabilityPlugin, PluginContext } from "../types";
import { Vulnerability } from "../../core/vulnerability-detector";

export class SecurityHeadersPlugin extends BaseVulnerabilityPlugin {
  readonly name = "Security Headers Analyzer";
  readonly type = "header" as const;
  readonly description = "Analyzes HTTP security headers";
  
  private readonly reportedHosts = new Set<string>();
  
  private readonly requiredHeaders: Record<string, { 
    title: string; 
    severity: "low" | "info"; 
    remediation: string 
  }> = {
    "content-security-policy": {
      title: "Missing Content-Security-Policy",
      severity: "low",
      remediation: "Implement a strict CSP to prevent XSS and data injection attacks.",
    },
    "x-frame-options": {
      title: "Missing X-Frame-Options",
      severity: "low",
      remediation: "Set X-Frame-Options to DENY or SAMEORIGIN to prevent clickjacking.",
    },
    "strict-transport-security": {
      title: "Missing Strict-Transport-Security (HSTS)",
      severity: "low",
      remediation: "Enable HSTS with max-age of at least 31536000 seconds.",
    },
    "x-content-type-options": {
      title: "Missing X-Content-Type-Options",
      severity: "info",
      remediation: "Set X-Content-Type-Options to 'nosniff'.",
    },
    "referrer-policy": {
      title: "Missing Referrer-Policy",
      severity: "info",
      remediation: "Set Referrer-Policy to 'strict-origin-when-cross-origin'.",
    },
    "permissions-policy": {
      title: "Missing Permissions-Policy",
      severity: "info",
      remediation: "Restrict browser features using Permissions-Policy header.",
    },
  };
  
  async analyzeHeaders(context: PluginContext, headers: Record<string, string>): Promise<Vulnerability[]> {
    const host = new URL(context.url).host;
    
    // Only report once per host
    if (this.reportedHosts.has(host)) {
      return [];
    }
    
    const vulnerabilities: Vulnerability[] = [];
    
    for (const [header, config] of Object.entries(this.requiredHeaders)) {
      if (!headers[header.toLowerCase()]) {
        vulnerabilities.push(
          this.createVulnerability(
            config.title,
            `The ${header} security header is not set on ${host}.`,
            context.url,
            config.severity,
            undefined,
            config.remediation
          )
        );
      }
    }
    
    if (vulnerabilities.length > 0) {
      this.reportedHosts.add(host);
    }
    
    return vulnerabilities;
  }
  
  reset(): void {
    this.reportedHosts.clear();
  }
}
