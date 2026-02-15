import { BaseVulnerabilityPlugin, PluginContext } from "../types";

export class CSRFPlugin extends BaseVulnerabilityPlugin {
  readonly name = "CSRF Detector";
  readonly type = "csrf" as const;
  readonly description = "Detects missing CSRF protection in forms";
  
  private readonly csrfTokenPatterns = [
    'name="csrf',
    'name="_token',
    'name="authenticity_token',
    'name="_csrf',
  ];
  
  async analyzeContent(context: PluginContext, content: string) {
    // Look for forms in the content
    const formRegex = /<form[^>]*>([\s\S]*?)<\/form>/gi;
    const forms = content.match(formRegex);
    
    if (!forms) return [];
    
    const vulnerabilities = [];
    
    for (const form of forms) {
      const hasCSRFToken = this.csrfTokenPatterns.some(pattern => 
        form.toLowerCase().includes(pattern.toLowerCase())
      );
      
      if (!hasCSRFToken) {
        // Extract form action for better reporting
        const actionMatch = form.match(/action=["']([^"']*)["']/i);
        const action = actionMatch ? actionMatch[1] : context.url;
        
        vulnerabilities.push(
          this.createVulnerability(
            "Missing CSRF Protection",
            "Form lacks CSRF tokens. Attackers can forge requests to perform unauthorized actions.",
            new URL(action, context.url).toString(),
            "medium",
            "Form HTML does not contain CSRF token",
            "Implement anti-CSRF tokens. Use SameSite cookies.",
            "CWE-352"
          )
        );
      }
    }
    
    return vulnerabilities;
  }
}
