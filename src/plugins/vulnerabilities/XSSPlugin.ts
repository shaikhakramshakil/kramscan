import { BaseVulnerabilityPlugin, PluginContext } from "../types";

export class XSSPlugin extends BaseVulnerabilityPlugin {
  readonly name = "XSS Detector";
  readonly type = "xss" as const;
  readonly description = "Detects Cross-Site Scripting vulnerabilities";
  
  private readonly payloads = [
    "<script>alert('XSS')</script>",
    '"><script>alert(1)</script>',
    "<img src=x onerror=alert(1)>",
    "'-alert(1)-'",
    "<svg/onload=alert(1)>",
  ];
  
  async testParameter(context: PluginContext, param: string, _value: string) {
    for (const payload of this.payloads) {
      try {
        const url = new URL(context.url);
        url.searchParams.set(param, payload);
        
        await context.page.goto(url.toString(), { 
          waitUntil: "networkidle2", 
          timeout: context.timeout 
        });
        
        const content = await context.page.content();
        
        if (content.includes(payload)) {
          return this.success(
            this.createVulnerability(
              "Reflected Cross-Site Scripting (XSS)",
              `The parameter '${param}' reflects user input without proper encoding, allowing script injection.`,
              context.url,
              "high",
              `Payload: ${payload}`,
              "Implement input validation, output encoding, and Content Security Policy (CSP) headers.",
              "CWE-79"
            )
          );
        }
      } catch (error) {
        return this.failure((error as Error).message);
      }
    }
    
    return this.failure();
  }
  
  async testFormInput(context: PluginContext, formData: { inputs: Array<{ name: string; type: string }> }) {
    for (const input of formData.inputs) {
      if (input.type === "hidden" || input.type === "submit") continue;
      
      for (const payload of this.payloads) {
        try {
          await context.page.goto(context.url, { 
            waitUntil: "networkidle2", 
            timeout: context.timeout 
          });
          
          const inputSelector = `input[name="${input.name}"], textarea[name="${input.name}"]`;
          await context.page.type(inputSelector, payload);
          
          const submitButton = await context.page.$("input[type=submit], button[type=submit]");
          if (submitButton) {
            await submitButton.click();
            await context.page.waitForNavigation({ timeout: context.timeout }).catch(() => {});
          }
          
          const content = await context.page.content();
          
          if (content.includes(payload)) {
            return this.success(
              this.createVulnerability(
                "Reflected Cross-Site Scripting (XSS)",
                `The form input '${input.name}' reflects user input without proper encoding.`,
                context.url,
                "high",
                `Payload: ${payload}`,
                "Implement input validation, output encoding, and Content Security Policy (CSP) headers.",
                "CWE-79"
              )
            );
          }
        } catch (error) {
          return this.failure((error as Error).message);
        }
      }
    }
    
    return this.failure();
  }
}
