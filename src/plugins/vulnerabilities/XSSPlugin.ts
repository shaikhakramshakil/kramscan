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

  private async getPayloads(context: PluginContext, param: string): Promise<string[]> {
    if (context.payloadGenerator) {
      const aiPayloads = await context.payloadGenerator.generatePayloads("xss", {
        parameterName: param,
        url: context.url,
        // We could extract more context from the page here if needed
      });
      if (aiPayloads.length > 0) {
        return [...aiPayloads, ...this.payloads];
      }
    }
    return this.payloads;
  }

  async testParameter(context: PluginContext, param: string, _value: string) {
    const payloads = await this.getPayloads(context, param);
    for (const payload of payloads) {
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

      const payloads = await this.getPayloads(context, input.name);
      for (const payload of payloads) {
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
            await context.page.waitForNavigation({ timeout: context.timeout }).catch(() => { });
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
