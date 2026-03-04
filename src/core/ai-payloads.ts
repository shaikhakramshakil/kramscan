import { AIClient } from "./ai-client";

export type PayloadType = "xss" | "sqli" | "cmdi" | "lfi";

export interface ContextInfo {
    htmlContext?: string;
    tagName?: string;
    attributeName?: string;
    parameterName: string;
    url: string;
}

export class PayloadGenerator {
    constructor(private aiClient: AIClient) { }

    /**
     * Generates a list of contextual payloads based on the provided HTML context.
     */
    async generatePayloads(type: PayloadType, context: ContextInfo): Promise<string[]> {
        const systemPrompt = `You are an expert penetration tester. Your task is to generate 5 highly effective, specialized payloads to test for ${type.toUpperCase()} vulnerabilities.
Focus on bypass techniques relevant to the provided HTML/parameter context.
Format your response as a simple JSON array of strings: ["payload1", "payload2", ...]
Do not include any explanations, just the JSON array.`;

        const prompt = `
Generate 5 ${type.toUpperCase()} payloads for:
Parameter: ${context.parameterName}
URL: ${context.url}
${context.htmlContext ? `HTML Context: ${context.htmlContext}` : ""}
${context.tagName ? `Inside Tag: ${context.tagName}` : ""}
${context.attributeName ? `Inside Attribute: ${context.attributeName}` : ""}

Consider:
1. Filter bypasses (WAF, sanitizers).
2. Escape sequences if inside a string or attribute.
3. Breaking out of tags if applicable.
4. Non-standard encoding (URL/HTML entities) if likely needed.
`;

        try {
            const response = await this.aiClient.analyze(prompt, systemPrompt);
            const content = response.content.trim();

            // Try to parse JSON array from the response
            const match = content.match(/\[.*\]/s);
            if (match) {
                const payloads = JSON.parse(match[0]);
                if (Array.isArray(payloads)) {
                    return payloads.map(p => String(p));
                }
            }

            // Fallback: split by newlines if JSON parsing fails
            return content.split("\n")
                .map(line => line.replace(/^[\d.-]\s*/, "").trim())
                .filter(line => line.length > 0)
                .slice(0, 5);
        } catch (error) {
            console.error(`Error generating AI payloads: ${(error as Error).message}`);
            return [];
        }
    }
}
