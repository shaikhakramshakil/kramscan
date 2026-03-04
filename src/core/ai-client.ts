import OpenAI from "openai";
import Anthropic from "@anthropic-ai/sdk";
import { GoogleGenerativeAI } from "@google/generative-ai";
import { Mistral } from "@mistralai/mistralai";
import { getConfig } from "./config";
import { ScanResult } from "./vulnerability-detector";

export interface AIResponse {
    content: string;
    usage?: {
        promptTokens: number;
        completionTokens: number;
        totalTokens: number;
    };
}

export interface AIClient {
    analyze(prompt: string, systemPrompt?: string): Promise<AIResponse>;
}

function getApiKeyFromEnv(provider: string): string {
    const envVars: Record<string, string> = {
        openai: process.env.OPENAI_API_KEY || "",
        anthropic: process.env.ANTHROPIC_API_KEY || "",
        gemini: process.env.GEMINI_API_KEY || "",
        mistral: process.env.MISTRAL_API_KEY || "",
        openrouter: process.env.OPENROUTER_API_KEY || "",
        kimi: process.env.KIMI_API_KEY || "",
        groq: process.env.GROQ_API_KEY || "",
    };
    return envVars[provider] || "";
}

export async function createAIClient(): Promise<AIClient> {
    const config = await getConfig();

    if (!config.ai.enabled) {
        throw new Error("AI analysis is not enabled. Run 'kramscan onboard' first.");
    }

    const provider = config.ai.provider;
    const apiKey = config.ai.apiKey || getApiKeyFromEnv(provider);
    const model = config.ai.defaultModel;

    if (!apiKey) {
        throw new Error(
            `No API key configured for ${provider}. Run 'kramscan onboard' or set ${provider.toUpperCase()}_API_KEY environment variable.`
        );
    }

    switch (provider) {
        case "openai":
            return new OpenAIClient(apiKey, model);
        case "anthropic":
            return new AnthropicClient(apiKey, model);
        case "gemini":
            return new GeminiClient(apiKey, model);
        case "openrouter":
            return new OpenRouterClient(apiKey, model);
        case "mistral":
            return new MistralClient(apiKey, model);
        case "kimi":
            return new KimiClient(apiKey, model);
        case "groq":
            return new GroqClient(apiKey, model);
        default:
            throw new Error(`Unsupported AI provider: ${provider}`);
    }
}

class OpenAIClient implements AIClient {
    private client: OpenAI;
    private model: string;

    constructor(apiKey: string, model: string) {
        this.client = new OpenAI({ apiKey });
        this.model = model;
    }

    async analyze(prompt: string, systemPrompt?: string): Promise<AIResponse> {
        const response = await this.client.chat.completions.create({
            model: this.model,
            messages: [
                {
                    role: "system",
                    content: systemPrompt ||
                        "You are a security expert analyzing web application vulnerabilities. Provide detailed, actionable insights.",
                },
                { role: "user", content: prompt },
            ],
            temperature: 0.3,
        });

        const content = response.choices[0]?.message?.content || "";
        return {
            content,
            usage: {
                promptTokens: response.usage?.prompt_tokens || 0,
                completionTokens: response.usage?.completion_tokens || 0,
                totalTokens: response.usage?.total_tokens || 0,
            },
        };
    }
}

class AnthropicClient implements AIClient {
    private client: Anthropic;
    private model: string;

    constructor(apiKey: string, model: string) {
        this.client = new Anthropic({ apiKey });
        this.model = model;
    }

    async analyze(prompt: string, systemPrompt?: string): Promise<AIResponse> {
        const response = await this.client.messages.create({
            model: this.model,
            max_tokens: 4096,
            messages: [
                {
                    role: "user",
                    content: prompt,
                },
            ],
            system: systemPrompt ||
                "You are a security expert analyzing web application vulnerabilities. Provide detailed, actionable insights.",
        });

        const content =
            response.content[0]?.type === "text" ? response.content[0].text : "";

        return {
            content,
            usage: {
                promptTokens: response.usage.input_tokens,
                completionTokens: response.usage.output_tokens,
                totalTokens: response.usage.input_tokens + response.usage.output_tokens,
            },
        };
    }
}

class GeminiClient implements AIClient {
    private client: GoogleGenerativeAI;
    private model: string;

    constructor(apiKey: string, model: string) {
        this.client = new GoogleGenerativeAI(apiKey);
        this.model = model;
    }

    async analyze(prompt: string, systemPrompt?: string): Promise<AIResponse> {
        const generativeModel = this.client.getGenerativeModel({ model: this.model });

        const result = await generativeModel.generateContent([
            systemPrompt || "You are a security expert analyzing web application vulnerabilities. Provide detailed, actionable insights.",
            prompt
        ]);

        const response = await result.response;
        const content = response.text();

        return {
            content,
            usage: {
                promptTokens: response.usageMetadata?.promptTokenCount || 0,
                completionTokens: response.usageMetadata?.candidatesTokenCount || 0,
                totalTokens: response.usageMetadata?.totalTokenCount || 0,
            },
        };
    }
}

class OpenRouterClient implements AIClient {
    private client: OpenAI;
    private model: string;

    constructor(apiKey: string, model: string) {
        this.client = new OpenAI({
            apiKey,
            baseURL: "https://openrouter.ai/api/v1",
        });
        this.model = model;
    }

    async analyze(prompt: string, systemPrompt?: string): Promise<AIResponse> {
        const response = await this.client.chat.completions.create({
            model: this.model,
            messages: [
                {
                    role: "system",
                    content: systemPrompt || "You are a security expert analyzing web application vulnerabilities. Provide detailed, actionable insights.",
                },
                { role: "user", content: prompt },
            ],
            temperature: 0.3,
        });

        const content = response.choices[0]?.message?.content || "";
        return {
            content,
            usage: {
                promptTokens: response.usage?.prompt_tokens || 0,
                completionTokens: response.usage?.completion_tokens || 0,
                totalTokens: response.usage?.total_tokens || 0,
            },
        };
    }
}

class MistralClient implements AIClient {
    private client: Mistral;
    private model: string;

    constructor(apiKey: string, model: string) {
        this.client = new Mistral({ apiKey });
        this.model = model;
    }

    async analyze(prompt: string, systemPrompt?: string): Promise<AIResponse> {
        const response = await this.client.chat.complete({
            model: this.model,
            messages: [
                {
                    role: "system",
                    content: systemPrompt || "You are a security expert analyzing web application vulnerabilities. Provide detailed, actionable insights.",
                },
                { role: "user", content: prompt },
            ],
        });

        const content = typeof response.choices?.[0]?.message?.content === "string"
            ? response.choices[0].message.content
            : "";

        return {
            content,
            usage: {
                promptTokens: response.usage?.promptTokens || 0,
                completionTokens: response.usage?.completionTokens || 0,
                totalTokens: response.usage?.totalTokens || 0,
            },
        };
    }
}

class KimiClient implements AIClient {
    private client: OpenAI;
    private model: string;

    constructor(apiKey: string, model: string) {
        this.client = new OpenAI({
            apiKey,
            baseURL: "https://api.moonshot.cn/v1",
        });
        this.model = model;
    }

    async analyze(prompt: string, systemPrompt?: string): Promise<AIResponse> {
        const response = await this.client.chat.completions.create({
            model: this.model,
            messages: [
                {
                    role: "system",
                    content: systemPrompt || "You are a security expert analyzing web application vulnerabilities. Provide detailed, actionable insights.",
                },
                { role: "user", content: prompt },
            ],
            temperature: 0.3,
        });

        const content = response.choices[0]?.message?.content || "";
        return {
            content,
            usage: {
                promptTokens: response.usage?.prompt_tokens || 0,
                completionTokens: response.usage?.completion_tokens || 0,
                totalTokens: response.usage?.total_tokens || 0,
            },
        };
    }
}

class GroqClient implements AIClient {
    private client: OpenAI;
    private model: string;

    constructor(apiKey: string, model: string) {
        this.client = new OpenAI({
            apiKey,
            baseURL: "https://api.groq.com/openai/v1",
        });
        this.model = model;
    }

    async analyze(prompt: string, systemPrompt?: string): Promise<AIResponse> {
        const response = await this.client.chat.completions.create({
            model: this.model,
            messages: [
                {
                    role: "system",
                    content: systemPrompt || "You are a security expert analyzing web application vulnerabilities. Provide detailed, actionable insights.",
                },
                { role: "user", content: prompt },
            ],
            temperature: 0.3,
        });

        const content = response.choices[0]?.message?.content || "";
        return {
            content,
            usage: {
                promptTokens: response.usage?.prompt_tokens || 0,
                completionTokens: response.usage?.completion_tokens || 0,
                totalTokens: response.usage?.total_tokens || 0,
            },
        };
    }
}

/**
 * Generates a high-level executive summary of the scan results using AI.
 */
export async function generateExecutiveSummary(client: AIClient, result: ScanResult): Promise<string> {
    const vulnSummary = result.vulnerabilities.map(v =>
        `- [${v.severity.toUpperCase()}] ${v.title} on ${v.url}`
    ).join("\n");

    const prompt = `
Please provide a professional executive summary for a web security scan.

Target: ${result.target}
Scan Date: ${result.timestamp}
Total Vulnerabilities: ${result.summary.total}
Critical: ${result.summary.critical}
High: ${result.summary.high}
Medium: ${result.summary.medium}
Low: ${result.summary.low}

Detailed Findings:
${vulnSummary}

The summary should:
1. Briefly state the overall security posture.
2. Highlight the most critical risks.
3. Provide high-level recommendations for management.
4. Be concise (max 3-4 paragraphs).
`;

    const systemPrompt = "You are a senior cybersecurity consultant writing for a non-technical executive audience. Focus on business risk and impact.";

    const response = await client.analyze(prompt, systemPrompt);
    return response.content;
}
