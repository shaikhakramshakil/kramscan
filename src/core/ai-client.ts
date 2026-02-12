import OpenAI from "openai";
import Anthropic from "@anthropic-ai/sdk";
import { getConfig } from "./config";

export interface AIResponse {
    content: string;
    usage?: {
        promptTokens: number;
        completionTokens: number;
        totalTokens: number;
    };
}

export interface AIClient {
    analyze(prompt: string): Promise<AIResponse>;
}

class OpenAIClient implements AIClient {
    private client: OpenAI;
    private model: string;

    constructor(apiKey: string, model: string) {
        this.client = new OpenAI({ apiKey });
        this.model = model;
    }

    async analyze(prompt: string): Promise<AIResponse> {
        const response = await this.client.chat.completions.create({
            model: this.model,
            messages: [
                {
                    role: "system",
                    content:
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

    async analyze(prompt: string): Promise<AIResponse> {
        const response = await this.client.messages.create({
            model: this.model,
            max_tokens: 4096,
            messages: [
                {
                    role: "user",
                    content: prompt,
                },
            ],
            system:
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

export function createAIClient(): AIClient {
    const config = getConfig();

    if (!config.ai.enabled) {
        throw new Error("AI analysis is not enabled. Run 'kramscan onboard' first.");
    }

    const provider = config.ai.provider;
    const apiKey = config.ai.apiKey;
    const model = config.ai.defaultModel;

    if (!apiKey) {
        throw new Error(
            `No API key configured for ${provider}. Run 'kramscan onboard' to set it up.`
        );
    }

    switch (provider) {
        case "openai":
            return new OpenAIClient(apiKey, model);
        case "anthropic":
            return new AnthropicClient(apiKey, model);
        default:
            throw new Error(`Unsupported AI provider: ${provider}`);
    }
}
