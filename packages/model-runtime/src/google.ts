/**
 * Google Gemini provider (REST, dependency-free via global fetch).
 *
 * Honest scope: implements `generate` and `countTokens` against the
 * generativelanguage.googleapis.com v1beta REST API. Streaming is not
 * implemented (capabilities().streaming === false).
 *
 * Error mapping (spec §24/§25):
 *   401/403 -> AuthenticationError   429 -> QuotaError
 *   5xx     -> ModelError            timeout -> TimeoutError
 *
 * The API key is injected by the caller (read from the environment) and is
 * never logged or persisted.
 */
import {
  AuthenticationError,
  ModelError,
  QuotaError,
  TimeoutError,
} from '@aegis/shared';
import type { GenerateRequest, GenerateResult, ModelCapabilities, ModelProvider } from './types.js';

const API_BASE = 'https://generativelanguage.googleapis.com/v1beta/models';

interface GoogleOptions {
  apiKey: string;
  model: string;
  timeoutMs?: number;
  fetchImpl?: typeof fetch;
}

interface GeminiPart {
  text?: string;
}

interface GeminiContent {
  role?: 'user' | 'model';
  parts: GeminiPart[];
}

interface GenerateContentResponse {
  candidates?: Array<{
    content?: { parts?: GeminiPart[] };
    finishReason?: string;
  }>;
  usageMetadata?: {
    promptTokenCount?: number;
    candidatesTokenCount?: number;
  };
  error?: { message?: string; status?: string };
}

export class GoogleModelProvider implements ModelProvider {
  readonly id = 'google';
  readonly model: string;
  private readonly apiKey: string;
  private readonly timeoutMs: number;
  private readonly fetchImpl: typeof fetch;

  constructor(options: GoogleOptions) {
    if (!options.apiKey) {
      throw new AuthenticationError(
        'Google API key is required for the google model provider',
        'MODEL_PROVIDER_NOT_CONFIGURED',
      );
    }
    this.apiKey = options.apiKey;
    this.model = options.model;
    this.timeoutMs = options.timeoutMs ?? 60_000;
    this.fetchImpl = options.fetchImpl ?? globalThis.fetch;
  }

  capabilities(): ModelCapabilities {
    return { streaming: false, jsonSchema: true, tools: false };
  }

  async generate(request: GenerateRequest): Promise<GenerateResult> {
    const contents: GeminiContent[] = request.messages.map((message) => ({
      role: message.role === 'assistant' ? 'model' : 'user',
      parts: [{ text: message.content }],
    }));

    const generationConfig: Record<string, unknown> = {};
    if (request.responseJsonSchema) {
      generationConfig.responseMimeType = 'application/json';
      generationConfig.responseSchema = request.responseJsonSchema;
    }
    if (request.maxOutputTokens !== undefined) generationConfig.maxOutputTokens = request.maxOutputTokens;
    if (request.temperature !== undefined) generationConfig.temperature = request.temperature;

    const body: Record<string, unknown> = { contents, generationConfig };
    if (request.system) {
      body.systemInstruction = { parts: [{ text: request.system }] };
    }

    const response = await this.post(`${this.model}:generateContent`, body);
    const parsed = (await response.json()) as GenerateContentResponse;

    const text = (parsed.candidates?.[0]?.content?.parts ?? [])
      .map((part) => part.text ?? '')
      .join('');

    return {
      content: text,
      provider: this.id,
      model: this.model,
      usage: {
        inputTokens: parsed.usageMetadata?.promptTokenCount,
        outputTokens: parsed.usageMetadata?.candidatesTokenCount,
      },
      finishReason: parsed.candidates?.[0]?.finishReason,
    };
  }

  async countTokens(text: string): Promise<number> {
    const response = await this.post(`${this.model}:countTokens`, { contents: [{ parts: [{ text }] }] });
    const parsed = (await response.json()) as { totalTokens?: number };
    return parsed.totalTokens ?? 0;
  }

  private async post(path: string, body: unknown): Promise<Response> {
    let response: Response;
    try {
      response = await this.fetchImpl(`${API_BASE}/${path}`, {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          'x-goog-api-key': this.apiKey,
        },
        body: JSON.stringify(body),
        signal: AbortSignal.timeout(this.timeoutMs),
      });
    } catch (cause) {
      if (
        cause instanceof Error &&
        // The signal is always AbortSignal.timeout() created here, so any
        // abort (TimeoutError DOMException or AbortError) is a timeout.
        (cause.name === 'TimeoutError' || cause.name === 'AbortError')
      ) {
        throw new TimeoutError(`Google model request timed out after ${this.timeoutMs}ms`);
      }
      throw new ModelError('Google model request failed', 'MODEL_REQUEST_FAILED');
    }

    if (!response.ok) {
      const errorBody = await response.text().catch(() => '');
      const detail = errorBody.slice(0, 500);
      if (response.status === 401 || response.status === 403) {
        throw new AuthenticationError('Google API rejected the credentials', 'MODEL_AUTH_FAILED', detail);
      }
      if (response.status === 429) {
        throw new QuotaError('Google API rate limit exceeded', 'MODEL_RATE_LIMITED', detail);
      }
      if (response.status >= 500) {
        throw new ModelError(`Google API server error (${response.status})`, 'MODEL_SERVER_ERROR', detail);
      }
      throw new ModelError(
        `Google API request failed (${response.status})`,
        'MODEL_REQUEST_FAILED',
        detail,
      );
    }
    return response;
  }
}
