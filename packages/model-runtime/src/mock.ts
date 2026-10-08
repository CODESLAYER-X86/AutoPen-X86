/**
 * Mock provider: deterministic, offline, test-friendly. The default for
 * development so the platform runs without API keys. It NEVER simulates
 * real target interaction — it only provides canned model content.
 */
import type { GenerateRequest, GenerateResult, ModelProvider, ModelCapabilities } from './types.js';

export type MockHandler = (request: GenerateRequest) => string | Promise<string>;

export class MockModelProvider implements ModelProvider {
  readonly id = 'mock';
  readonly model: string;
  private readonly handler?: MockHandler;

  constructor(model = 'mock-model', handler?: MockHandler) {
    this.model = model;
    this.handler = handler;
  }

  capabilities(): ModelCapabilities {
    return { streaming: false, jsonSchema: true, tools: false };
  }

  async generate(request: GenerateRequest): Promise<GenerateResult> {
    const content = this.handler
      ? await this.handler(request)
      : JSON.stringify({ decision: 'CONTINUE', reason: 'mock model output', priority: 0.5 });
    return {
      content,
      provider: this.id,
      model: this.model,
      usage: {
        inputTokens: request.messages.reduce((sum, m) => sum + m.content.length, 0),
        outputTokens: content.length,
      },
      finishReason: 'STOP',
    };
  }
}
