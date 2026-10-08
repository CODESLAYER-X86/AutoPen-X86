import { describe, expect, it } from 'vitest';
import {
  AuthenticationError,
  QuotaError,
  TimeoutError,
} from '@aegis/shared';
import { GoogleModelProvider, MockModelProvider, ModelRouter } from '@aegis/model-runtime';

describe('mock model provider', () => {
  it('returns deterministic structured output by default', async () => {
    const provider = new MockModelProvider('mock-1');
    const result = await provider.generate({ messages: [{ role: 'user', content: 'hello' }] });
    expect(result.provider).toBe('mock');
    expect(result.model).toBe('mock-1');
    expect(() => JSON.parse(result.content)).not.toThrow();
  });

  it('supports custom handlers for tests', async () => {
    const provider = new MockModelProvider('mock-2', () =>
      JSON.stringify({ decision: 'STOP', reason: 'done', priority: 0.1 }),
    );
    const result = await provider.generate({ messages: [] });
    const parsed = JSON.parse(result.content) as { decision: string };
    expect(parsed.decision).toBe('STOP');
  });

  it('reports honest capabilities', () => {
    const capabilities = new MockModelProvider().capabilities();
    expect(capabilities.streaming).toBe(false);
    expect(capabilities.jsonSchema).toBe(true);
    expect(capabilities.tools).toBe(false);
  });
});

describe('google model provider (request shaping & error mapping)', () => {
  const validKey = 'test-api-key';

  function providerWith(fetchImpl: typeof fetch): GoogleModelProvider {
    return new GoogleModelProvider({
      apiKey: validKey,
      model: 'gemini-test-1',
      timeoutMs: 500,
      fetchImpl: fetchImpl as typeof fetch,
    });
  }

  it('sends a properly-shaped generateContent request', async () => {
    let capturedUrl = '';
    let capturedInit: RequestInit | undefined;
    const provider = providerWith((async (url: unknown, init?: RequestInit) => {
      capturedUrl = url as string;
      capturedInit = init;
      return new Response(
        JSON.stringify({
          candidates: [
            { content: { parts: [{ text: '{"decision":"CONTINUE"}' }] }, finishReason: 'STOP' },
          ],
          usageMetadata: { promptTokenCount: 10, candidatesTokenCount: 5 },
        }),
        { status: 200 },
      );
    }) as typeof fetch);

    const result = await provider.generate({
      messages: [{ role: 'user', content: 'analyze this' }],
      system: 'You are a security analyst.',
      responseJsonSchema: { type: 'object' },
      temperature: 0.2,
      maxOutputTokens: 512,
    });

    expect(capturedUrl).toBe(
      'https://generativelanguage.googleapis.com/v1beta/models/gemini-test-1:generateContent',
    );
    const headers = new Headers(capturedInit?.headers);
    expect(headers.get('x-goog-api-key')).toBe(validKey);
    expect(headers.get('content-type')).toBe('application/json');
    const body = JSON.parse(String(capturedInit?.body)) as {
      contents: Array<{ role: string; parts: Array<{ text: string }> }>;
      systemInstruction: { parts: Array<{ text: string }> };
      generationConfig: Record<string, unknown>;
    };
    expect(body.contents[0]?.parts[0]?.text).toBe('analyze this');
    expect(body.systemInstruction.parts[0]?.text).toBe('You are a security analyst.');
    expect(body.generationConfig.responseMimeType).toBe('application/json');
    expect(body.generationConfig.temperature).toBe(0.2);
    expect(result.content).toBe('{"decision":"CONTINUE"}');
    expect(result.usage?.inputTokens).toBe(10);
  });

  it('maps 429 to QuotaError', async () => {
    const provider = providerWith((async () => new Response('{"error":{}}', { status: 429 })) as typeof fetch);
    await expect(
      provider.generate({ messages: [{ role: 'user', content: 'x' }] }),
    ).rejects.toThrowError(QuotaError);
  });

  it('maps 401/403 to AuthenticationError', async () => {
    const provider = providerWith((async () => new Response('{"error":{}}', { status: 403 })) as typeof fetch);
    await expect(provider.generate({ messages: [] })).rejects.toThrowError(AuthenticationError);
  });

  it('maps 5xx to ModelError', async () => {
    const provider = providerWith((async () => new Response('{}', { status: 503 })) as typeof fetch);
    await expect(provider.generate({ messages: [] })).rejects.toThrowError(/server error/i);
  });

  it('requires an API key at construction', () => {
    expect(() => new GoogleModelProvider({ apiKey: '', model: 'x' })).toThrowError(
      AuthenticationError,
    );
  });

  it('countTokens returns the reported total', async () => {
    const provider = providerWith((async () => new Response('{"totalTokens": 42}', { status: 200 })) as typeof fetch);
    await expect(provider.countTokens('some text')).resolves.toBe(42);
  });
});

describe('model router (spec §19 roles)', () => {
  it('resolves providers per role', () => {
    const router = new ModelRouter({
      strategic: new MockModelProvider('strategic-1'),
      tactical: new MockModelProvider('tactical-1'),
    });
    expect(router.forRole('strategic').model).toBe('strategic-1');
    expect(router.forRole('tactical').model).toBe('tactical-1');
    expect(router.all()).toHaveLength(2);
  });
});

describe('provider timeout behaviour', () => {
  it('surface timeouts as TimeoutError semantics via abort signal', async () => {
    const provider = new GoogleModelProvider({
      apiKey: 'k',
      model: 'm',
      timeoutMs: 50,
      // Cooperative mock: honours the abort signal like a real fetch.
      fetchImpl: (async (_url: unknown, init?: RequestInit) => {
        await new Promise<void>((resolve, reject) => {
          const signal = init?.signal;
          if (signal) {
            signal.addEventListener('abort', () => {
              const error = new Error('This operation was aborted');
              error.name = 'AbortError';
              reject(error);
            });
          }
          setTimeout(resolve, 2000);
        });
        return new Response('{}');
      }) as unknown as typeof fetch,
    });
    await expect(provider.generate({ messages: [] })).rejects.toThrowError(TimeoutError);
  });
});
