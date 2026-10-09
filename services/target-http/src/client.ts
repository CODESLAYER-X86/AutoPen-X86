/**
 * Legacy Part 1 stub surface — retained for API compatibility. The real
 * HTTP engine is `HttpEngine` (engine.ts); this factory now returns the
 * engine-backed client so existing consumers transparently upgrade.
 */
import { HttpEngine } from './engine.js';
import type { HttpMethod } from '@aegis/shared';
import type { ScopeRules } from '@aegis/security';
import type { PlainHeader } from './normalize.js';
import type { HttpBodyInput } from '@aegis/contracts';
import type { HttpExchange } from './engine.js';

export interface TargetHttpRequest {
  method: string;
  url: string;
  headers?: Record<string, string>;
  body?: Uint8Array | string | null;
  identity_id?: string | null;
}

export interface TargetHttpResponse {
  status: number;
  headers: Record<string, string[]>;
  body: Uint8Array;
  duration_ms: number;
}

export interface TargetHttpClient {
  send(request: TargetHttpRequest, scope: ScopeRules, engagementId: string): Promise<TargetHttpResponse>;
  exchange(input: {
    engagementId: string;
    method: HttpMethod;
    url: string;
    headers: PlainHeader[];
    body: HttpBodyInput | null;
    identityId: string | null;
  }, scope: ScopeRules): Promise<HttpExchange>;
}

export function createEngineTargetHttpClient(engine: HttpEngine): TargetHttpClient {
  return {
    async send(request, scope, engagementId) {
      const headers: PlainHeader[] = Object.entries(request.headers ?? {}).map(([name, value]) => ({ name, value }));
      let body: HttpBodyInput | null = null;
      if (typeof request.body === 'string') {
        body = { body_type: 'TEXT', text: request.body };
      } else if (request.body instanceof Uint8Array && request.body.byteLength > 0) {
        body = { body_type: 'BINARY', content_b64: Buffer.from(request.body).toString('base64') };
      }
      const exchange = await engine.send(
        {
          engagementId,
          method: request.method.toUpperCase() as HttpMethod,
          url: request.url,
          headers,
          body,
          identityId: request.identity_id ?? null,
        },
        scope,
      );
      const grouped: Record<string, string[]> = {};
      for (const h of exchange.response.headers) {
        const key = h.name.toLowerCase();
        (grouped[key] ??= []).push(h.value);
      }
      return {
        status: exchange.response.status,
        headers: grouped,
        body: exchange.response.bodyBytes,
        duration_ms: exchange.response.timingMs,
      };
    },
    async exchange(input, scope) {
      return engine.send(
        {
          engagementId: input.engagementId,
          method: input.method,
          url: input.url,
          headers: input.headers,
          body: input.body,
          identityId: input.identityId,
        },
        scope,
      );
    },
  };
}
