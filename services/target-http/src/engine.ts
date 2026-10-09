/**
 * HTTP engine (spec Part 3 §15-§22, §47-§54, §67-§72).
 *
 * The ONLY sanctioned server-side network path for the HTTP worker. It
 * composes the deterministic safety pipeline for every outgoing request:
 *
 *   validate URL (scope + network/SSRF policy)
 *     -> rate limit (engagement + host, §53)
 *     -> concurrency admission (§54)
 *     -> serialize body (§67-§68)
 *     -> auth injection via session manager (§26 — engine never sees secrets)
 *     -> fetch with deadline (§47)
 *     -> manual redirect following, re-validated per hop (§51)
 *     -> response size limit with EXPLICIT truncation flag (§48)
 *
 * The engine is pure execution: persistence and evidence creation live in
 * the traffic recorder / tool layer (§44 persist step).
 */
import { PlatformError, ValidationError, type HttpMethod } from '@aegis/shared';
import type { HttpBodyInput } from '@aegis/contracts';
import type { ScopeRules } from '@aegis/security';
import {
  DEFAULT_NETWORK_POLICY,
  validateAndNormalizeUrl,
  validateRedirectTarget,
  type NetworkPolicy,
  type NormalizedUrl,
} from './url-policy.js';
import { serializeBody, parseResponseBody, type SerializedBody, type ParsedResponseBody } from './body.js';
import { ConcurrencyManager, RateLimitError, SlidingWindowRateLimiter, type ConcurrencyLimits } from './rate.js';
import type { PlainHeader } from './normalize.js';

export class HttpEngineError extends PlatformError {
  constructor(message: string, code: string, status = 502, category: 'NETWORK' | 'QUOTA' | 'VALIDATION' = 'NETWORK') {
    super(message, { code, category, statusCode: status });
    this.name = 'HttpEngineError';
  }
}

export interface HttpEngineLimits {
  /** Maximum response body bytes kept in memory (§48). */
  maxResponseBytes: number;
  maxHtmlBytes: number;
  maxScriptBytes: number;
  maxRequestBytes: number;
  /** Per-request network timeout (§47). */
  timeoutMs: number;
}

export const DEFAULT_HTTP_LIMITS: HttpEngineLimits = {
  maxResponseBytes: 2_097_152, // 2 MiB
  maxHtmlBytes: 2_097_152,
  maxScriptBytes: 4_194_304,
  maxRequestBytes: 1_048_576,
  timeoutMs: 15_000,
};

export interface HttpSendInput {
  /** Rate limiting + concurrency key (§53-§54). */
  engagementId: string;
  method: HttpMethod;
  url: string;
  headers: PlainHeader[];
  body: HttpBodyInput | null;
  identityId: string | null;
  timeoutMs?: number;
  /** Auth injection hook — provided by the session manager (§26). */
  applyAuth?: (identityId: string, headers: PlainHeader[]) => Promise<PlainHeader[]>;
  /** Redirect following override; defaults to policy-follow. */
  followRedirects?: boolean;
}

export interface HttpRedirectHop {
  status: number;
  location: string;
  url: string;
}

export interface HttpExchange {
  request: {
    method: string;
    url: string;
    normalizedUrl: NormalizedUrl;
    headers: PlainHeader[];
    body: SerializedBody | null;
    /** Final headers actually sent (post auth-injection). */
    sentHeaders: PlainHeader[];
  };
  response: {
    status: number;
    headers: PlainHeader[];
    contentType: string | null;
    contentKind: ParsedResponseBody['kind'];
    bodyBytes: Uint8Array;
    parsed: ParsedResponseBody;
    truncated: boolean;
    contentLengthHeader: number | null;
    timingMs: number;
    redirectTo: string | null;
    finalUrl: string;
  };
  redirects: HttpRedirectHop[];
  totalDurationMs: number;
}

export interface HttpEngineDeps {
  limits?: Partial<HttpEngineLimits>;
  networkPolicy?: NetworkPolicy;
  rateLimiter?: SlidingWindowRateLimiter;
  concurrency?: ConcurrencyLimits;
  fetchImpl?: typeof fetch;
}

const HOP_BY_HOP_HEADERS = new Set([
  'connection',
  'keep-alive',
  'proxy-authenticate',
  'proxy-authorization',
  'te',
  'trailer',
  'transfer-encoding',
  'upgrade',
  'host',
  'content-length',
]);

export class HttpEngine {
  private readonly limits: HttpEngineLimits;
  private readonly networkPolicy: NetworkPolicy;
  private readonly rateLimiter: SlidingWindowRateLimiter;
  private readonly concurrency: ConcurrencyManager;
  private readonly fetchImpl: typeof fetch;

  constructor(deps: HttpEngineDeps = {}) {
    this.limits = { ...DEFAULT_HTTP_LIMITS, ...deps.limits };
    this.networkPolicy = deps.networkPolicy ?? DEFAULT_NETWORK_POLICY;
    this.rateLimiter =
      deps.rateLimiter ??
      new SlidingWindowRateLimiter({
        perEngagement: 600,
        perHost: 300,
        windowMs: 60_000,
      });
    this.concurrency = new ConcurrencyManager(
      deps.concurrency ?? { global: 16, perEngagement: 8, perHost: 4 },
    );
    this.fetchImpl = deps.fetchImpl ?? fetch;
  }

  get policy(): NetworkPolicy {
    return this.networkPolicy;
  }

  get engineLimits(): HttpEngineLimits {
    return this.limits;
  }

  /**
   * Execute a request against an authorized target. `scope` MUST be the
   * engagement's effective scope rules; the engine refuses to run without
   * them (§49: no unrestricted server-side requests).
   */
  async send(input: HttpSendInput, scope: ScopeRules): Promise<HttpExchange> {
    const startedAt = Date.now();
    const timeoutMs = Math.min(input.timeoutMs ?? this.limits.timeoutMs, 120_000);

    // 1. Validate + normalize URL (scope + SSRF, §49-§50).
    const normalizedUrl = await validateAndNormalizeUrl(input.url, scope, this.networkPolicy);
    const host = normalizedUrl.host;

    // 2. Rate limit BEFORE any socket opens (§53).
    this.rateLimiter.check(input.engagementId, host);
    this.rateLimiter.consume(input.engagementId, host);

    // 3. Serialize the body (§67-§68).
    const serialized =
      input.body && input.body.body_type !== 'EMPTY' ? serializeBody(input.body) : null;
    if (serialized && serialized.byteLength > this.limits.maxRequestBytes) {
      throw new ValidationError(
        `Request body of ${serialized.byteLength} bytes exceeds the ${this.limits.maxRequestBytes} byte limit`,
        'HTTP_REQUEST_TOO_LARGE',
      );
    }

    // 4. Auth injection (§26): the engine forwards identity_id, never secrets.
    let sentHeaders: PlainHeader[] = [...input.headers];
    if (serialized?.contentType && !hasHeader(sentHeaders, 'content-type')) {
      sentHeaders = [...sentHeaders, { name: 'content-type', value: serialized.contentType }];
    }
    if (input.identityId && input.applyAuth) {
      sentHeaders = await input.applyAuth(input.identityId, sentHeaders);
    }
    sentHeaders = sentHeaders.filter((h) => !HOP_BY_HOP_HEADERS.has(h.name.toLowerCase()));

    // 5. Concurrency admission (§54).
    const release = await this.concurrency.acquire(input.engagementId, host);
    try {
      return await this.fetchWithRedirects(input, scope, sentHeaders, serialized, normalizedUrl, timeoutMs, startedAt);
    } finally {
      release();
    }
  }

  private async fetchWithRedirects(
    input: HttpSendInput,
    scope: ScopeRules,
    headers: PlainHeader[],
    body: SerializedBody | null,
    initialUrl: NormalizedUrl,
    timeoutMs: number,
    startedAt: number,
  ): Promise<HttpExchange> {
    const redirects: HttpRedirectHop[] = [];
    let currentUrl = initialUrl.href;
    let method = input.method;
    // Per spec §47: smallest applicable deadline wins — the total budget
    // covers ALL redirect hops, not each hop individually.
    const deadline = Date.now() + timeoutMs;

    for (let hop = 0; hop <= this.networkPolicy.maxRedirects; hop += 1) {
      const remainingMs = deadline - Date.now();
      if (remainingMs <= 0) {
        throw new HttpEngineError(
          `Request deadline exceeded after ${redirects.length} redirect(s)`,
          'HTTP_DEADLINE_EXCEEDED',
          504,
        );
      }

      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort('timeout'), remainingMs);
      let response: Response;
      const requestStartedAt = Date.now();
      try {
        response = await this.fetchImpl(currentUrl, {
          method,
          headers: headersToRecord(headers),
          body: body && method !== 'GET' && method !== 'HEAD' ? Buffer.from(body.bytes) : undefined,
          redirect: 'manual',
          signal: controller.signal,
        });
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        if (message.includes('abort') || (error as Error & { name?: string }).name === 'AbortError') {
          throw new HttpEngineError(
            `Network timeout after ${Date.now() - requestStartedAt}ms`,
            'HTTP_TIMEOUT',
            504,
          );
        }
        throw new HttpEngineError(`Network request failed: ${message}`, 'HTTP_NETWORK_ERROR');
      } finally {
        clearTimeout(timer);
      }

      // Redirect handling (§51): re-validate EVERY hop against scope + network.
      if (response.status >= 300 && response.status < 400) {
        const location = response.headers.get('location');
        if (!location) {
          throw new HttpEngineError(
            `Redirect status ${response.status} without a Location header`,
            'HTTP_REDIRECT_MISSING_LOCATION',
          );
        }
        if (redirects.length >= this.networkPolicy.maxRedirects) {
          throw new HttpEngineError(
            `Excessive redirects: more than ${this.networkPolicy.maxRedirects} hops`,
            'HTTP_TOO_MANY_REDIRECTS',
            508,
          );
        }
        if (input.followRedirects === false) {
          const finalUrl = await validateRedirectTarget(location, currentUrl, scope, this.networkPolicy);
          return this.buildExchange(
            input, headers, body, initialUrl,
            { status: response.status, headers: fromFetchHeaders(response.headers), response },
            redirects, currentUrl, Date.now() - startedAt, finalUrl.href,
          );
        }
        const target = await validateRedirectTarget(location, currentUrl, scope, this.networkPolicy);
        redirects.push({ status: response.status, location, url: target.href });
        currentUrl = target.href;
        // 301/302 historically re-POST as GET; 307/308 preserve the method.
        if ((response.status === 301 || response.status === 302) && method !== 'GET' && method !== 'HEAD') {
          method = 'GET';
          body = null;
        }
        continue;
      }

      return await this.buildExchangeWithBody(
        input, headers, body, initialUrl, response, redirects, currentUrl, startedAt,
      );
    }

    throw new HttpEngineError(
      `Excessive redirects: more than ${this.networkPolicy.maxRedirects} hops`,
      'HTTP_TOO_MANY_REDIRECTS',
      508,
    );
  }

  private async buildExchangeWithBody(
    input: HttpSendInput,
    headers: PlainHeader[],
    body: SerializedBody | null,
    initialUrl: NormalizedUrl,
    response: Response,
    redirects: HttpRedirectHop[],
    finalUrl: string,
    startedAt: number,
  ): Promise<HttpExchange> {
    const timingMs = Date.now() - startedAt;
    const contentType = response.headers.get('content-type');
    const { bytes, truncated } = await this.readBodyWithLimit(response);
    const parsed = parseResponseBody(bytes, contentType);
    const contentLengthHeader = response.headers.get('content-length');

    return {
      request: {
        method: input.method,
        url: input.url,
        normalizedUrl: initialUrl,
        headers: input.headers,
        body,
        sentHeaders: headers,
      },
      response: {
        status: response.status,
        headers: fromFetchHeaders(response.headers),
        contentType,
        contentKind: parsed.kind,
        bodyBytes: bytes,
        parsed,
        truncated,
        contentLengthHeader: contentLengthHeader ? Number.parseInt(contentLengthHeader, 10) : null,
        timingMs,
        redirectTo: null,
        finalUrl,
      },
      redirects,
      totalDurationMs: Date.now() - startedAt,
    };
  }

  private buildExchange(
    input: HttpSendInput,
    headers: PlainHeader[],
    body: SerializedBody | null,
    initialUrl: NormalizedUrl,
    parts: { status: number; headers: PlainHeader[]; response: Response },
    redirects: HttpRedirectHop[],
    finalUrl: string,
    totalDurationMs: number,
    redirectTo: string,
  ): HttpExchange {
    const contentType = parts.response.headers.get('content-type');
    return {
      request: {
        method: input.method,
        url: input.url,
        normalizedUrl: initialUrl,
        headers: input.headers,
        body,
        sentHeaders: headers,
      },
      response: {
        status: parts.status,
        headers: parts.headers,
        contentType,
        contentKind: 'UNKNOWN',
        bodyBytes: new Uint8Array(0),
        parsed: { kind: 'UNKNOWN', parsed: null, textPreview: null },
        truncated: false,
        contentLengthHeader: null,
        timingMs: totalDurationMs,
        redirectTo,
        finalUrl,
      },
      redirects,
      totalDurationMs,
    };
  }

  /**
   * Read the response body with an explicit size limit (§48). Never throws
   * on overflow: the bytes are kept up to the limit and `truncated=true`.
   */
  private async readBodyWithLimit(response: Response): Promise<{ bytes: Uint8Array; truncated: boolean }> {
    const contentType = response.headers.get('content-type') ?? '';
    let limit = this.limits.maxResponseBytes;
    if (contentType.includes('text/html')) limit = this.limits.maxHtmlBytes;
    else if (contentType.includes('javascript') || contentType.includes('ecmascript')) {
      limit = this.limits.maxScriptBytes;
    }

    const contentLengthHeader = response.headers.get('content-length');
    if (contentLengthHeader !== null) {
      const declared = Number.parseInt(contentLengthHeader, 10);
      if (!Number.isNaN(declared) && declared > limit) {
        // Consume but do not retain beyond the limit.
        await drainStream(response.body, limit + 1);
        return { bytes: new Uint8Array(0), truncated: true };
      }
    }

    if (!response.body) {
      return { bytes: new Uint8Array(0), truncated: false };
    }

    const reader = response.body.getReader();
    const chunks: Uint8Array[] = [];
    let received = 0;
    let truncated = false;
    try {
      for (;;) {
        const { done, value } = await reader.read();
        if (done) break;
        if (value) {
          if (received + value.byteLength > limit) {
            const remaining = Math.max(0, limit - received);
            if (remaining > 0) chunks.push(value.slice(0, remaining));
            received += value.byteLength;
            truncated = true;
            await reader.cancel('size limit');
            break;
          }
          chunks.push(value);
          received += value.byteLength;
        }
      }
    } finally {
      reader.releaseLock();
    }

    const bytes = new Uint8Array(chunks.reduce((sum, c) => sum + c.byteLength, 0));
    let offset = 0;
    for (const chunk of chunks) {
      bytes.set(chunk, offset);
      offset += chunk.byteLength;
    }
    return { bytes, truncated };
  }
}

async function drainStream(body: ReadableStream<Uint8Array> | null, maxBytes: number): Promise<void> {
  if (!body) return;
  const reader = body.getReader();
  let total = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      if (value) {
        total += value.byteLength;
        if (total > maxBytes) {
          await reader.cancel('size limit');
          break;
        }
      }
    }
  } finally {
    reader.releaseLock();
  }
}

function headersToRecord(headers: PlainHeader[]): Record<string, string> {
  const out: Record<string, string> = {};
  for (const h of headers) {
    const key = h.name.toLowerCase();
    if (!(key in out)) out[key] = h.value;
  }
  return out;
}

function fromFetchHeaders(headers: Headers): PlainHeader[] {
  const out: PlainHeader[] = [];
  headers.forEach((value, name) => {
    out.push({ name, value });
  });
  return out;
}

function hasHeader(headers: PlainHeader[], name: string): boolean {
  return headers.some((h) => h.name.toLowerCase() === name.toLowerCase());
}

export { RateLimitError };
