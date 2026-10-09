/**
 * Browser network capture (spec Part 3 §12-§14, §62).
 *
 * Bridges Playwright network activity into the SHARED normalized
 * HttpRequest/HttpResponse representation so browser traffic can be
 * promoted into the HTTP testing subsystem (§14: "Do not create
 * incompatible models").
 *
 * Persisted HTTP records cover significant resource types (document, xhr,
 * fetch, script); every request still produces a browser event. Bodies
 * are capped, with explicit truncation flags (§48).
 */
import type { BrowserContext, Page, Request, Response } from 'playwright-core';
import { createHash } from 'node:crypto';
import type { HttpExchange } from '@aegis/target-http';
import type { SerializedBody } from '@aegis/target-http';
import { parseResponseBody } from '@aegis/target-http';
import type { PlainHeader } from '@aegis/target-http';

/** Resource types promoted into full HTTP records (§12 significant). */
const PERSISTED_RESOURCE_TYPES = new Set(['document', 'xhr', 'fetch', 'script', 'websocket']);

export interface NetworkCaptureLimits {
  maxBodyBytes: number;
}

export const DEFAULT_NETWORK_CAPTURE_LIMITS: NetworkCaptureLimits = {
  maxBodyBytes: 2_097_152,
};

interface PendingCapture {
  requestId: string;
  request: Request;
  response: Response | null;
  failed: boolean;
}

export interface CapturedExchange {
  exchange: HttpExchange;
  resourceType: string;
  shouldPersistRecord: boolean;
  pageUrl: string | null;
}

/**
 * Attaches network capture to a page. Collected exchanges drain via
 * `drain()` after actions — deterministic ordering, bounded memory.
 */
export class PageNetworkCapture {
  private readonly pending: PendingCapture[] = [];
  private readonly responses = new Map<Request, Response>();

  constructor(
    private readonly page: Page,
    private readonly limits: NetworkCaptureLimits,
  ) {}

  attach(): void {
    this.page.on('response', (response) => {
      this.responses.set(response.request(), response);
    });
    this.page.on('requestfinished', (request) => {
      this.pushPending(request, null, false, null);
    });
    this.page.on('requestfailed', (request) => {
      const failure = request.failure()?.errorText ?? 'request failed';
      this.pushPending(request, null, true, failure);
    });
  }

  private pushPending(request: Request, _response: Response | null, failed: boolean, _failureText: string | null): void {
    if (this.pending.some((p) => p.request === request)) return;
    const response = this.responses.get(request) ?? null;
    this.pending.push({
      requestId: `${request.method()}:${request.url()}`,
      request,
      response,
      failed,
    });
    this.responses.delete(request);
  }

  get pendingCount(): number {
    return this.pending.length;
  }

  /** Convert all pending network activity into normalized exchanges. */
  async drain(): Promise<CapturedExchange[]> {
    const batch = this.pending.splice(0, this.pending.length);
    const out: CapturedExchange[] = [];
    for (const item of batch) {
      const captured = await this.captureOne(item);
      if (captured) out.push(captured);
    }
    return out;
  }

  private async captureOne(item: PendingCapture): Promise<CapturedExchange | null> {
    const { request, response, failed } = item;
    const url = request.url();
    if (url.startsWith('data:') || url.startsWith('blob:')) return null;

    const resourceType = request.resourceType();
    const pageUrl = this.page.url() === 'about:blank' ? null : this.page.url();

    const method = request.method().toUpperCase();
    const requestHeaders: PlainHeader[] = (await request.headersArray())
      .slice(0, 64)
      .map((h: { name: string; value: string }) => ({ name: h.name.slice(0, 128), value: h.value.slice(0, 8192) }));

    const postData = request.postDataBuffer();
    let body: SerializedBody | null = null;
    if (postData && postData.byteLength > 0) {
      body = {
        bytes: new Uint8Array(postData),
        contentType: requestHeaders.find((h) => h.name.toLowerCase() === 'content-type')?.value ?? null,
        parsed: safeParseText(postData.toString('utf8')),
        byteLength: postData.byteLength,
        sha256: createHash('sha256').update(postData).digest('hex'),
      };
    }

    const timing = response ? safeTiming(response) : null;
    let status = 0;
    let responseHeaders: PlainHeader[] = [];
    let contentType: string | null = null;
    let bodyBytes = new Uint8Array(0);
    let truncated = false;
    let redirectTo: string | null = null;

    if (failed) {
      status = 0;
    } else if (response) {
      status = response.status();
      responseHeaders = (await response.headersArray())
        .slice(0, 64)
        .map((h: { name: string; value: string }) => ({ name: h.name.slice(0, 128), value: h.value.slice(0, 8192) }));
      contentType = response.headers()['content-type'] ?? null;
      redirectTo = response.headers()['location'] ?? null;
      if (status >= 300 && status < 400) {
        // Redirect responses: body not retrievable in Playwright.
      } else {
        try {
          const raw = await response.body();
          const bytes = new Uint8Array(raw);
          if (bytes.byteLength > this.limits.maxBodyBytes) {
            bodyBytes = bytes.slice(0, this.limits.maxBodyBytes);
            truncated = true;
          } else {
            bodyBytes = bytes;
          }
        } catch {
          // Some responses (e.g. 304, streamed) cannot provide a body —
          // represented honestly as zero bytes, not fabricated.
        }
      }
    }

    const parsed = parseResponseBody(bodyBytes, contentType);
    const exchange: HttpExchange = {
      request: {
        method,
        url,
        normalizedUrl: {
          scheme: new URL(url).protocol.replace(':', ''),
          host: new URL(url).hostname,
          port: null,
          path: new URL(url).pathname,
          query: new URL(url).search,
          href: url,
          resolvedIps: [],
        },
        headers: requestHeaders,
        body,
        sentHeaders: requestHeaders,
      },
      response: {
        status,
        headers: responseHeaders,
        contentType,
        contentKind: parsed.kind,
        bodyBytes,
        parsed,
        truncated,
        contentLengthHeader: null,
        timingMs: timing ?? 0,
        redirectTo,
        finalUrl: url,
      },
      redirects: [],
      totalDurationMs: timing ?? 0,
    };

    return {
      exchange,
      resourceType,
      shouldPersistRecord: PERSISTED_RESOURCE_TYPES.has(resourceType) && !failed,
      pageUrl,
    };
  }
}

function safeParseText(text: string): unknown {
  if (text.length > 8192) return { note: 'body exceeds inline parse limit', bytes: text.length };
  try {
    return JSON.parse(text) as unknown;
  } catch {
    return null;
  }
}

function safeTiming(response: Response): number | null {
  try {
    const timing = response.request().timing();
    if (typeof timing.responseStart === 'number' && timing.responseStart >= 0) {
      return Math.round(timing.responseStart);
    }
    return null;
  } catch {
    return null;
  }
}


/** Attach capture for a whole context (all pages incl. popups). */
export function attachContextCapture(
  context: BrowserContext,
  limits: NetworkCaptureLimits,
): Map<Page, PageNetworkCapture> {
  const captures = new Map<Page, PageNetworkCapture>();
  const attachPage = (page: Page): void => {
    const capture = new PageNetworkCapture(page, limits);
    capture.attach();
    captures.set(page, capture);
    page.on('close', () => {
      captures.delete(page);
    });
  };
  context.on('page', attachPage);
  for (const page of context.pages()) attachPage(page);
  return captures;
}
