/**
 * Controlled web fetcher for knowledge ingestion (spec Part 5 §26-§28,
 * §52-§53, §66, §80-§82).
 *
 * Reuses the Part 3 network safety principles:
 *  - URL validation BEFORE any connection (SSRF defence: DNS resolution +
 *    IP classification; loopback/private/link-local denied by default)
 *  - redirects re-validated per hop
 *  - bounded body reads with explicit truncation flags
 *  - per-source and global rate limits + concurrency limits (§82)
 *  - ETag/Last-Modified conditional requests avoid re-downloads (§66)
 *
 * Scripts/macros in downloaded files are NEVER executed (§52-§53): bytes
 * are hashed, sealed into object storage and parsed as data.
 */
import { lookup } from 'node:dns/promises';
import { isIP } from 'node:net';
import { classifyIp } from '@aegis/target-http';
import { ValidationError } from '@aegis/shared';
import type { ObjectStore } from '@aegis/evidence';
import { bytesHash } from './util.js';

/** Knowledge-fetch policy violation (SSRF/size/rate/budget). */
export class KnowledgeFetchError extends ValidationError {
  constructor(message: string, code: string) {
    super(message, code);
  }
}

export interface FetchLimits {
  maxPageBytes: number;
  maxRedirects: number;
  timeoutMs: number;
  maxConcurrency: number;
  ratePerSourcePerMinute: number;
  dailyFetchBudget: number;
  allowLoopback: boolean;
}

export interface FetchPolicyInput {
  allowedDomains?: string[];
  blockedDomains?: string[];
}

export interface FetchedDocument {
  url: string;
  finalUrl: string;
  statusCode: number;
  contentType: string | null;
  bytes: Uint8Array;
  byteLength: number;
  truncated: boolean;
  etag: string | null;
  lastModified: string | null;
  /** Content-addressed object-store key of the raw artifact (§94). */
  artifactKey: string | null;
  notModified: boolean;
}

interface FetchCallOptions {
  etag?: string | null;
  lastModified?: string | null;
  /** Engagement-bound daily budget counter holder. */
  budget?: { searches?: number; pages?: number; bytes?: number; deadlineMs?: number };
  fetchImpl?: typeof fetch;
}

export interface KnowledgeFetcherDeps {
  limits: FetchLimits;
  objectStore?: ObjectStore;
  /** Injectable clock/fetch for deterministic tests. */
  fetchImpl?: typeof fetch;
  now?: () => number;
}

const SCHEME_RE = /^https?:$/i;

/** Validate a knowledge URL under the knowledge network policy (§26). */
export async function validateKnowledgeUrl(
  rawUrl: string,
  policy: FetchPolicyInput,
  limits: { allowLoopback: boolean },
): Promise<URL> {
  let url: URL;
  try {
    url = new URL(rawUrl);
  } catch {
    throw new KnowledgeFetchError(`URL could not be parsed: ${rawUrl.slice(0, 200)}`, 'INVALID_URL');
  }
  if (rawUrl.length > 2048) {
    throw new KnowledgeFetchError('URL exceeds 2048 characters', 'URL_TOO_LONG');
  }
  if (!SCHEME_RE.test(url.protocol)) {
    throw new KnowledgeFetchError(`Scheme not allowed for knowledge fetch: ${url.protocol}`, 'SCHEME_NOT_ALLOWED');
  }
  if (url.username || url.password) {
    throw new KnowledgeFetchError('URLs with embedded credentials are rejected', 'USERINFO_NOT_ALLOWED');
  }
  const host = url.hostname.toLowerCase();
  const blocked = policy.blockedDomains ?? [];
  const allowed = policy.allowedDomains ?? [];
  if (blocked.some((d) => host === d || host.endsWith(`.${d}`))) {
    throw new KnowledgeFetchError(`Domain is blocked for knowledge fetch: ${host}`, 'DOMAIN_BLOCKED');
  }
  if (allowed.length > 0 && !allowed.some((d) => host === d || host.endsWith(`.${d}`))) {
    throw new KnowledgeFetchError(`Domain is not in the knowledge allowlist: ${host}`, 'DOMAIN_NOT_ALLOWED');
  }
  // SSRF defence: resolve DNS BEFORE connecting and classify the IP (§26,
  // Part 3 §50). Knowledge fetch is stricter than target traffic by default.
  if (isIP(host)) {
    assertIpAllowed(host, limits.allowLoopback);
  } else {
    try {
      const records = await lookup(host, { all: true, verbatim: true });
      for (const record of records) {
        assertIpAllowed(record.address, limits.allowLoopback);
      }
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === 'ENOTFOUND' || (error as NodeJS.ErrnoException).code === 'EAI_AGAIN') {
        throw new KnowledgeFetchError(`Knowledge host does not resolve: ${host}`, 'HOST_NOT_RESOLVABLE');
      }
      throw error;
    }
  }
  return url;
}

function assertIpAllowed(ip: string, allowLoopback: boolean): void {
  const classification = classifyIp(ip);
  if (classification === 'PUBLIC') return;
  if (classification === 'LOOPBACK' && allowLoopback) return;
  throw new KnowledgeFetchError(
    `Knowledge fetch refused non-public address (${classification}): ${ip}`,
    'NON_PUBLIC_ADDRESS',
  );
}

/** Per-source sliding-window rate limiter (§82). */
export class SourceRateLimiter {
  private readonly windows = new Map<string, number[]>();
  constructor(private readonly maxPerMinute: number, private readonly now: () => number = Date.now) {}

  check(sourceKey: string): boolean {
    const window = this.windows.get(sourceKey) ?? [];
    const currentTime = this.now();
    const recent = window.filter((t) => currentTime - t < 60_000);
    if (recent.length >= this.maxPerMinute) {
      this.windows.set(sourceKey, recent);
      return false;
    }
    recent.push(currentTime);
    this.windows.set(sourceKey, recent);
    return true;
  }

  prune(): void {
    const currentTime = this.now();
    for (const [key, window] of this.windows) {
      const recent = window.filter((t) => currentTime - t < 60_000);
      if (recent.length === 0) this.windows.delete(key);
      else this.windows.set(key, recent);
    }
  }
}

/** Bounded concurrency guard (§82). */
export class ConcurrencyGate {
  private active = 0;
  private readonly waiters: Array<() => void> = [];
  constructor(private readonly max: number) {}

  async acquire(): Promise<void> {
    if (this.active < this.max) {
      this.active += 1;
      return;
    }
    await new Promise<void>((resolve) => this.waiters.push(resolve));
    this.active += 1;
  }

  release(): void {
    this.active = Math.max(0, this.active - 1);
    const next = this.waiters.shift();
    next?.();
  }
}

export class KnowledgeFetcher {
  private readonly limits: FetchLimits;
  private readonly objectStore?: ObjectStore;
  private readonly fetchImpl: typeof fetch;
  private readonly rateLimiter: SourceRateLimiter;
  private readonly gate: ConcurrencyGate;
  /** Global daily budget counters (§83/§82). */
  private daily = { fetches: 0, day: new Date().toISOString().slice(0, 10) };

  constructor(private readonly deps: KnowledgeFetcherDeps) {
    this.limits = deps.limits;
    this.objectStore = deps.objectStore;
    this.fetchImpl = deps.fetchImpl ?? fetch;
    this.rateLimiter = new SourceRateLimiter(deps.limits.ratePerSourcePerMinute, deps.now ?? Date.now);
    this.gate = new ConcurrencyGate(deps.limits.maxConcurrency);
  }

  /** Daily fetch budget state (for status reporting). */
  budgetState(): { day: string; fetches: number; limit: number } {
    const today = new Date((this.deps.now ?? Date.now)()).toISOString().slice(0, 10);
    if (today !== this.daily.day) this.daily = { fetches: 0, day: today };
    return { day: this.daily.day, fetches: this.daily.fetches, limit: this.limits.dailyFetchBudget };
  }

  async fetch(rawUrl: string, policy: FetchPolicyInput, options: FetchCallOptions = {}): Promise<FetchedDocument> {
    const url = await validateKnowledgeUrl(rawUrl, policy, this.limits);
    const sourceKey = url.hostname;
    if (!this.rateLimiter.check(sourceKey)) {
      throw new KnowledgeFetchError(`Knowledge fetch rate limit exceeded for ${sourceKey}`, 'RATE_LIMITED');
    }
    const budget = this.budgetState();
    if (budget.fetches >= budget.limit) {
      throw new KnowledgeFetchError('Knowledge daily fetch budget exhausted', 'DAILY_BUDGET_EXHAUSTED');
    }
    this.daily.fetches += 1;

    await this.gate.acquire();
    try {
      return await this.fetchWithRedirects(url, policy, options, 0);
    } finally {
      this.gate.release();
    }
  }

  private async fetchWithRedirects(
    url: URL,
    policy: FetchPolicyInput,
    options: FetchCallOptions,
    depth: number,
  ): Promise<FetchedDocument> {
    if (depth > this.limits.maxRedirects) {
      throw new KnowledgeFetchError(`Knowledge fetch exceeded ${this.limits.maxRedirects} redirects`, 'TOO_MANY_REDIRECTS');
    }
    const headers: Record<string, string> = {
      accept: 'text/html, application/xhtml+xml, text/markdown, application/json, application/xml, text/plain, application/pdf, */*',
      'user-agent': 'Aegis-Knowledge-Fetcher/0.5 (authorized security testing platform; contact: operator)',
    };
    if (options.etag) headers['if-none-match'] = options.etag;
    if (options.lastModified) headers['if-modified-since'] = options.lastModified;

    const response = await this.fetchImpl(url.toString(), {
      method: 'GET',
      headers,
      redirect: 'manual',
      signal: AbortSignal.timeout(this.limits.timeoutMs),
    });

    if (response.status >= 300 && response.status < 400) {
      const location = response.headers.get('location');
      if (!location) {
        throw new KnowledgeFetchError('Redirect without Location header', 'INVALID_REDIRECT');
      }
      const target = new URL(location, url);
      // Per-hop re-validation (§26, Part 3 §51).
      await validateKnowledgeUrl(target.toString(), policy, this.limits);
      return this.fetchWithRedirects(target, policy, options, depth + 1);
    }

    if (response.status === 304) {
      return {
        url: url.toString(),
        finalUrl: url.toString(),
        statusCode: 304,
        contentType: response.headers.get('content-type'),
        bytes: new Uint8Array(0),
        byteLength: 0,
        truncated: false,
        etag: options.etag ?? null,
        lastModified: options.lastModified ?? null,
        artifactKey: null,
        notModified: true,
      };
    }

    if (!response.ok) {
      throw Object.assign(new Error(`Knowledge fetch failed: HTTP ${response.status} for ${url.host}`), {
        code: 'KNOWLEDGE_FETCH_FAILED',
      });
    }

    // Bounded body read with explicit truncation (§27).
    const declaredLength = Number(response.headers.get('content-length') ?? '0');
    let truncated = false;
    if (declaredLength > this.limits.maxPageBytes) truncated = true;
    const reader = response.body?.getReader();
    let bytes: Uint8Array;
    if (reader) {
      const chunks: Uint8Array[] = [];
      let total = 0;
      for (;;) {
        const { done, value } = await reader.read();
        if (done) break;
        if (total + value.length > this.limits.maxPageBytes) {
          const remaining = this.limits.maxPageBytes - total;
          if (remaining > 0) chunks.push(value.subarray(0, remaining));
          total = this.limits.maxPageBytes;
          truncated = true;
          await reader.cancel().catch(() => undefined);
          break;
        }
        chunks.push(value);
        total += value.length;
      }
      bytes = concatChunks(chunks, total);
    } else {
      const buffer = Buffer.from(await response.arrayBuffer());
      truncated = buffer.length > this.limits.maxPageBytes;
      bytes = truncated ? buffer.subarray(0, this.limits.maxPageBytes) : buffer;
    }

    if (options.budget) {
      options.budget.pages = (options.budget.pages ?? 0) + 1;
      options.budget.bytes = (options.budget.bytes ?? 0) + bytes.length;
    }

    // Raw artifact is sealed into object storage (§94): hash-addressed,
    // never executed, treated as untrusted data (§53).
    let artifactKey: string | null = null;
    if (this.objectStore && bytes.length > 0) {
      const hash = bytesHash(bytes);
      // Reuse the content-addressed key (put is idempotent by design).
      artifactKey = (await this.objectStore.put(bytes)).key;
      if (artifactKey !== hash) artifactKey = hash;
    }

    return {
      url: url.toString(),
      finalUrl: url.toString(),
      statusCode: response.status,
      contentType: response.headers.get('content-type'),
      bytes,
      byteLength: bytes.length,
      truncated,
      etag: response.headers.get('etag'),
      lastModified: response.headers.get('last-modified'),
      artifactKey,
      notModified: false,
    };
  }
}

function concatChunks(chunks: Uint8Array[], total: number): Uint8Array {
  const out = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    out.set(chunk, offset);
    offset += chunk.length;
  }
  return out;
}
