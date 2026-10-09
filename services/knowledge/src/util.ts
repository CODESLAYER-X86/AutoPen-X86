/**
 * Part 5 shared utilities: token estimation, content hashing, canonical URL
 * normalization and cache key construction (spec Part 5 §25, §65, §67).
 *
 * Token estimation is a deterministic chars/4 heuristic with word-boundary
 * rounding — used ONLY for budget decisions, never for quota accounting
 * (quota accounting uses provider-reported usage, Part 2 §38).
 */
import { createHash } from 'node:crypto';

/** Deterministic token estimate (~4 chars/token heuristic, §62 budgeting). */
export function estimateTokens(text: string): number {
  if (!text) return 0;
  return Math.max(1, Math.ceil(text.length / 4));
}

/** sha256 hex of UTF-8 text — content identity for dedup/versioning (§25). */
export function contentHash(text: string): string {
  return createHash('sha256').update(text, 'utf8').digest('hex');
}

/** sha256 hex of raw bytes — raw artifact identity (§94). */
export function bytesHash(bytes: Uint8Array): string {
  return createHash('sha256').update(bytes).digest('hex');
}

/**
 * Canonical URL for document identity: lowercase host, drop default ports,
 * drop fragment, sort query keys, strip common tracking params. The ORIGINAL
 * url is always retained in provenance; this is only the dedup key (§67).
 */
export function canonicalizeUrl(rawUrl: string): string {
  const url = new URL(rawUrl);
  url.hash = '';
  url.hostname = url.hostname.toLowerCase();
  if ((url.protocol === 'https:' && url.port === '443') || (url.protocol === 'http:' && url.port === '80')) {
    url.port = '';
  }
  const dropParams = new Set(['utm_source', 'utm_medium', 'utm_campaign', 'utm_term', 'utm_content', 'ref', 'fbclid']);
  const keys = [...url.searchParams.keys()].filter((k) => !dropParams.has(k.toLowerCase())).sort();
  const sorted = new URLSearchParams();
  for (const key of keys) {
    for (const value of url.searchParams.getAll(key).sort()) sorted.append(key, value);
  }
  url.search = sorted.toString();
  // Normalize a trailing slash on root-less paths.
  if (url.pathname !== '/' && url.pathname.endsWith('/')) {
    url.pathname = url.pathname.replace(/\/+$/, '') || '/';
  }
  return url.toString();
}

/** Domain of a URL, lowercase; null when unparseable. */
export function domainOf(rawUrl: string): string | null {
  try {
    return new URL(rawUrl).hostname.toLowerCase();
  } catch {
    return null;
  }
}

/**
 * Query cache key (§65): covers query text + taxonomy + technology + index
 * version so cached packets are never served across index generations.
 */
export function buildCacheKey(input: {
  query: string;
  categories: string[];
  technologies: string[];
  indexVersion: string;
  maxResults: number;
  maxTokens: number;
}): string {
  const canonical = JSON.stringify({
    q: input.query.trim().toLowerCase(),
    c: [...input.categories].sort(),
    t: [...input.technologies].map((x) => x.toLowerCase()).sort(),
    v: input.indexVersion,
    r: input.maxResults,
    k: input.maxTokens,
  });
  return createHash('sha256').update(canonical, 'utf8').digest('hex').slice(0, 48);
}
