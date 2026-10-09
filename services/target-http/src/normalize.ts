/**
 * HTTP normalization + sensitive-data redaction (spec Part 3 §18, §66).
 *
 * Normalization is used for COMPARISON ONLY (fingerprints, duplicate
 * detection, replay matching). The raw representation is always preserved
 * — normalization never destroys semantically meaningful differences.
 *
 * Redaction removes credential material (Authorization, Cookie, Set-Cookie,
 * API keys, password fields, tokens, session identifiers) before anything
 * enters model context or logs. Raw evidence keeps the full content in the
 * (authorized, hash-verified) evidence store.
 */
import { createHash } from 'node:crypto';

export interface PlainHeader {
  name: string;
  value: string;
}

export interface NormalizedRequestParts {
  /** Lowercased header names, sorted, semicolon-collapsed values trimmed. */
  headers: PlainHeader[];
  /** Query params sorted by name (then value), preserving duplicates. */
  query: PlainHeader[];
  /** Canonical JSON: recursively key-sorted, whitespace-stripped. */
  bodyCanonical: string | null;
  /** Normalized URL: default-port stripped, trailing-host dot stripped,
   *  path kept, query re-serialized from sorted params. */
  url: string;
  /** Method uppercase. */
  method: string;
}

const SENSITIVE_HEADER_PATTERNS = [
  /^authorization$/i,
  /^cookie$/i,
  /^set-cookie$/i,
  /^proxy-authorization$/i,
  /^x-api-key$/i,
  /^x-auth-token$/i,
  /^x-session-token$/i,
  /^x-csrf-token$/i,
  /^api-key$/i,
];

const SENSITIVE_BODY_FIELD_PATTERNS = [
  /^password$/i,
  /^passwd$/i,
  /^secret$/i,
  /^token$/i,
  /^access_token$/i,
  /^refresh_token$/i,
  /^api_?key$/i,
  /^session_?id$/i,
  /^private_?key$/i,
];

export const REDACTED = '«redacted»';

export function isSensitiveHeader(name: string): boolean {
  return SENSITIVE_HEADER_PATTERNS.some((p) => p.test(name));
}

export function isSensitiveFieldName(name: string): boolean {
  return SENSITIVE_BODY_FIELD_PATTERNS.some((p) => p.test(name));
}

/** Sort + normalize headers for comparison (§18). */
export function normalizeHeaders(headers: PlainHeader[]): PlainHeader[] {
  return headers
    .map((h) => ({ name: h.name.trim().toLowerCase(), value: h.value.trim() }))
    .sort((a, b) => (a.name === b.name ? a.value.localeCompare(b.value) : a.name.localeCompare(b.name)));
}

/** Parse + sort query parameters, preserving duplicates and empty values. */
export function parseQuery(url: string): PlainHeader[] {
  const queryIndex = url.indexOf('?');
  if (queryIndex === -1) return [];
  const raw = url.slice(queryIndex + 1).split('#')[0] ?? '';
  if (raw === '') return [];
  const params: PlainHeader[] = [];
  for (const pair of raw.split('&')) {
    if (pair === '') continue;
    const eq = pair.indexOf('=');
    const name = eq === -1 ? pair : pair.slice(0, eq);
    const value = eq === -1 ? '' : pair.slice(eq + 1);
    params.push({ name, value });
  }
  return params.sort((a, b) => (a.name === b.name ? a.value.localeCompare(b.value) : a.name.localeCompare(b.name)));
}

/** Canonical JSON: recursive key sort, no insignificant whitespace (§18). */
export function canonicalizeJson(value: unknown): string {
  const walk = (v: unknown): unknown => {
    if (v === null || typeof v !== 'object') return v;
    if (Array.isArray(v)) return v.map(walk);
    const entries = Object.entries(v as Record<string, unknown>)
      .filter(([, val]) => val !== undefined)
      .sort(([a], [b]) => a.localeCompare(b));
    const out: Record<string, unknown> = {};
    for (const [k, val] of entries) out[k] = walk(val);
    return out;
  };
  return JSON.stringify(walk(value));
}

/** Normalize a URL for comparison: default port stripped, sorted query. */
export function normalizeUrlForComparison(rawUrl: string): string {
  const url = new URL(rawUrl);
  if (
    (url.protocol === 'http:' && url.port === '80') ||
    (url.protocol === 'https:' && url.port === '443')
  ) {
    url.port = '';
  }
  url.hostname = url.hostname.toLowerCase().replace(/\.+$/, '');
  const sortedParams = parseQuery(url.toString());
  url.search = '';
  for (const p of sortedParams) {
    url.searchParams.append(p.name, p.value);
  }
  return url.toString();
}

/** All normalized parts for a request record. */
export function buildNormalizedParts(input: {
  method: string;
  url: string;
  headers: PlainHeader[];
  bodyCanonical: string | null;
}): NormalizedRequestParts {
  return {
    method: input.method.toUpperCase(),
    url: normalizeUrlForComparison(input.url),
    headers: normalizeHeaders(input.headers),
    query: parseQuery(input.url),
    bodyCanonical: input.bodyCanonical,
  };
}

/** Deterministic fingerprint for duplicate detection (replay idempotency). */
export function fingerprintNormalized(parts: NormalizedRequestParts): string {
  const material = JSON.stringify({
    m: parts.method,
    u: parts.url,
    h: parts.headers.map((h) => [h.name, h.value]),
    b: parts.bodyCanonical,
  });
  return createHash('sha256').update(material).digest('hex');
}

// ---------------------------------------------------------------------------
// Redaction (§66)
// ---------------------------------------------------------------------------

export function redactHeaders(headers: PlainHeader[]): PlainHeader[] {
  return headers.map((h) =>
    isSensitiveHeader(h.name) ? { name: h.name, value: REDACTED } : { name: h.name, value: h.value },
  );
}

/** Redact sensitive string fields inside parsed JSON bodies (recursive). */
export function redactParsedBody(value: unknown): unknown {
  if (value === null || typeof value !== 'object') return value;
  if (Array.isArray(value)) return value.map(redactParsedBody);
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
    out[k] = isSensitiveFieldName(k) && typeof v === 'string' && v.length > 0 ? REDACTED : redactParsedBody(v);
  }
  return out;
}

/** Redact form-urlencoded field values by name. */
export function redactFormFields(fields: PlainHeader[]): PlainHeader[] {
  return fields.map((f) =>
    isSensitiveFieldName(f.name) ? { name: f.name, value: REDACTED } : { name: f.name, value: f.value },
  );
}

/** Header lookup helper (case-insensitive, first match wins). */
export function findHeader(headers: PlainHeader[], name: string): PlainHeader | null {
  const lower = name.toLowerCase();
  for (const h of headers) {
    if (h.name.toLowerCase() === lower) return h;
  }
  return null;
}

/** Classify response content (§17). */
export function classifyContent(contentType: string | null): 'JSON' | 'HTML' | 'XML' | 'TEXT' | 'BINARY' | 'IMAGE' | 'FILE' | 'UNKNOWN' {
  const ct = (contentType ?? '').toLowerCase();
  if (ct.includes('application/json') || ct.includes('+json')) return 'JSON';
  if (ct.includes('text/html')) return 'HTML';
  if (ct.includes('text/xml') || ct.includes('application/xml') || ct.includes('+xml')) return 'XML';
  if (ct.startsWith('text/')) return 'TEXT';
  if (ct.startsWith('image/')) return 'IMAGE';
  if (
    ct.includes('application/octet-stream') ||
    ct.includes('application/pdf') ||
    ct.includes('application/zip') ||
    ct.includes('application/gzip')
  ) {
    return 'FILE';
  }
  if (ct === '') return 'UNKNOWN';
  return 'BINARY';
}
