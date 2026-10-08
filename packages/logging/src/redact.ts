/**
 * Secret redaction for structured logging (spec §23).
 *
 * Defence in depth:
 *  1. Keys with sensitive names are replaced by `[REDACTED]` at any depth.
 *  2. String VALUES are pattern-scrubbed (Bearer headers, JWTs, common API
 *     key formats) so that secrets smuggled into free-form fields (e.g. a
 *     URL, an error message, a target response) are still masked.
 *  3. Depth and breadth are capped to keep redaction cheap and cycle-safe.
 *
 * This is a best-effort structural control, not a guarantee that arbitrary
 * target-controlled content is fully sanitised — target responses should be
 * stored as evidence rather than logged verbatim.
 */

export const REDACTED = '[REDACTED]';
const MAX_DEPTH = 8;
const MAX_ARRAY_ITEMS = 100;

const SENSITIVE_KEY_PATTERN =
  /^(?:password|passwd|passphrase|secret|secrets|token|tokens|api[-_]?key|apikey|authorization|auth|cookie|cookies|set[-_]?cookie|session|sessions?_?id|credential|credentials|private[-_]?key|access[-_]?token|refresh[-_]?token|id[-_]?token|jwt|bearer|password[-_]?hash|master[-_]?key|client[-_]?secret|signing[-_]?key)$/i;

// Value-level patterns (applied to every logged string).
const AUTH_HEADER_PATTERN = /\b(?:Bearer|Basic)\s+[A-Za-z0-9\-._~+/]+=*/gi;
const JWT_PATTERN = /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g;
const COMMON_KEY_PATTERN =
  /\b(?:sk-[A-Za-z0-9]{20,}|AIza[0-9A-Za-z\-_]{30,}|ghp_[A-Za-z0-9]{30,}|gho_[A-Za-z0-9]{30,}|xox[baprs]-[A-Za-z0-9-]{10,})\b/g;

const seen = new WeakSet<object>();

export function scrubString(value: string): string {
  if (value.length > 65_536) {
    return `${value.slice(0, 1024)}…[TRUNCATED]`;
  }
  return value
    .replace(AUTH_HEADER_PATTERN, (m) => m.slice(0, m.indexOf(' ') + 1) + REDACTED)
    .replace(JWT_PATTERN, REDACTED)
    .replace(COMMON_KEY_PATTERN, REDACTED);
}

export function redactValue(value: unknown, depth = 0): unknown {
  if (value === null || value === undefined) return value;
  const type = typeof value;
  if (type === 'string') return scrubString(value as string);
  if (type === 'number' || type === 'boolean' || type === 'bigint') return value;
  if (type === 'function' || type === 'symbol') return '[NON_SERIALIZABLE]';

  if (depth >= MAX_DEPTH) return '[TRUNCATED]';

  if (Array.isArray(value)) {
    const items = value.slice(0, MAX_ARRAY_ITEMS).map((item) => redactValue(item, depth + 1));
    if (value.length > MAX_ARRAY_ITEMS) items.push(`[+${value.length - MAX_ARRAY_ITEMS} items]`);
    return items;
  }

  if (type === 'object') {
    const obj = value as Record<string, unknown>;
    if (seen.has(obj)) return '[CIRCULAR]';
    seen.add(obj);
    try {
      const out: Record<string, unknown> = {};
      for (const [key, val] of Object.entries(obj)) {
        out[key] = SENSITIVE_KEY_PATTERN.test(key) ? REDACTED : redactValue(val, depth + 1);
      }
      return out;
    } finally {
      seen.delete(obj);
    }
  }

  return value;
}

/** Redact a metadata object into a JSON-safe record. */
export function redactRecord(meta: Record<string, unknown>): Record<string, unknown> {
  return redactValue(meta) as Record<string, unknown>;
}
