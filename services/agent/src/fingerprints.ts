/**
 * Deterministic test fingerprints (spec Part 2 §29).
 *
 * hash(endpoint + method + identity + mutation_type + relevant_parameter +
 * normalized_mutation) over a canonical JSON encoding. Used to detect
 * equivalent or near-equivalent tests BEFORE scheduling them — never by an
 * LLM.
 */
import { createHash } from 'node:crypto';

export interface TestFingerprintInput {
  endpoint: string;
  method?: string;
  identity?: string | null;
  mutationType?: string;
  relevantParameter?: string;
  mutation?: Record<string, unknown>;
}

/** Canonical JSON: sorted keys, no insignificant whitespace. */
export function canonicalJson(value: unknown): string {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  const entries = Object.entries(value as Record<string, unknown>)
    .filter(([, v]) => v !== undefined)
    .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
  return `{${entries.map(([k, v]) => `${JSON.stringify(k)}:${canonicalJson(v)}`).join(',')}}`;
}

export function computeTestFingerprint(input: TestFingerprintInput): string {
  const canonical = canonicalJson({
    endpoint: normalizeText(input.endpoint),
    method: input.method ? input.method.toUpperCase() : 'GET',
    identity: input.identity ? normalizeText(input.identity) : null,
    mutation_type: input.mutationType ? normalizeText(input.mutationType) : null,
    relevant_parameter: input.relevantParameter ? normalizeText(input.relevantParameter) : null,
    mutation: input.mutation ?? null,
  });
  return createHash('sha256').update(canonical, 'utf8').digest('hex');
}

/**
 * Near-equivalence check (§28 "equivalent or near-equivalent tests"): two
 * fingerprints are near-equivalent when the underlying inputs match after
 * normalization but differ only in mutation payload values that serialize
 * identically modulo ordering.
 */
export function fingerprintsNearEquivalent(a: string, b: string): boolean {
  return a === b;
}

function normalizeText(value: string): string {
  // Fingerprint-level normalization: trim, lowercase, and strip trailing
  // slashes so `/API/Users/` and `/api/users` collide as near-equivalent.
  return value.trim().toLowerCase().replace(/\/+$/, '');
}
