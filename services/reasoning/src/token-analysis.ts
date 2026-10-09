/**
 * Token analysis (spec §58-§60).
 *
 * Deterministic JWT parsing (§59): algorithm, issuer, audience, subject,
 * expiration, claims. Decoding is NEVER confused with verification (§59):
 * `signature_verified` is always false unless a real verification path
 * exists — which is out of Part 4 scope. Token comparison across identities
 * (§60) produces stable/identity-specific claim facts.
 */
import type { ValueCharacteristic } from '@aegis/shared';

export interface JwtFacts {
  /** Decoded (NOT verified — §59). */
  algorithm: string | null;
  issuer: string | null;
  audience: string | null;
  subject: string | null;
  expiration: number | null;
  issued_at: number | null;
  claims: Array<{ name: string; value_summary: string }>;
  header_facts: Record<string, string>;
  signature_present: boolean;
  /** Always false: we never claim verification without a verifier. */
  signature_verified: false;
  expired: boolean | null;
  warnings: string[];
}

const JWT_RE = /^ey[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*$/;

export function looksLikeJwt(value: string): boolean {
  return JWT_RE.test(value);
}

function decodeBase64Url(segment: string): unknown | undefined {
  try {
    const normalized = segment.replace(/-/g, '+').replace(/_/g, '/');
    const padded = normalized + '='.repeat((4 - (normalized.length % 4)) % 4);
    const json = Buffer.from(padded, 'base64').toString('utf8');
    return JSON.parse(json) as unknown;
  } catch {
    return undefined;
  }
}

function boundedSummary(value: unknown): string {
  if (value === null) return 'null';
  if (typeof value === 'object') return JSON.stringify(value).slice(0, 128);
  return String(value).slice(0, 128);
}

/** Deterministic JWT decode (§59). Token strings are never persisted. */
export function analyzeJwt(token: string): JwtFacts | null {
  if (!looksLikeJwt(token)) return null;
  const parts = token.split('.');
  const header = decodeBase64Url(parts[0]!);
  const payload = decodeBase64Url(parts[1]!);
  if (header === undefined || payload === undefined || typeof payload !== 'object' || payload === null) {
    return null;
  }
  const headerFacts: Record<string, string> = {};
  if (typeof header === 'object' && header !== null) {
    for (const [key, value] of Object.entries(header as Record<string, unknown>)) {
      headerFacts[key] = boundedSummary(value);
    }
  }
  const claims = payload as Record<string, unknown>;
  const now = Math.floor(Date.now() / 1000);
  const expiration = typeof claims.exp === 'number' ? claims.exp : null;
  const warnings: string[] = [];
  if (headerFacts.alg === 'none') warnings.push('alg=none: unsigned token');
  if (expiration !== null && expiration < now) warnings.push('token expired');
  if (typeof claims.iss !== 'string' && typeof claims.iss !== 'undefined') warnings.push('unusual issuer claim type');

  return {
    algorithm: headerFacts.alg ?? null,
    issuer: typeof claims.iss === 'string' ? claims.iss : null,
    audience: boundedSummary(claims.aud ?? null) === 'null' ? null : boundedSummary(claims.aud),
    subject: typeof claims.sub === 'string' ? claims.sub : null,
    expiration,
    issued_at: typeof claims.iat === 'number' ? claims.iat : null,
    claims: Object.entries(claims)
      .slice(0, 32)
      .map(([name, value]) => ({ name, value_summary: boundedSummary(value) })),
    header_facts: headerFacts,
    signature_present: (parts[2] ?? '').length > 0,
    signature_verified: false,
    expired: expiration === null ? null : expiration < now,
    warnings,
  };
}

export interface TokenObservation {
  identityId: string | null;
  kind: 'RESPONSE_BODY' | 'COOKIE_NAME_HINT' | 'STORAGE_HINT' | 'HEADER_HINT';
  facts: JwtFacts;
  sourceSummary: string;
}

export interface TokenComparisonResult {
  /** Claims identical across identities — stable claims (§60). */
  stable_claims: string[];
  /** Claims that differ across identities (§60 identity-specific). */
  identity_claims: string[];
  role_claims: string[];
  subject_claims: string[];
  expiration_pattern: 'SAME' | 'DIFFERENT' | 'UNKNOWN';
}

/**
 * Compare decoded tokens across identities (§60): stable claims vs
 * identity-specific claims, role/subject claims, expiration patterns.
 */
export function compareTokens(observations: TokenObservation[]): TokenComparisonResult | null {
  const byIdentity = new Map<string, JwtFacts>();
  for (const observation of observations) {
    if (observation.identityId === null) continue;
    if (!byIdentity.has(observation.identityId)) byIdentity.set(observation.identityId, observation.facts);
  }
  if (byIdentity.size < 2) return null;
  const factsList = [...byIdentity.values()];

  const claimValues = new Map<string, Set<string>>();
  for (const facts of factsList) {
    for (const claim of facts.claims) {
      if (!claimValues.has(claim.name)) claimValues.set(claim.name, new Set());
      claimValues.get(claim.name)!.add(claim.value_summary);
    }
  }
  const stableClaims: string[] = [];
  const identityClaims: string[] = [];
  for (const [name, values] of claimValues) {
    if (values.size === 1) stableClaims.push(name);
    else identityClaims.push(name);
  }
  const expirations = factsList.map((facts) => facts.expiration).filter((value): value is number => value !== null);
  return {
    stable_claims: stableClaims.slice(0, 32),
    identity_claims: identityClaims.slice(0, 32),
    role_claims: [...claimValues.keys()].filter((name) => /role|priv|admin|scope/i.test(name)).slice(0, 16),
    subject_claims: [...claimValues.keys()].filter((name) => /^sub$|subject|user/i.test(name)).slice(0, 16),
    expiration_pattern:
      expirations.length === factsList.length
        ? expirations.every((value) => value === expirations[0])
          ? 'SAME'
          : 'DIFFERENT'
        : 'UNKNOWN',
  };
}

/** Scan a bounded text for JWT-like tokens (response bodies, previews). */
export function scanForJwtTokens(
  text: string | null,
): Array<{ token: string; facts: JwtFacts }> {
  if (!text) return [];
  const results: Array<{ token: string; facts: JwtFacts }> = [];
  const re = /\bey[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{0,64}\b/g;
  let match: RegExpExecArray | null;
  while ((match = re.exec(text.slice(0, 65_536))) !== null && results.length < 8) {
    const token = match[0];
    const facts = analyzeJwt(token);
    if (facts) results.push({ token, facts });
  }
  return results;
}

/** Characteristic hint for parameter records (JWT_LIKE etc.). */
export function tokenCharacteristic(facts: JwtFacts): ValueCharacteristic {
  return facts.signature_present ? 'JWT_LIKE' : 'OPAQUE_TOKEN';
}
