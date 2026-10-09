/**
 * Zero-trust internal authentication (spec Part 8 §5).
 *
 * Services authenticate each other with short-lived HMAC-signed internal
 * tokens. The signing secret never leaves the platform boundary; workers
 * present their token with each internal request and the receiving side
 * verifies signature, expiry and subject before trusting the call.
 * Tokens are scoped: subject + allowed engagement + capability list.
 */
import { createHmac, randomBytes, timingSafeEqual } from 'node:crypto';

export type InternalSubject = 'ORCHESTRATOR' | 'WORKER' | 'ANALYSIS' | 'BROWSER' | 'KNOWLEDGE';

export interface InternalTokenClaims {
  subject: InternalSubject;
  engagement_id: string | null;
  capabilities: string[];
  issued_at: number; // epoch ms
  expires_at: number; // epoch ms
  nonce: string;
}

const CLAIMS_ENCODING = 'utf8';

function sign(payload: string, secret: string): string {
  return createHmac('sha256', secret).update(payload, CLAIMS_ENCODING).digest('base64url');
}

export function createInternalToken(input: {
  secret: string;
  subject: InternalSubject;
  engagementId: string | null;
  capabilities: string[];
  ttlSeconds: number;
}): { token: string; claims: InternalTokenClaims } {
  const now = Date.now();
  const claims: InternalTokenClaims = {
    subject: input.subject,
    engagement_id: input.engagementId,
    capabilities: input.capabilities,
    issued_at: now,
    expires_at: now + input.ttlSeconds * 1000,
    nonce: randomBytes(12).toString('base64url'),
  };
  const payload = Buffer.from(JSON.stringify(claims), CLAIMS_ENCODING).toString('base64url');
  return { token: `internal.${payload}.${sign(payload, input.secret)}`, claims };
}

export class InternalAuthError extends Error {
  constructor(
    message: string,
    readonly code: 'INVALID_FORMAT' | 'BAD_SIGNATURE' | 'EXPIRED' | 'WRONG_SUBJECT' | 'MISSING_CAPABILITY',
  ) {
    super(message);
    this.name = 'InternalAuthError';
  }
}

/**
 * Verify an internal service token. Fail-closed on every dimension: format,
 * signature, expiry, subject match and required capability (§5).
 */
export function verifyInternalToken(
  token: string,
  input: { secret: string; expectedSubject: InternalSubject; requiredCapability?: string },
): InternalTokenClaims {
  const parts = token.split('.');
  if (
    parts.length !== 3 ||
    parts[0] !== 'internal' ||
    (parts[1] ?? '').length === 0 ||
    (parts[2] ?? '').length === 0
  ) {
    throw new InternalAuthError('Malformed internal token', 'INVALID_FORMAT');
  }
  const expectedSignature = sign(parts[1]!, input.secret);
  const provided = Buffer.from(parts[2]!, 'utf8');
  const expected = Buffer.from(expectedSignature, 'utf8');
  if (provided.length !== expected.length || !timingSafeEqual(provided, expected)) {
    throw new InternalAuthError('Internal token signature verification failed', 'BAD_SIGNATURE');
  }
  let claims: InternalTokenClaims;
  try {
    claims = JSON.parse(Buffer.from(parts[1]!, 'base64url').toString(CLAIMS_ENCODING)) as InternalTokenClaims;
  } catch {
    throw new InternalAuthError('Internal token claims are not valid JSON', 'INVALID_FORMAT');
  }
  if (typeof claims.expires_at !== 'number' || claims.expires_at < Date.now()) {
    throw new InternalAuthError('Internal token has expired', 'EXPIRED');
  }
  if (claims.subject !== input.expectedSubject) {
    throw new InternalAuthError(
      `Internal token subject ${String(claims.subject)} does not match expected ${input.expectedSubject}`,
      'WRONG_SUBJECT',
    );
  }
  if (input.requiredCapability && !claims.capabilities.includes(input.requiredCapability)) {
    throw new InternalAuthError(
      `Internal token lacks required capability '${input.requiredCapability}'`,
      'MISSING_CAPABILITY',
    );
  }
  return claims;
}
