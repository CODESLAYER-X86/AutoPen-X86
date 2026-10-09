/**
 * Identity mapping and authorization matrix (spec §20-§23, §98).
 *
 * Identity is explicit whenever known (§20): null identity means ANONYMOUS.
 * Outcomes are classified deterministically (§23) — HTTP 403 is never
 * equated with every possible denial. The matrix expands toward
 * Identity x Endpoint x Object x Action (§98).
 */
import type { AccessOutcome } from '@aegis/shared';
import type { AuthorizationMatrixRecord, EndpointRecord } from '@aegis/database';
import { createHash } from 'node:crypto';
import { pathParameterNames } from './parameter-extractor.js';
import { canonicalizePath, isIdentifierSegment } from './endpoint-extractor.js';

const LOGINISH_PATH = /login|signin|sign-in|auth|session\/?|sso|oauth/i;
const LOGOUTISH_PATH = /logout|signout|sign-out/i;
const REGISTERISH_PATH = /register|signup|sign-up/i;
const RESETTISH_PATH = /reset|forgot|recover|verify|verification|mfa|2fa/i;

/** Authentication map classification (§21). */
export type AuthMapEntryKind =
  | 'LOGIN_PAGE'
  | 'LOGIN_SUBMIT'
  | 'REGISTRATION'
  | 'LOGOUT'
  | 'PASSWORD_RESET'
  | 'VERIFICATION'
  | 'MFA'
  | 'SESSION_ESTABLISHMENT'
  | 'TOKEN_REFRESH'
  | 'SESSION_EXPIRATION'
  | 'UNKNOWN';

export function classifyAuthSurface(method: string, path: string, status: number | null): AuthMapEntryKind {
  if (LOGINISH_PATH.test(path)) {
    if (method === 'POST' || method === 'PUT') return 'LOGIN_SUBMIT';
    return 'LOGIN_PAGE';
  }
  if (LOGOUTISH_PATH.test(path)) return 'LOGOUT';
  if (REGISTERISH_PATH.test(path)) return 'REGISTRATION';
  if (RESETTISH_PATH.test(path)) {
    if (/mfa|2fa/i.test(path)) return 'MFA';
    if (/verify|verification/i.test(path)) return 'VERIFICATION';
    return 'PASSWORD_RESET';
  }
  if (status === 401) return 'SESSION_EXPIRATION';
  return 'UNKNOWN';
}

/** Deterministic access-outcome classification (§23). */
export function classifyOutcome(input: {
  status: number | null;
  redirectTo: string | null;
  identityId: string | null;
}): AccessOutcome {
  const status = input.status;
  if (status === null) return 'UNKNOWN';
  if (status >= 500) return 'ERROR';
  if (status === 401 || status === 403) return 'DENIED';
  if (status >= 300 && status < 400) {
    // Redirect to a login-ish target means "not authenticated for this route".
    if (input.redirectTo && LOGINISH_PATH.test(input.redirectTo)) return 'REDIRECTED';
    return 'REDIRECTED';
  }
  if (status >= 200 && status < 300) return 'ALLOWED';
  return 'UNKNOWN';
}

/**
 * Object reference extraction (§19, §98): for templated endpoints the
 * concrete identifier value at the {param} position becomes the object ref.
 */
export function objectRefForRequest(
  endpoint: EndpointRecord,
  observedUrl: string,
): string | null {
  const urlPath = extractPath(observedUrl);
  if (urlPath === null) return null;
  const canonicalSegments = endpoint.canonical_path.split('/').filter((segment) => segment.length > 0);
  const observedSegments = urlPath.split('/').filter((segment) => segment.length > 0);
  if (canonicalSegments.length !== observedSegments.length) return null;

  const names = pathParameterNames(endpoint.canonical_path);
  let refs: string[] = [];
  canonicalSegments.forEach((segment, index) => {
    if (segment !== '{param}') return;
    const value = observedSegments[index] ?? '';
    if (!isIdentifierSegment(value)) return;
    const name = names.find((entry) => entry.segmentIndex === index)?.name ?? `param_${index}`;
    refs.push(`${stripIdSuffix(name)}:${value}`);
  });
  if (refs.length === 0) {
    // Query-based object references (§19): ?order_id=381
    refs = [];
  }
  return refs.length > 0 ? refs.join('|') : null;
}

function stripIdSuffix(name: string): string {
  return name.replace(/_id$/, '');
}

function extractPath(url: string): string | null {
  try {
    return new URL(url).pathname || '/';
  } catch {
    return null;
  }
}

/** Object refs from query/JSON parameters carrying identifier semantics (§19). */
export function objectRefsFromParameters(
  endpoint: EndpointRecord,
  parameters: Array<{ name: string; location: string; exampleValues: string[]; identifierish: boolean }>,
): string[] {
  const refs: string[] = [];
  for (const parameter of parameters.slice(0, 32)) {
    if (!parameter.identifierish) continue;
    if (parameter.location === 'HEADER' || parameter.location === 'COOKIE') continue;
    const value = parameter.exampleValues[0];
    if (!value || value === '«redacted»') continue;
    refs.push(`${stripIdSuffix(parameter.name)}:${value}`);
  }
  return refs.slice(0, 8);
}

export function matrixFingerprint(
  endpointFingerprint: string,
  identityId: string | null,
  objectRef: string | null,
  action: string | null,
): string {
  // Outcome deliberately excluded: the cell tracks the LATEST outcome over
  // time (§23 observed access matrix).
  const identity = identityId ?? 'ANONYMOUS';
  const object = objectRef ?? '';
  const actionKey = action ?? '';
  return createHash('sha256')
    .update(`${endpointFingerprint}|${identity}|${object}|${actionKey}`)
    .digest('hex')
    .slice(0, 40);
}

/**
 * Authentication-boundary detection (§22): when a login submit succeeds and
 * subsequent requests by the same identity are authenticated, the boundary
 * is anonymous -> authenticated. Returned as workflow transition facts.
 */
export function authBoundaryFor(
  kind: AuthMapEntryKind,
  method: string,
  status: number | null,
): { before: 'ANONYMOUS' | 'AUTHENTICATED'; after: 'ANONYMOUS' | 'AUTHENTICATED' } | null {
  if (kind === 'LOGIN_SUBMIT' && status !== null && status >= 200 && status < 300) {
    return { before: 'ANONYMOUS', after: 'AUTHENTICATED' };
  }
  if (kind === 'LOGOUT' && status !== null && status >= 200 && status < 300) {
    return { before: 'AUTHENTICATED', after: 'ANONYMOUS' };
  }
  return null;
}

/** Authentication observed on an endpoint: non-anonymous identity reached it. */
export function authenticationObserved(matrix: AuthorizationMatrixRecord[]): boolean {
  return matrix.some((entry) => entry.identity_id !== null && entry.outcome === 'ALLOWED');
}

/** Canonicalize a path for auth-surface matching. */
export function normalizedPathForAuth(path: string): string {
  const { canonicalPath } = canonicalizePath(path);
  return canonicalPath;
}
