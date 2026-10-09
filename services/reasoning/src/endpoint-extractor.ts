/**
 * Endpoint extraction and canonicalization (spec §7-§13, §86-§87).
 *
 * Deterministic fingerprinting prevents duplicate endpoint records (§8).
 * Canonical paths are CANDIDATES (§7): templating confidence rises only when
 * multiple distinct values are observed at the same segment position.
 * Endpoint families cluster paths (§86); API versions are separate
 * surfaces initially (§87).
 */
import { createHash } from 'node:crypto';
import type { EndpointRecord } from '@aegis/database';
import type { ConfidenceCategory, DiscoverySource, EndpointStatus } from '@aegis/shared';

const IDENTIFIER_SEGMENT_PATTERNS: RegExp[] = [
  /^\d+$/, // numeric ids: /api/user/12
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i, // uuids
  /^[0-9a-f]{12,}$/i, // long hex (mongo-style)
  /^[A-Za-z0-9_-]{10,}$/, // opaque tokens / base64url-ish
];

export interface ParsedUrl {
  scheme: string;
  host: string;
  port: number;
  path: string;
}

export function parseUrlParts(rawUrl: string): ParsedUrl | null {
  try {
    const url = new URL(rawUrl);
    return {
      scheme: url.protocol.replace(':', ''),
      host: url.hostname.toLowerCase(),
      port: url.port ? Number(url.port) : defaultPort(url.protocol),
      path: url.pathname || '/',
    };
  } catch {
    return null;
  }
}

function defaultPort(protocol: string): number {
  if (protocol === 'https:') return 443;
  if (protocol === 'http:') return 80;
  return 0;
}

/** Does a single path segment look like an identifier value? */
export function isIdentifierSegment(segment: string): boolean {
  if (segment.length === 0) return false;
  // Short static words are never templated — avoids over-generalization.
  if (segment.length <= 3 && !/^\d+$/.test(segment)) return false;
  return IDENTIFIER_SEGMENT_PATTERNS.some((pattern) => pattern.test(segment));
}

/**
 * Canonicalization candidate for a path (§7). Templating is conservative:
 * only segments that look like identifier VALUES become `{param}`.
 */
export function canonicalizePath(path: string): { canonicalPath: string; templatedPositions: number[] } {
  const segments = decodeSegments(path);
  const templatedPositions: number[] = [];
  const canonical = segments.map((segment, index) => {
    if (isIdentifierSegment(segment)) {
      templatedPositions.push(index);
      return '{param}';
    }
    return segment;
  });
  return { canonicalPath: `/${canonical.join('/')}`, templatedPositions };
}

/**
 * Path "shape" ignoring identifier positions — used to merge concrete paths
 * like /api/user/1 and /api/user/2 into /api/user/{param}.
 */
export function pathShape(path: string): string {
  const { canonicalPath } = canonicalizePath(path);
  return canonicalPath;
}

export function endpointFingerprint(parts: ParsedUrl, canonicalPath: string): string {
  return createHash('sha256')
    .update(`${parts.scheme}|${parts.host}|${parts.port}|${canonicalPath}`)
    .digest('hex')
    .slice(0, 40);
}

/** Resource family clustering (§86): static prefix + first templated position. */
export function resourceFamilyOf(canonicalPath: string): string {
  const segments = decodeSegments(canonicalPath);
  const statics: string[] = [];
  for (const segment of segments) {
    if (segment === '{param}') break;
    statics.push(segment);
  }
  if (statics.length === 0) return '/';
  return `/${statics.join('/')}`;
}

/** API version detection (§87): /api/v1/... -> v1 (separate surface initially). */
export function apiVersionOf(canonicalPath: string): string | null {
  const segments = decodeSegments(canonicalPath);
  for (const segment of segments.slice(0, 3)) {
    const match = segment.match(/^v\d+$/i);
    if (match) return match[0]!.toLowerCase();
    if (/^internal$/i.test(segment)) return 'internal';
  }
  return null;
}

function decodeSegments(path: string): string[] {
  const clean = path.startsWith('/') ? path.slice(1) : path;
  const parts = clean.split('/').filter((segment) => segment.length > 0);
  return parts.map((segment) => {
    try {
      return decodeURIComponent(segment);
    } catch {
      return segment;
    }
  });
}

export interface ObserveEndpointInput {
  engagementId: string;
  url: string;
  method: string;
  contentType: string | null;
  identityId: string | null;
  discoverySource: DiscoverySource;
  evidenceId: string | null;
  at: string;
}

export interface ObservedEndpoint {
  fingerprint: string;
  scheme: string;
  host: string;
  port: number;
  path: string;
  canonicalPath: string;
  canonicalConfidence: number;
  confidenceCategory: ConfidenceCategory;
  /** Record-level confidence (0-1) distinct from canonical-path confidence. */
  confidence: number;
  resourceFamily: string;
  apiVersion: string | null;
  status: EndpointStatus;
}

/**
 * Derive the endpoint representation for one observed URL. The canonical
 * confidence starts conservative (single observation, §13) and is raised by
 * the repository layer when multiple distinct values converge (§7).
 */
export function deriveEndpoint(input: ObserveEndpointInput): ObservedEndpoint | null {
  const parts = parseUrlParts(input.url);
  if (!parts) return null;
  const { canonicalPath, templatedPositions } = canonicalizePath(parts.path);
  const templated = templatedPositions.length > 0;
  return {
    fingerprint: endpointFingerprint(parts, canonicalPath),
    scheme: parts.scheme,
    host: parts.host,
    port: parts.port,
    path: parts.path,
    canonicalPath,
    canonicalConfidence: templated ? 0.55 : 1,
    confidenceCategory: 'OBSERVED',
    // Directly observed endpoint: existence is a fact (§13 OBSERVED), so
    // record confidence reflects only single-source observation.
    confidence: 1,
    resourceFamily: resourceFamilyOf(canonicalPath),
    apiVersion: apiVersionOf(canonicalPath),
    status: 'OBSERVED',
  };
}

/**
 * Re-canonicalization upgrade (§7): when a concrete-path endpoint sees a
 * second distinct value at an identifier-looking segment, upgrade its
 * canonical form. Returns null when no upgrade is warranted.
 */
export function canonicalUpgrade(existing: EndpointRecord, newUrl: string): {
  canonicalPath: string;
  canonicalConfidence: number;
} | null {
  const parts = parseUrlParts(newUrl);
  if (!parts) return null;
  if (parts.host !== existing.host || parts.port !== existing.port || parts.scheme !== existing.scheme) return null;

  const existingSegments = decodeSegments(existing.path);
  const newSegments = decodeSegments(parts.path);
  if (existingSegments.length !== newSegments.length) return null;

  let differing = 0;
  let differingIdentifierish = 0;
  for (let i = 0; i < existingSegments.length; i += 1) {
    const a = existingSegments[i]!;
    const b = newSegments[i]!;
    if (a === b) continue;
    differing += 1;
    if (isIdentifierSegment(a) && isIdentifierSegment(b)) differingIdentifierish += 1;
  }
  if (differing === 0 || differing !== differingIdentifierish) return null;

  // ≥2 distinct identifier values at the same position: strong evidence for
  // the templated form (§7 confidence rises with distinct observations).
  const distinctObserved = existing.observed_urls.length + 1;
  const upgraded = canonicalizePath(parts.path);
  return {
    canonicalPath: upgraded.canonicalPath,
    canonicalConfidence: Math.min(0.95, 0.6 + 0.1 * distinctObserved),
  };
}
