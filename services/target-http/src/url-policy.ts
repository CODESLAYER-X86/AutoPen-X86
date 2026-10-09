/**
 * URL validation / normalization + SSRF defence (spec Part 3 §49-§52).
 *
 * The ScopeChecker decides "is this host authorized for this engagement?".
 * This module decides "is the destination network-safe to fetch?" — the
 * platform itself must not become an SSRF proxy (§50):
 *   - schemes restricted per policy
 *   - DNS resolved, IP classified (loopback / private / link-local / …)
 *   - redirect destinations RE-validated per hop (§51) — hostname-only
 *     checks are never sufficient
 *   - malformed / oversized / userinfo-bearing URLs rejected
 *
 * The policy is deliberately configurable for authorized labs (the test
 * suite itself targets 127.0.0.1) — production defaults are restrictive.
 */
import { lookup } from 'node:dns/promises';
import { isIP } from 'node:net';
import { ValidationError } from '@aegis/shared';
import { ScopeChecker, type ScopeRules, type ScopeRejectionCode } from '@aegis/security';

export interface NetworkPolicy {
  allowedSchemes: string[];
  /** Allow 127.0.0.0/8 + ::1 (authorized lab targets only). */
  allowLoopback: boolean;
  /** Allow RFC1918 + link-local + unique-local IPv6 (authorized labs). */
  allowPrivateNetworks: boolean;
  maxRedirects: number;
}

export const DEFAULT_NETWORK_POLICY: NetworkPolicy = {
  allowedSchemes: ['http', 'https'],
  allowLoopback: false,
  allowPrivateNetworks: false,
  maxRedirects: 5,
};

/** Lab policy: loopback + private networks allowed (fixture apps). */
export const LAB_NETWORK_POLICY: NetworkPolicy = {
  ...DEFAULT_NETWORK_POLICY,
  allowLoopback: true,
  allowPrivateNetworks: true,
};

export type UrlRejectionCode =
  | ScopeRejectionCode
  | 'IP_LOOPBACK_FORBIDDEN'
  | 'IP_PRIVATE_FORBIDDEN'
  | 'IP_LINK_LOCAL_FORBIDDEN'
  | 'IP_UNSPECIFIED_FORBIDDEN'
  | 'DNS_RESOLUTION_FAILED'
  | 'URL_TOO_LONG';

export class UrlPolicyError extends ValidationError {
  constructor(
    message: string,
    code: UrlRejectionCode,
    public readonly details?: Record<string, unknown>,
  ) {
    super(message, code, details as unknown as Array<{ path: string; message: string }>);
    this.name = 'UrlPolicyError';
  }
}

export interface NormalizedUrl {
  scheme: string;
  host: string;
  port: number | null;
  path: string;
  query: string;
  href: string;
  /** Resolved addresses at validation time (DNS rebinding awareness, §52). */
  resolvedIps: string[];
}

export interface UrlPolicyCheckResult {
  normalized: NormalizedUrl;
  redirects: [];
}

const IP_V4_PRIVATE = [
  { cidr: '10.0.0.0', bits: 8 },
  { cidr: '172.16.0.0', bits: 12 },
  { cidr: '192.168.0.0', bits: 16 },
  { cidr: '169.254.0.0', bits: 16 },
  { cidr: '0.0.0.0', bits: 8 },
];
const IP_V4_LOOPBACK = { cidr: '127.0.0.0', bits: 8 };

function ipv4ToInt(ip: string): number {
  const parts = ip.split('.').map((p) => Number.parseInt(p, 10));
  if (parts.length !== 4 || parts.some((p) => Number.isNaN(p) || p < 0 || p > 255)) return -1;
  return ((parts[0]! << 24) | (parts[1]! << 16) | (parts[2]! << 8) | parts[3]!) >>> 0;
}

function inCidr(ip: string, cidr: { cidr: string; bits: number }): boolean {
  const ipInt = ipv4ToInt(ip);
  const netInt = ipv4ToInt(cidr.cidr);
  if (ipInt < 0 || netInt < 0) return false;
  const mask = cidr.bits === 0 ? 0 : (0xffffffff << (32 - cidr.bits)) >>> 0;
  return (ipInt & mask) === (netInt & mask);
}

export function classifyIp(ip: string): 'LOOPBACK' | 'PRIVATE' | 'LINK_LOCAL' | 'UNSPECIFIED' | 'PUBLIC' {
  if (isIP(ip) === 4) {
    if (inCidr(ip, IP_V4_LOOPBACK)) return 'LOOPBACK';
    if (inCidr(ip, { cidr: '169.254.0.0', bits: 16 })) return 'LINK_LOCAL';
    if (inCidr(ip, { cidr: '0.0.0.0', bits: 8 })) return 'UNSPECIFIED';
    for (const range of IP_V4_PRIVATE) if (inCidr(ip, range)) return 'PRIVATE';
    return 'PUBLIC';
  }
  if (isIP(ip) === 6) {
    const lower = ip.toLowerCase().replace(/^\[|\]$/g, '');
    if (lower === '::1' || lower === '::') return lower === '::' ? 'UNSPECIFIED' : 'LOOPBACK';
    if (lower.startsWith('fe80:')) return 'LINK_LOCAL';
    if (lower.startsWith('fc') || lower.startsWith('fd')) return 'PRIVATE';
    // IPv4-mapped ::ffff:10.0.0.1
    const mapped = lower.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/);
    if (mapped) return classifyIp(mapped[1]!);
    return 'PUBLIC';
  }
  return 'PUBLIC';
}

/**
 * Validate + normalize a URL against both the engagement scope rules and
 * the platform network policy. DNS resolution happens here so the IP is
 * checked BEFORE any connection (§50), and the resolved list is returned
 * for redirect re-validation (§51-§52).
 */
export async function validateAndNormalizeUrl(
  rawUrl: string,
  scope: ScopeRules,
  policy: NetworkPolicy,
): Promise<NormalizedUrl> {
  if (typeof rawUrl !== 'string' || rawUrl.length === 0) {
    throw new UrlPolicyError('URL is empty', 'INVALID_URL');
  }
  if (rawUrl.length > 2048) {
    throw new UrlPolicyError('URL exceeds 2048 characters', 'URL_TOO_LONG');
  }

  let url: URL;
  try {
    url = new URL(rawUrl);
  } catch {
    throw new UrlPolicyError(`URL could not be parsed: ${redactUrlForLog(rawUrl)}`, 'INVALID_URL');
  }

  const scopeChecker = new ScopeChecker(scope);

  if (url.username !== '' || url.password !== '') {
    throw new UrlPolicyError('URLs with embedded credentials are not permitted', 'USERINFO_NOT_ALLOWED');
  }

  const scheme = url.protocol.replace(/:$/, '').toLowerCase();
  if (!policy.allowedSchemes.includes(scheme)) {
    throw new UrlPolicyError(`Scheme '${scheme}' is not permitted by network policy`, 'SCHEME_NOT_ALLOWED');
  }

  // Hostname literal — check scope FIRST (engagement authorization).
  const scopeResult = scopeChecker.checkUrl(rawUrl);
  if (!scopeResult.allowed) {
    throw new UrlPolicyError(`Out of engagement scope: ${scopeResult.reason}`, scopeResult.code);
  }

  const host = url.hostname.toLowerCase().replace(/\.+$/, '');

  // IP-level policy (SSRF defence). Resolve DNS when the host is a name.
  let resolvedIps: string[];
  if (isIP(host.replace(/^\[|\]$/g, '')) !== 0) {
    resolvedIps = [host.replace(/^\[|\]$/g, '')];
  } else {
    try {
      const records = await lookup(host, { all: true, verbatim: true });
      resolvedIps = records.map((r) => r.address);
    } catch {
      throw new UrlPolicyError(`DNS resolution failed for '${host}'`, 'DNS_RESOLUTION_FAILED');
    }
  }

  for (const ip of resolvedIps) {
    const classification = classifyIp(ip);
    switch (classification) {
      case 'LOOPBACK':
        if (!policy.allowLoopback) {
          throw new UrlPolicyError(
            `Loopback address ${ip} is forbidden by network policy`,
            'IP_LOOPBACK_FORBIDDEN',
            { host, ip },
          );
        }
        break;
      case 'PRIVATE':
        if (!policy.allowPrivateNetworks) {
          throw new UrlPolicyError(
            `Private-network address ${ip} is forbidden by network policy`,
            'IP_PRIVATE_FORBIDDEN',
            { host, ip },
          );
        }
        break;
      case 'LINK_LOCAL':
        if (!policy.allowPrivateNetworks) {
          throw new UrlPolicyError(
            `Link-local address ${ip} is forbidden by network policy`,
            'IP_LINK_LOCAL_FORBIDDEN',
            { host, ip },
          );
        }
        break;
      case 'UNSPECIFIED':
        throw new UrlPolicyError(`Unspecified address ${ip} is forbidden`, 'IP_UNSPECIFIED_FORBIDDEN', { host, ip });
      case 'PUBLIC':
        break;
    }
  }

  return {
    scheme,
    host,
    port: url.port === '' ? null : Number.parseInt(url.port, 10),
    path: url.pathname,
    query: url.search,
    href: url.toString(),
    resolvedIps,
  };
}

/** Re-validate a redirect target (§51): scope + network, per hop. */
export async function validateRedirectTarget(
  location: string,
  currentUrl: string,
  scope: ScopeRules,
  policy: NetworkPolicy,
): Promise<NormalizedUrl> {
  let absolute: string;
  try {
    absolute = new URL(location, currentUrl).toString();
  } catch {
    throw new UrlPolicyError(`Redirect target could not be resolved: ${redactUrlForLog(location)}`, 'INVALID_URL');
  }
  return validateAndNormalizeUrl(absolute, scope, policy);
}

/** Keep host but strip query/fragment from URLs in error messages. */
export function redactUrlForLog(rawUrl: string): string {
  try {
    const url = new URL(rawUrl);
    return `${url.protocol}//${url.host}${url.pathname}`;
  } catch {
    return '(unparseable URL)';
  }
}
