/**
 * Deterministic scope enforcement (spec §10, §40).
 *
 * The ScopeChecker is the single source of truth for "is this URL/target
 * inside the authorized engagement scope?". It is pure, side-effect-free
 * code so it can be exhaustively unit-tested. It NEVER consults an LLM.
 *
 * Evaluation order (deny-wins, deterministic):
 *   1. URL must parse (WHATWG URL, IDN-normalised, lowercased host).
 *   2. URLs containing embedded credentials (userinfo) are rejected.
 *   3. Scheme must be explicitly allowed.
 *   4. Excluded hosts (exact or domain-suffix) deny the request.
 *   5. Host must match allowed_hosts exactly OR be a subdomain of an
 *      allowed_domains entry (or equal to it).
 *   6. Port must be explicitly allowed; if allowed_ports is empty, only the
 *      scheme's default port (80/443/80/443) is permitted.
 *   7. Path must not fall under an excluded path prefix.
 *
 * IPv6 hosts keep their brackets in `hostname`; they must be listed in
 * allowed_hosts in bracketed form (e.g. `[::1]`).
 */
import type { TargetType } from '@aegis/shared';

export interface ScopeRules {
  allowed_hosts: string[];
  allowed_domains: string[];
  allowed_ports: number[];
  allowed_schemes: string[];
  excluded_hosts: string[];
  excluded_paths: string[];
  rate_limit?: number | null;
  concurrency_limit?: number | null;
  destructive_actions_allowed: boolean;
}

export type ScopeRejectionCode =
  | 'INVALID_URL'
  | 'USERINFO_NOT_ALLOWED'
  | 'SCHEME_NOT_ALLOWED'
  | 'HOST_EXCLUDED'
  | 'HOST_NOT_ALLOWED'
  | 'PORT_NOT_ALLOWED'
  | 'PATH_EXCLUDED'
  | 'SCOPE_NOT_CONFIGURED'
  | 'TARGET_TYPE_INVALID';

export type ScopeCheckResult =
  | {
      allowed: true;
      normalized: { scheme: string; host: string; port: number | null; path: string };
    }
  | { allowed: false; code: ScopeRejectionCode; reason: string };

const DEFAULT_PORTS: Record<string, number> = {
  http: 80,
  https: 443,
  ws: 80,
  wss: 443,
};

function normalizeHost(host: string): string {
  return host.toLowerCase().replace(/\.+$/, '');
}

function hostMatchesPattern(host: string, pattern: string): boolean {
  const p = normalizeHost(pattern);
  return host === p || host.endsWith(`.${p}`);
}

export class ScopeChecker {
  constructor(private readonly rules: ScopeRules) {}

  get ruleSet(): ScopeRules {
    return this.rules;
  }

  checkUrl(rawUrl: string): ScopeCheckResult {
    if (typeof rawUrl !== 'string' || rawUrl.length === 0 || rawUrl.length > 2048) {
      return { allowed: false, code: 'INVALID_URL', reason: 'URL is empty or too long' };
    }

    let url: URL;
    try {
      url = new URL(rawUrl);
    } catch {
      return { allowed: false, code: 'INVALID_URL', reason: 'URL could not be parsed' };
    }

    if (url.username !== '' || url.password !== '') {
      return {
        allowed: false,
        code: 'USERINFO_NOT_ALLOWED',
        reason: 'URLs with embedded credentials are not permitted',
      };
    }

    const scheme = url.protocol.replace(/:$/, '').toLowerCase();
    if (!this.rules.allowed_schemes.includes(scheme)) {
      return {
        allowed: false,
        code: 'SCHEME_NOT_ALLOWED',
        reason: `Scheme '${scheme}' is not in the allowed schemes`,
      };
    }

    const host = normalizeHost(url.hostname);
    if (host === '') {
      return { allowed: false, code: 'INVALID_URL', reason: 'URL has no host' };
    }

    // Exclusions take priority over allowances (deny wins).
    for (const pattern of this.rules.excluded_hosts) {
      if (hostMatchesPattern(host, pattern)) {
        return {
          allowed: false,
          code: 'HOST_EXCLUDED',
          reason: `Host '${host}' matches excluded host '${pattern}'`,
        };
      }
    }

    const hostAllowed =
      this.rules.allowed_hosts.some((h) => normalizeHost(h) === host) ||
      this.rules.allowed_domains.some((d) => hostMatchesPattern(host, d));
    if (!hostAllowed) {
      return {
        allowed: false,
        code: 'HOST_NOT_ALLOWED',
        reason: `Host '${host}' is not within the allowed hosts or domains`,
      };
    }

    const defaultPort = DEFAULT_PORTS[scheme] ?? null;
    const port = url.port === '' ? defaultPort : Number(url.port);
    const portAllowed =
      port !== null &&
      (this.rules.allowed_ports.length > 0
        ? this.rules.allowed_ports.includes(port)
        : port === defaultPort);
    if (!portAllowed) {
      return {
        allowed: false,
        code: 'PORT_NOT_ALLOWED',
        reason:
          this.rules.allowed_ports.length > 0
            ? `Port ${port} is not in the allowed ports`
            : `Port ${port} is not the default port for ${scheme} and no ports were explicitly allowed`,
      };
    }

    const path = url.pathname === '' ? '/' : url.pathname;
    for (const prefix of this.rules.excluded_paths) {
      const normalizedPrefix = prefix.startsWith('/') ? prefix : `/${prefix}`;
      const boundary = normalizedPrefix.endsWith('/') ? normalizedPrefix : `${normalizedPrefix}/`;
      if (path === normalizedPrefix || path.startsWith(boundary)) {
        return {
          allowed: false,
          code: 'PATH_EXCLUDED',
          reason: `Path '${path}' falls under excluded path '${prefix}'`,
        };
      }
    }

    return { allowed: true, normalized: { scheme, host, port, path } };
  }
}

const DOMAIN_PATTERN =
  /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
const IPV4_PATTERN = /^(?:\d{1,3}\.){3}\d{1,3}$/;
const IPV6_PATTERN = /^\[[0-9a-f:]+\]$/;

/**
 * Validates a target value of a given type against scope rules.
 * Used by the API layer when a target is added to an engagement: an
 * out-of-scope target is rejected deterministically, never by an LLM.
 */
export function validateTargetAgainstScope(
  type: TargetType,
  value: string,
  rules: ScopeRules,
): ScopeCheckResult {
  const checker = new ScopeChecker(rules);
  const v = value.trim();

  switch (type) {
    case 'URL':
    case 'CTF_INSTANCE':
    case 'APPLICATION':
      return checker.checkUrl(v);

    case 'DOMAIN': {
      const host = v.toLowerCase();
      if (!DOMAIN_PATTERN.test(host)) {
        return { allowed: false, code: 'TARGET_TYPE_INVALID', reason: `'${v}' is not a valid domain name` };
      }
      return checkBareHost(checker, host, rules);
    }

    case 'HOST': {
      const host = v.toLowerCase();
      const isHostLike =
        DOMAIN_PATTERN.test(host) || IPV4_PATTERN.test(host) || host === 'localhost' || IPV6_PATTERN.test(host);
      if (!isHostLike) {
        return { allowed: false, code: 'TARGET_TYPE_INVALID', reason: `'${v}' is not a valid host` };
      }
      return checkBareHost(checker, host, rules);
    }

    case 'IP': {
      const host = v.toLowerCase();
      if (!IPV4_PATTERN.test(host) && !IPV6_PATTERN.test(host)) {
        return { allowed: false, code: 'TARGET_TYPE_INVALID', reason: `'${v}' is not an IP literal` };
      }
      // IP literals are only permitted when listed verbatim in allowed_hosts.
      const allowed = rules.allowed_hosts.some((h) => normalizeHost(h) === host);
      return allowed
        ? { allowed: true, normalized: { scheme: '', host, port: null, path: '' } }
        : {
            allowed: false,
            code: 'HOST_NOT_ALLOWED',
            reason: `IP '${host}' is not explicitly listed in allowed hosts`,
          };
    }

    default:
      return { allowed: false, code: 'TARGET_TYPE_INVALID', reason: `Unknown target type '${String(type)}'` };
  }
}

function checkBareHost(
  checker: ScopeChecker,
  host: string,
  rules: ScopeRules,
): ScopeCheckResult {
  // Bare hosts are compared against host/domain rules only. If the scope
  // also excludes the host, deny.
  for (const pattern of rules.excluded_hosts) {
    if (hostMatchesPattern(host, pattern)) {
      return { allowed: false, code: 'HOST_EXCLUDED', reason: `Host '${host}' is excluded` };
    }
  }
  const hostAllowed =
    rules.allowed_hosts.some((h) => normalizeHost(h) === host) ||
    rules.allowed_domains.some((d) => hostMatchesPattern(host, d));
  if (!hostAllowed) {
    return {
      allowed: false,
      code: 'HOST_NOT_ALLOWED',
      reason: `Host '${host}' is not within the allowed hosts or domains`,
    };
  }
  void checker;
  return { allowed: true, normalized: { scheme: '', host, port: null, path: '' } };
}
