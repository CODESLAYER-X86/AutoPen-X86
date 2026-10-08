import { describe, expect, it } from 'vitest';
import { ScopeChecker, type ScopeRules } from '@aegis/security';

const rules: ScopeRules = {
  allowed_hosts: ['app.example.com', 'localhost', '10.10.0.5'],
  allowed_domains: ['example.com'],
  allowed_ports: [8443],
  allowed_schemes: ['https'],
  excluded_hosts: ['admin.example.com'],
  excluded_paths: ['/admin', '/.git'],
  rate_limit: null,
  concurrency_limit: null,
  destructive_actions_allowed: false,
};

const checker = () => new ScopeChecker(rules);

describe('deterministic scope checker (spec §10, §33)', () => {
  it('allows exact allowed hosts on allowed schemes/ports', () => {
    const result = checker().checkUrl('https://app.example.com:8443/path');
    expect(result.allowed).toBe(true);
  });

  it('allows subdomains of allowed domains', () => {
    const result = checker().checkUrl('https://blog.example.com:8443/');
    expect(result.allowed).toBe(true);
  });

  it('denies hosts that merely CONTAIN an allowed host (suffix trick)', () => {
    const result = checker().checkUrl('https://app.example.com.evil.attacker.com:8443/');
    expect(result.allowed).toBe(false);
    if (!result.allowed) expect(result.code).toBe('HOST_NOT_ALLOWED');
  });

  it('denies userinfo tricks (allowed host as credentials)', () => {
    const result = checker().checkUrl('https://app.example.com@evil.attacker.com:8443/');
    expect(result.allowed).toBe(false);
    // Userinfo is rejected outright — the check runs before host evaluation.
    if (!result.allowed) expect(result.code).toBe('USERINFO_NOT_ALLOWED');
  });

  it('rejects URLs with embedded credentials outright', () => {
    const result = checker().checkUrl('https://user:password@app.example.com:8443/');
    expect(result.allowed).toBe(false);
    if (!result.allowed) expect(result.code).toBe('USERINFO_NOT_ALLOWED');
  });

  it('denies non-allowed schemes', () => {
    const result = checker().checkUrl('http://app.example.com:8443/');
    expect(result.allowed).toBe(false);
    if (!result.allowed) expect(result.code).toBe('SCHEME_NOT_ALLOWED');
  });

  it('denies excluded hosts even when the domain is allowed', () => {
    const result = checker().checkUrl('https://admin.example.com:8443/');
    expect(result.allowed).toBe(false);
    if (!result.allowed) expect(result.code).toBe('HOST_EXCLUDED');
  });

  it('denies excluded path prefixes with boundary semantics', () => {
    const admin = checker().checkUrl('https://app.example.com:8443/admin/users');
    expect(admin.allowed).toBe(false);
    if (!admin.allowed) expect(admin.code).toBe('PATH_EXCLUDED');

    const git = checker().checkUrl('https://app.example.com:8443/.git/config');
    expect(git.allowed).toBe(false);
    if (!git.allowed) expect(git.code).toBe('PATH_EXCLUDED');

    // Similar but not excluded.
    const adminish = checker().checkUrl('https://app.example.com:8443/administration');
    expect(adminish.allowed).toBe(true);
  });

  it('denies non-listed ports', () => {
    const result = checker().checkUrl('https://app.example.com:9443/');
    expect(result.allowed).toBe(false);
    if (!result.allowed) expect(result.code).toBe('PORT_NOT_ALLOWED');
  });

  it('rejects unparseable URLs deterministically', () => {
    for (const bad of ['', 'not a url', 'https://', '::::']) {
      const result = checker().checkUrl(bad);
      expect(result.allowed).toBe(false);
    }
  });

  it('treats scheme default ports as allowed when no ports are listed', () => {
    const noPorts = new ScopeChecker({ ...rules, allowed_ports: [] });
    expect(noPorts.checkUrl('https://app.example.com/').allowed).toBe(true);
    expect(noPorts.checkUrl('https://app.example.com:8443/').allowed).toBe(false);
  });

  it('normalises case and trailing dots in hosts', () => {
    const result = checker().checkUrl('HTTPS://APP.EXAMPLE.COM.:8443/');
    expect(result.allowed).toBe(true);
  });

  it('is case-insensitive on schemes and lowercases hosts', () => {
    const result = checker().checkUrl('HTTPS://LOCALHOST:8443/x');
    expect(result.allowed).toBe(true);
    if (result.allowed) expect(result.normalized.host).toBe('localhost');
  });

  it('IP literals must be listed verbatim', () => {
    expect(checker().checkUrl('https://10.10.0.5:8443/').allowed).toBe(true);
    expect(checker().checkUrl('https://10.10.0.6:8443/').allowed).toBe(false);
  });
});
