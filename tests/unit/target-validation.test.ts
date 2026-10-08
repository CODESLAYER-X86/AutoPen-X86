import { describe, expect, it } from 'vitest';
import { validateTargetAgainstScope, type ScopeRules } from '@aegis/security';

const rules: ScopeRules = {
  allowed_hosts: ['localhost', '10.10.0.5'],
  allowed_domains: ['example.com'],
  allowed_ports: [8080],
  allowed_schemes: ['http'],
  excluded_hosts: [],
  excluded_paths: ['/admin'],
  rate_limit: null,
  concurrency_limit: null,
  destructive_actions_allowed: false,
};

describe('target validation against scope (spec §11)', () => {
  it('accepts an in-scope URL target', () => {
    const result = validateTargetAgainstScope('URL', 'http://localhost:8080/', rules);
    expect(result.allowed).toBe(true);
  });

  it('accepts a DOMAIN target inside an allowed domain', () => {
    expect(validateTargetAgainstScope('DOMAIN', 'www.example.com', rules).allowed).toBe(true);
    expect(validateTargetAgainstScope('DOMAIN', 'example.com', rules).allowed).toBe(true);
  });

  it('rejects a DOMAIN target outside the allowed domains', () => {
    const result = validateTargetAgainstScope('DOMAIN', 'attacker.net', rules);
    expect(result.allowed).toBe(false);
    if (!result.allowed) expect(result.code).toBe('HOST_NOT_ALLOWED');
  });

  it('rejects malformed DOMAIN values', () => {
    const result = validateTargetAgainstScope('DOMAIN', 'not a domain!', rules);
    expect(result.allowed).toBe(false);
    if (!result.allowed) expect(result.code).toBe('TARGET_TYPE_INVALID');
  });

  it('accepts an IP target only when explicitly listed', () => {
    expect(validateTargetAgainstScope('IP', '10.10.0.5', rules).allowed).toBe(true);
    expect(validateTargetAgainstScope('IP', '10.10.0.99', rules).allowed).toBe(false);
    expect(validateTargetAgainstScope('IP', 'localhost', rules).allowed).toBe(false);
  });

  it('accepts CTF_INSTANCE targets as URLs (local labs)', () => {
    expect(validateTargetAgainstScope('CTF_INSTANCE', 'http://localhost:8080/', rules).allowed).toBe(true);
    expect(validateTargetAgainstScope('CTF_INSTANCE', 'http://evil.net/', rules).allowed).toBe(false);
  });

  it('rejects an unknown target type deterministically', () => {
    const result = validateTargetAgainstScope('GARBAGE' as 'URL', 'http://localhost:8080/', rules);
    expect(result.allowed).toBe(false);
    if (!result.allowed) expect(result.code).toBe('TARGET_TYPE_INVALID');
  });
});
