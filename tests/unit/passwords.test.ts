import { describe, expect, it } from 'vitest';
import { generateSessionToken, hashPassword, hashToken, sha256Hex, verifyPassword } from '@aegis/security';

describe('password hashing (scrypt)', () => {
  it('hashes and verifies correctly', () => {
    const stored = hashPassword('correct horse battery staple');
    expect(stored).toMatch(/^scrypt\$16384\$8\$1\$/);
    expect(verifyPassword('correct horse battery staple', stored)).toBe(true);
  });

  it('rejects wrong passwords', () => {
    const stored = hashPassword('right password');
    expect(verifyPassword('wrong password', stored)).toBe(false);
    expect(verifyPassword('', stored)).toBe(false);
  });

  it('produces unique salts (no rainbow-table reuse)', () => {
    const a = hashPassword('same password');
    const b = hashPassword('same password');
    expect(a).not.toBe(b);
  });

  it('fails closed on malformed stored hashes', () => {
    expect(verifyPassword('x', 'plaintext')).toBe(false);
    expect(verifyPassword('x', 'scrypt$999')).toBe(false);
    expect(verifyPassword('x', 'scrypt$a$b$c$d$e')).toBe(false);
  });
});

describe('session tokens', () => {
  it('generates 256-bit url-safe tokens', () => {
    const token = generateSessionToken();
    expect(token).toMatch(/^[A-Za-z0-9_-]{43}$/);
  });

  it('stores only a hash of the token (server-side)', () => {
    const token = generateSessionToken();
    const hashed = hashToken(token);
    expect(hashed).toMatch(/^[a-f0-9]{64}$/);
    expect(hashed).not.toBe(token);
  });

  it('hashes are deterministic and collision-free across tokens', () => {
    expect(hashToken('abc')).toBe(hashToken('abc'));
    expect(hashToken('abc')).not.toBe(hashToken('abd'));
  });

  it('sha256Hex digests arbitrary content', () => {
    const digest = sha256Hex('evidence content');
    expect(digest).toMatch(/^[a-f0-9]{64}$/);
    expect(sha256Hex(new TextEncoder().encode('evidence content'))).toBe(digest);
  });
});
