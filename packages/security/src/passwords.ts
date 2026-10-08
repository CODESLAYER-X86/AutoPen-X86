/**
 * Password hashing (scrypt from node:crypto — no native modules required)
 * and session token helpers. Hash format:
 *
 *   scrypt$<N>$<r>$<p>$<saltB64>$<hashB64>
 */
import { randomBytes, scryptSync, timingSafeEqual, createHash } from 'node:crypto';

const N = 16384;
const R = 8;
const P = 1;
const KEYLEN = 64;
// maxmem must comfortably exceed 128*N*r (16 MiB for default params).
const MAXMEM = 256 * 1024 * 1024;

export function hashPassword(password: string): string {
  const salt = randomBytes(16);
  const hash = scryptSync(password, salt, KEYLEN, { N, r: R, p: P, maxmem: MAXMEM });
  return `scrypt$${N}$${R}$${P}$${salt.toString('base64')}$${hash.toString('base64')}`;
}

export function verifyPassword(password: string, stored: string): boolean {
  const parts = stored.split('$');
  if (parts.length !== 6 || parts[0] !== 'scrypt') return false;
  const n = Number(parts[1]);
  const r = Number(parts[2]);
  const p = Number(parts[3]);
  if (!Number.isFinite(n) || !Number.isFinite(r) || !Number.isFinite(p) || n < 1 || r < 1 || p < 1) {
    return false;
  }
  let salt: Buffer;
  let expected: Buffer;
  try {
    salt = Buffer.from(parts[4]!, 'base64');
    expected = Buffer.from(parts[5]!, 'base64');
  } catch {
    return false;
  }
  let actual: Buffer;
  try {
    actual = scryptSync(password, salt, expected.length, { N: n, r, p, maxmem: MAXMEM });
  } catch {
    return false;
  }
  if (actual.length !== expected.length) return false;
  return timingSafeEqual(actual, expected);
}

/** Generates a URL-safe opaque session token (256 bits). */
export function generateSessionToken(): string {
  return randomBytes(32).toString('base64url');
}

/** Platform auth sessions store only the SHA-256 of the token. */
export function hashToken(token: string): string {
  return createHash('sha256').update(token, 'utf8').digest('hex');
}

/** Generic SHA-256 hex digest for arbitrary bytes/strings. */
export function sha256Hex(data: string | Uint8Array): string {
  return createHash('sha256').update(data).digest('hex');
}
