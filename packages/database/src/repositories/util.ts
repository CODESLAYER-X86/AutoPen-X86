/** Shared repository helpers. */
import type { Pool } from 'pg';

/** Convert pg timestamps to ISO strings (stable JSON representation). */
export function iso(value: Date | string | null | undefined): string | null {
  if (value === null || value === undefined) return null;
  return value instanceof Date ? value.toISOString() : new Date(value).toISOString();
}

export function requireIso(value: Date | string): string {
  const result = iso(value);
  if (result === null) throw new Error('Expected non-null timestamp');
  return result;
}

export interface RepoBase {
  readonly pool: Pool;
}
