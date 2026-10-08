import type { Pool } from 'pg';
import { generateId } from '@aegis/shared';
import type { AuthSessionRecord } from '../types.js';
import { requireIso, type RepoBase } from './util.js';

export interface CreateAuthSessionInput {
  userId: string;
  tokenHash: string;
  expiresAt: Date;
}

export class AuthSessionsRepository implements RepoBase {
  constructor(readonly pool: Pool) {}

  async create(input: CreateAuthSessionInput): Promise<AuthSessionRecord> {
    const id = generateId('SES');
    const result = await this.pool.query(
      `INSERT INTO auth_sessions (id, user_id, token_hash, expires_at)
       VALUES ($1, $2, $3, $4)
       RETURNING id, user_id, token_hash, created_at, expires_at, revoked_at`,
      [id, input.userId, input.tokenHash, input.expiresAt],
    );
    return mapAuthSession(result.rows[0]!);
  }

  /** Active = not expired, not revoked. */
  async findActiveByTokenHash(tokenHash: string): Promise<AuthSessionRecord | null> {
    const result = await this.pool.query(
      `SELECT id, user_id, token_hash, created_at, expires_at, revoked_at
       FROM auth_sessions
       WHERE token_hash = $1 AND revoked_at IS NULL AND expires_at > now()`,
      [tokenHash],
    );
    return result.rows[0] ? mapAuthSession(result.rows[0]) : null;
  }

  async revokeByTokenHash(tokenHash: string): Promise<boolean> {
    const result = await this.pool.query(
      'UPDATE auth_sessions SET revoked_at = now() WHERE token_hash = $1 AND revoked_at IS NULL',
      [tokenHash],
    );
    return (result.rowCount ?? 0) > 0;
  }

  async revokeAllForUser(userId: string): Promise<number> {
    const result = await this.pool.query(
      'UPDATE auth_sessions SET revoked_at = now() WHERE user_id = $1 AND revoked_at IS NULL',
      [userId],
    );
    return result.rowCount ?? 0;
  }
}

type AuthSessionRow = {
  id: string;
  user_id: string;
  token_hash: string;
  created_at: Date;
  expires_at: Date;
  revoked_at: Date | null;
};

function mapAuthSession(row: AuthSessionRow): AuthSessionRecord {
  return {
    id: row.id,
    user_id: row.user_id,
    token_hash: row.token_hash,
    created_at: requireIso(row.created_at),
    expires_at: requireIso(row.expires_at),
    revoked_at: row.revoked_at ? requireIso(row.revoked_at) : null,
  };
}
