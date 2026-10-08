import type { Pool } from 'pg';
import { generateId, type IdentityType, type SessionType } from '@aegis/shared';
import type { IdentityRecord, SessionRecord } from '../types.js';
import { requireIso, type RepoBase } from './util.js';

export interface CreateIdentityInput {
  engagementId: string;
  name: string;
  role: string;
  type: IdentityType;
  metadata: Record<string, unknown>;
}

export interface CreateSessionInput {
  identityId: string;
  type: SessionType;
  secretReference: string;
  metadata?: Record<string, unknown>;
  expiresAt?: Date | null;
}

export class IdentitiesRepository implements RepoBase {
  constructor(readonly pool: Pool) {}

  async create(input: CreateIdentityInput): Promise<IdentityRecord> {
    const id = generateId('IDN');
    const result = await this.pool.query(
      `INSERT INTO identities (id, engagement_id, name, role, type, metadata)
       VALUES ($1, $2, $3, $4, $5, $6::jsonb)
       RETURNING id, engagement_id, name, role, type, metadata, created_at, updated_at`,
      [id, input.engagementId, input.name, input.role, input.type, JSON.stringify(input.metadata)],
    );
    return mapIdentity(result.rows[0]!);
  }

  async listByEngagement(engagementId: string): Promise<IdentityRecord[]> {
    const result = await this.pool.query(
      `SELECT id, engagement_id, name, role, type, metadata, created_at, updated_at
       FROM identities WHERE engagement_id = $1 ORDER BY created_at ASC`,
      [engagementId],
    );
    return result.rows.map(mapIdentity);
  }
}

export class SessionsRepository implements RepoBase {
  constructor(readonly pool: Pool) {}

  async create(input: CreateSessionInput): Promise<SessionRecord> {
    const id = generateId('SES');
    const result = await this.pool.query(
      `INSERT INTO sessions (id, identity_id, type, status, metadata, secret_reference, expires_at)
       VALUES ($1, $2, $3, 'ACTIVE', $4::jsonb, $5, $6)
       RETURNING id, identity_id, type, status, metadata, secret_reference, created_at, expires_at, updated_at`,
      [id, input.identityId, input.type, JSON.stringify(input.metadata ?? {}), input.secretReference, input.expiresAt ?? null],
    );
    return mapSession(result.rows[0]!);
  }

  async listByIdentity(identityId: string): Promise<SessionRecord[]> {
    const result = await this.pool.query(
      `SELECT id, identity_id, type, status, metadata, secret_reference, created_at, expires_at, updated_at
       FROM sessions WHERE identity_id = $1 ORDER BY created_at DESC`,
      [identityId],
    );
    return result.rows.map(mapSession);
  }
}

type IdentityRow = {
  id: string;
  engagement_id: string;
  name: string;
  role: string;
  type: IdentityType;
  metadata: Record<string, unknown>;
  created_at: Date;
  updated_at: Date;
};

function mapIdentity(row: IdentityRow): IdentityRecord {
  return {
    id: row.id,
    engagement_id: row.engagement_id,
    name: row.name,
    role: row.role,
    type: row.type,
    metadata: row.metadata ?? {},
    created_at: requireIso(row.created_at),
    updated_at: requireIso(row.updated_at),
  };
}

type SessionRow = {
  id: string;
  identity_id: string;
  type: SessionType;
  status: string;
  metadata: Record<string, unknown>;
  secret_reference: string;
  created_at: Date;
  expires_at: Date | null;
  updated_at: Date;
};

function mapSession(row: SessionRow): SessionRecord {
  return {
    id: row.id,
    identity_id: row.identity_id,
    type: row.type,
    status: row.status as SessionRecord['status'],
    metadata: row.metadata ?? {},
    secret_reference: row.secret_reference,
    created_at: requireIso(row.created_at),
    expires_at: row.expires_at ? requireIso(row.expires_at) : null,
    updated_at: requireIso(row.updated_at),
  };
}
