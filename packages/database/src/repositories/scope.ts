import type { Pool } from 'pg';
import { generateId } from '@aegis/shared';
import type { ScopeRecord } from '../types.js';
import { requireIso, type RepoBase } from './util.js';

export interface ScopeInput {
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

export class ScopeRepository implements RepoBase {
  constructor(readonly pool: Pool) {}

  /** Upsert: one scope row per engagement (unique constraint). */
  async upsert(engagementId: string, input: ScopeInput): Promise<ScopeRecord> {
    const id = generateId('SCP');
    const result = await this.pool.query(
      `INSERT INTO scope (
         id, engagement_id, allowed_hosts, allowed_domains, allowed_ports,
         allowed_schemes, excluded_hosts, excluded_paths, rate_limit,
         concurrency_limit, destructive_actions_allowed
       ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
       ON CONFLICT (engagement_id) DO UPDATE SET
         allowed_hosts = EXCLUDED.allowed_hosts,
         allowed_domains = EXCLUDED.allowed_domains,
         allowed_ports = EXCLUDED.allowed_ports,
         allowed_schemes = EXCLUDED.allowed_schemes,
         excluded_hosts = EXCLUDED.excluded_hosts,
         excluded_paths = EXCLUDED.excluded_paths,
         rate_limit = EXCLUDED.rate_limit,
         concurrency_limit = EXCLUDED.concurrency_limit,
         destructive_actions_allowed = EXCLUDED.destructive_actions_allowed,
         updated_at = now()
       RETURNING id, engagement_id, allowed_hosts, allowed_domains, allowed_ports,
                 allowed_schemes, excluded_hosts, excluded_paths, rate_limit,
                 concurrency_limit, destructive_actions_allowed, created_at, updated_at`,
      [
        id,
        engagementId,
        input.allowed_hosts,
        input.allowed_domains,
        input.allowed_ports,
        input.allowed_schemes,
        input.excluded_hosts,
        input.excluded_paths,
        input.rate_limit ?? null,
        input.concurrency_limit ?? null,
        input.destructive_actions_allowed,
      ],
    );
    return mapScope(result.rows[0]!);
  }

  async findByEngagement(engagementId: string): Promise<ScopeRecord | null> {
    const result = await this.pool.query(
      `SELECT id, engagement_id, allowed_hosts, allowed_domains, allowed_ports,
              allowed_schemes, excluded_hosts, excluded_paths, rate_limit,
              concurrency_limit, destructive_actions_allowed, created_at, updated_at
       FROM scope WHERE engagement_id = $1`,
      [engagementId],
    );
    return result.rows[0] ? mapScope(result.rows[0]) : null;
  }
}

type ScopeRow = {
  id: string;
  engagement_id: string;
  allowed_hosts: string[];
  allowed_domains: string[];
  allowed_ports: number[];
  allowed_schemes: string[];
  excluded_hosts: string[];
  excluded_paths: string[];
  rate_limit: number | null;
  concurrency_limit: number | null;
  destructive_actions_allowed: boolean;
  created_at: Date;
  updated_at: Date;
};

export function mapScope(row: ScopeRow): ScopeRecord {
  return {
    id: row.id,
    engagement_id: row.engagement_id,
    allowed_hosts: row.allowed_hosts ?? [],
    allowed_domains: row.allowed_domains ?? [],
    allowed_ports: row.allowed_ports ?? [],
    allowed_schemes: row.allowed_schemes ?? [],
    excluded_hosts: row.excluded_hosts ?? [],
    excluded_paths: row.excluded_paths ?? [],
    rate_limit: row.rate_limit,
    concurrency_limit: row.concurrency_limit,
    destructive_actions_allowed: row.destructive_actions_allowed,
    created_at: requireIso(row.created_at),
    updated_at: requireIso(row.updated_at),
  };
}
