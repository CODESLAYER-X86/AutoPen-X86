/**
 * Part 4 repositories — attack-surface graph nodes/edges (spec §4-§6) and
 * processor failure log (spec §112).
 *
 * Graph persistence uses fingerprint upserts: repeated processing of the same
 * observation produces the same node and the same edge — never duplicates.
 */
import type { Pool } from 'pg';
import { generateId } from '@aegis/shared';
import type { AttackEdgeRelation, AttackNodeType } from '@aegis/shared';
import type { AttackEdgeRecord, AttackNodeRecord, ReasoningFailureRecord } from '../types.js';
import { iso } from './util.js';

// -- Attack nodes (§4-§6) --------------------------------------------------------

export interface UpsertNodeInput {
  engagementId: string;
  nodeType: AttackNodeType;
  externalRef: string | null;
  fingerprint: string;
  label: string;
  metadata: Record<string, unknown>;
  confidence: number;
  at: string;
}

export class AttackNodesRepository {
  constructor(readonly pool: Pool) {}

  async upsert(input: UpsertNodeInput): Promise<AttackNodeRecord> {
    const id = generateId('AGN');
    const result = await this.pool.query(
      `INSERT INTO attack_nodes (id, engagement_id, node_type, external_ref, fingerprint, label, metadata, confidence, first_seen, last_seen)
       VALUES ($1,$2,$3,$4,$5,$6,$7::jsonb,$8,$9,$9)
       ON CONFLICT (engagement_id, fingerprint) DO UPDATE SET
         label = EXCLUDED.label,
         metadata = attack_nodes.metadata || EXCLUDED.metadata,
         confidence = GREATEST(attack_nodes.confidence, EXCLUDED.confidence),
         last_seen = EXCLUDED.last_seen
       RETURNING *`,
      [
        id,
        input.engagementId,
        input.nodeType,
        input.externalRef,
        input.fingerprint,
        input.label,
        JSON.stringify(input.metadata),
        input.confidence,
        input.at,
      ],
    );
    return mapNodeRow(result.rows[0]!);
  }

  async findById(id: string): Promise<AttackNodeRecord | null> {
    const result = await this.pool.query('SELECT * FROM attack_nodes WHERE id = $1', [id]);
    return result.rows[0] ? mapNodeRow(result.rows[0]) : null;
  }

  async findByExternalRef(engagementId: string, nodeType: AttackNodeType, externalRef: string): Promise<AttackNodeRecord | null> {
    const result = await this.pool.query(
      'SELECT * FROM attack_nodes WHERE engagement_id = $1 AND node_type = $2 AND external_ref = $3',
      [engagementId, nodeType, externalRef],
    );
    return result.rows[0] ? mapNodeRow(result.rows[0]) : null;
  }

  async listByEngagement(engagementId: string, options: { types?: AttackNodeType[]; limit?: number } = {}): Promise<AttackNodeRecord[]> {
    const limit = Math.min(Math.max(options.limit ?? 500, 1), 2000);
    const types = options.types?.length ? options.types : null;
    const result = await this.pool.query(
      `SELECT * FROM attack_nodes WHERE engagement_id = $1 ${types ? 'AND node_type = ANY($2::text[])' : ''}
       ORDER BY last_seen DESC LIMIT ${types ? '$3' : '$2'}`,
      types ? [engagementId, types, limit] : [engagementId, limit],
    );
    return result.rows.map(mapNodeRow);
  }

  async countByEngagement(engagementId: string): Promise<number> {
    const result = await this.pool.query(
      'SELECT count(*)::int AS total FROM attack_nodes WHERE engagement_id = $1',
      [engagementId],
    );
    return (result.rows[0] as { total: number }).total;
  }
}

// -- Attack edges (§4) ---------------------------------------------------------------

export interface UpsertEdgeInput {
  engagementId: string;
  sourceNodeId: string;
  targetNodeId: string;
  relation: AttackEdgeRelation;
  metadata: Record<string, unknown>;
  confidence: number;
}

export class AttackEdgesRepository {
  constructor(readonly pool: Pool) {}

  async upsert(input: UpsertEdgeInput): Promise<{ record: AttackEdgeRecord; created: boolean }> {
    const id = generateId('AGE');
    const result = await this.pool.query(
      `INSERT INTO attack_edges (id, engagement_id, source_node_id, target_node_id, relation, metadata, confidence)
       VALUES ($1,$2,$3,$4,$5,$6::jsonb,$7)
       ON CONFLICT (engagement_id, source_node_id, target_node_id, relation) DO UPDATE SET
         metadata = attack_edges.metadata || EXCLUDED.metadata,
         confidence = GREATEST(attack_edges.confidence, EXCLUDED.confidence)
       RETURNING *`,
      [
        id,
        input.engagementId,
        input.sourceNodeId,
        input.targetNodeId,
        input.relation,
        JSON.stringify(input.metadata),
        input.confidence,
      ],
    );
    const row = result.rows[0]!;
    return { record: mapEdgeRow(row), created: (row.id as string) === id };
  }

  async listByEngagement(engagementId: string, limit = 1000): Promise<AttackEdgeRecord[]> {
    const result = await this.pool.query(
      'SELECT * FROM attack_edges WHERE engagement_id = $1 ORDER BY created_at DESC LIMIT $2',
      [engagementId, Math.min(Math.max(limit, 1), 4000)],
    );
    return result.rows.map(mapEdgeRow);
  }

  async listByNode(nodeId: string): Promise<AttackEdgeRecord[]> {
    const result = await this.pool.query(
      'SELECT * FROM attack_edges WHERE source_node_id = $1 OR target_node_id = $1 ORDER BY created_at',
      [nodeId],
    );
    return result.rows.map(mapEdgeRow);
  }

  async countByEngagement(engagementId: string): Promise<number> {
    const result = await this.pool.query(
      'SELECT count(*)::int AS total FROM attack_edges WHERE engagement_id = $1',
      [engagementId],
    );
    return (result.rows[0] as { total: number }).total;
  }
}

// -- Processor failure log (§112) ---------------------------------------------------------

export class ReasoningFailuresRepository {
  constructor(readonly pool: Pool) {}

  async insert(input: {
    engagementId: string;
    processor: string;
    eventId: string | null;
    eventType: string | null;
    error: Record<string, unknown>;
  }): Promise<ReasoningFailureRecord> {
    const id = generateId('RFL');
    const result = await this.pool.query(
      `INSERT INTO reasoning_failures (id, engagement_id, processor, event_id, event_type, error)
       VALUES ($1,$2,$3,$4,$5,$6::jsonb)
       RETURNING *`,
      [id, input.engagementId, input.processor, input.eventId, input.eventType, JSON.stringify(input.error)],
    );
    return mapFailureRow(result.rows[0]!);
  }

  async listByEngagement(engagementId: string, limit = 50): Promise<ReasoningFailureRecord[]> {
    const result = await this.pool.query(
      'SELECT * FROM reasoning_failures WHERE engagement_id = $1 ORDER BY created_at DESC LIMIT $2',
      [engagementId, Math.min(Math.max(limit, 1), 500)],
    );
    return result.rows.map(mapFailureRow);
  }

  async countByEngagement(engagementId: string): Promise<number> {
    const result = await this.pool.query(
      'SELECT count(*)::int AS total FROM reasoning_failures WHERE engagement_id = $1',
      [engagementId],
    );
    return (result.rows[0] as { total: number }).total;
  }

  async markStatus(id: string, status: 'NEW' | 'RESOLVED' | 'SKIPPED'): Promise<void> {
    await this.pool.query('UPDATE reasoning_failures SET status = $2 WHERE id = $1', [id, status]);
  }
}

// -- Row mappers ------------------------------------------------------------------------------

function mapNodeRow(row: Record<string, unknown>): AttackNodeRecord {
  return {
    id: row.id as string,
    engagement_id: row.engagement_id as string,
    node_type: row.node_type as AttackNodeType,
    external_ref: (row.external_ref as string | null) ?? null,
    fingerprint: row.fingerprint as string,
    label: row.label as string,
    metadata: (row.metadata as Record<string, unknown>) ?? {},
    confidence: Number(row.confidence),
    first_seen: iso(row.first_seen as Date) ?? '',
    last_seen: iso(row.last_seen as Date) ?? '',
  };
}

function mapEdgeRow(row: Record<string, unknown>): AttackEdgeRecord {
  return {
    id: row.id as string,
    engagement_id: row.engagement_id as string,
    source_node_id: row.source_node_id as string,
    target_node_id: row.target_node_id as string,
    relation: row.relation as AttackEdgeRelation,
    metadata: (row.metadata as Record<string, unknown>) ?? {},
    confidence: Number(row.confidence),
    created_at: iso(row.created_at as Date) ?? '',
  };
}

function mapFailureRow(row: Record<string, unknown>): ReasoningFailureRecord {
  return {
    id: row.id as string,
    engagement_id: row.engagement_id as string,
    processor: row.processor as string,
    event_id: (row.event_id as string | null) ?? null,
    event_type: (row.event_type as string | null) ?? null,
    error: (row.error as Record<string, unknown>) ?? {},
    retry_count: row.retry_count as number,
    status: row.status as 'NEW' | 'RESOLVED' | 'SKIPPED',
    created_at: iso(row.created_at as Date) ?? '',
  };
}
