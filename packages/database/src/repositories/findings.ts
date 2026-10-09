import type { Pool } from 'pg';
import { generateId, type FindingStatus } from '@aegis/shared';
import type { FindingRecord } from '../types.js';
import { requireIso, type RepoBase } from './util.js';

const FINDING_COLUMNS =
  `id, engagement_id, hypothesis_id, title, description, severity, status, evidence_ids,
   category, confidence, confidence_level, confidence_reasons, impact, remediation,
   verification_ids, target_refs, affected_endpoints, affected_identities, mode,
   created_at, updated_at`;

export interface CreateFindingInput {
  engagementId: string;
  hypothesisId: string | null;
  title: string;
  description: string;
  severity: string;
  evidenceIds?: string[];
  /** Promotion status (§55): findings promoted from CONFIRMED hypotheses are CONFIRMED. */
  status?: FindingStatus;
}

export class FindingsRepository implements RepoBase {
  constructor(readonly pool: Pool) {}

  async create(input: CreateFindingInput): Promise<FindingRecord> {
    const id = generateId('FND');
    const result = await this.pool.query(
      `INSERT INTO findings (id, engagement_id, hypothesis_id, title, description, severity, status, evidence_ids)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8::jsonb)
       RETURNING ${FINDING_COLUMNS}`,
      [
        id,
        input.engagementId,
        input.hypothesisId,
        input.title,
        input.description,
        input.severity,
        input.status ?? 'PROPOSED',
        JSON.stringify(input.evidenceIds ?? []),
      ],
    );
    return mapFinding(result.rows[0]!);
  }

  async updateStatus(id: string, status: FindingStatus): Promise<FindingRecord | null> {
    const result = await this.pool.query(
      `UPDATE findings SET status = $2, updated_at = now() WHERE id = $1
       RETURNING ${FINDING_COLUMNS}`,
      [id, status],
    );
    return result.rows[0] ? mapFinding(result.rows[0]) : null;
  }

  /**
   * Part 6 §28/§58: attach the confidence model + rich linkage to a finding.
   * Used by the verification bridge after a finding is promoted.
   */
  async enrich(
    id: string,
    update: {
      category?: string;
      confidence?: number;
      confidenceLevel?: 'HIGH' | 'MEDIUM' | 'LOW';
      confidenceReasons?: string[];
      impact?: string;
      remediation?: string;
      verificationIds?: string[];
      evidenceIds?: string[];
      targetRefs?: string[];
      affectedEndpoints?: string[];
      affectedIdentities?: string[];
      mode?: string;
    },
  ): Promise<FindingRecord | null> {
    const result = await this.pool.query(
      `UPDATE findings SET
         category = COALESCE($2, category),
         confidence = COALESCE($3, confidence),
         confidence_level = COALESCE($4, confidence_level),
         confidence_reasons = COALESCE($5::jsonb, confidence_reasons),
         impact = COALESCE($6, impact),
         remediation = COALESCE($7, remediation),
         verification_ids = COALESCE($8::jsonb, verification_ids),
         evidence_ids = CASE WHEN $9::jsonb IS NOT NULL
           THEN (SELECT jsonb_agg(DISTINCT e) FROM jsonb_array_elements(evidence_ids || $9::jsonb) AS e)
           ELSE evidence_ids END,
         target_refs = COALESCE($10::jsonb, target_refs),
         affected_endpoints = COALESCE($11::jsonb, affected_endpoints),
         affected_identities = COALESCE($12::jsonb, affected_identities),
         mode = COALESCE($13, mode),
         updated_at = now()
       WHERE id = $1
       RETURNING ${FINDING_COLUMNS}`,
      [
        id,
        update.category ?? null,
        update.confidence ?? null,
        update.confidenceLevel ?? null,
        update.confidenceReasons ? JSON.stringify(update.confidenceReasons) : null,
        update.impact ?? null,
        update.remediation ?? null,
        update.verificationIds ? JSON.stringify(update.verificationIds) : null,
        update.evidenceIds ? JSON.stringify(update.evidenceIds) : null,
        update.targetRefs ? JSON.stringify(update.targetRefs) : null,
        update.affectedEndpoints ? JSON.stringify(update.affectedEndpoints) : null,
        update.affectedIdentities ? JSON.stringify(update.affectedIdentities) : null,
        update.mode ?? null,
      ],
    );
    return result.rows[0] ? mapFinding(result.rows[0]) : null;
  }

  async findByHypothesis(hypothesisId: string): Promise<FindingRecord | null> {
    const result = await this.pool.query(
      `SELECT ${FINDING_COLUMNS} FROM findings WHERE hypothesis_id = $1 LIMIT 1`,
      [hypothesisId],
    );
    return result.rows[0] ? mapFinding(result.rows[0]) : null;
  }

  async listByEngagement(
    engagementId: string,
    options: { statuses?: readonly FindingStatus[]; limit?: number } = {},
  ): Promise<FindingRecord[]> {
    const limit = Math.min(Math.max(options.limit ?? 200, 1), 500);
    if (options.statuses && options.statuses.length > 0) {
      const result = await this.pool.query(
        `SELECT ${FINDING_COLUMNS} FROM findings
         WHERE engagement_id = $1 AND status = ANY($2::text[])
         ORDER BY created_at DESC LIMIT $3`,
        [engagementId, [...options.statuses], limit],
      );
      return result.rows.map(mapFinding);
    }
    const result = await this.pool.query(
      `SELECT ${FINDING_COLUMNS} FROM findings WHERE engagement_id = $1
       ORDER BY created_at DESC LIMIT $2`,
      [engagementId, limit],
    );
    return result.rows.map(mapFinding);
  }
}

type FindingRow = {
  id: string;
  engagement_id: string;
  hypothesis_id: string | null;
  title: string;
  description: string;
  severity: string;
  status: FindingStatus;
  evidence_ids: string[];
  category: string | null;
  confidence: number | null;
  confidence_level: 'HIGH' | 'MEDIUM' | 'LOW' | null;
  confidence_reasons: string[] | null;
  impact: string | null;
  remediation: string | null;
  verification_ids: string[] | null;
  target_refs: string[] | null;
  affected_endpoints: string[] | null;
  affected_identities: string[] | null;
  mode: string | null;
  created_at: Date;
  updated_at: Date;
};

export function mapFinding(row: FindingRow): FindingRecord {
  return {
    id: row.id,
    engagement_id: row.engagement_id,
    hypothesis_id: row.hypothesis_id,
    title: row.title,
    description: row.description,
    severity: row.severity,
    status: row.status,
    evidence_ids: row.evidence_ids ?? [],
    category: row.category,
    confidence: row.confidence,
    confidence_level: row.confidence_level,
    confidence_reasons: row.confidence_reasons ?? [],
    impact: row.impact,
    remediation: row.remediation,
    verification_ids: row.verification_ids ?? [],
    target_refs: row.target_refs ?? [],
    affected_endpoints: row.affected_endpoints ?? [],
    affected_identities: row.affected_identities ?? [],
    mode: row.mode ?? 'PENTEST',
    created_at: requireIso(row.created_at),
    updated_at: requireIso(row.updated_at),
  };
}
