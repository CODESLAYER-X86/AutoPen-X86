import type { Pool } from 'pg';
import { generateId, type FindingStatus } from '@aegis/shared';
import type {
  FindingEvidenceQualityRecord,
  FindingLifecycleEventRecord,
  FindingRecord,
} from '../types.js';
import { requireIso, type RepoBase } from './util.js';

const FINDING_COLUMNS =
  `id, engagement_id, hypothesis_id, title, description, severity, status, evidence_ids,
   category, confidence, confidence_level, confidence_reasons, impact, remediation,
   verification_ids, target_refs, affected_endpoints, affected_identities, mode,
   retest_state, cvss_version, cvss_vector, cvss_base_score, cvss_temporal_score,
   cvss_environmental_score, cvss_base_severity, severity_source, dedup_key, duplicate_of,
   observed_behavior, expected_behavior,
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

  /** Part 7 §6: load one finding scoped to its engagement. */
  async findByIdAndEngagement(id: string, engagementId: string): Promise<FindingRecord | null> {
    const result = await this.pool.query(
      `SELECT ${FINDING_COLUMNS} FROM findings WHERE id = $1 AND engagement_id = $2 LIMIT 1`,
      [id, engagementId],
    );
    return result.rows[0] ? mapFinding(result.rows[0]) : null;
  }

  /** Part 7 §19: find sibling findings sharing a dedup key. */
  async findByDedupKey(engagementId: string, dedupKey: string): Promise<FindingRecord[]> {
    const result = await this.pool.query(
      `SELECT ${FINDING_COLUMNS} FROM findings
       WHERE engagement_id = $1 AND dedup_key = $2 AND duplicate_of IS NULL
       ORDER BY created_at ASC`,
      [engagementId, dedupKey],
    );
    return result.rows.map(mapFinding);
  }

  /** Part 7 §19-§20: mark a finding as a duplicate of another (kept, never
   *  deleted; affected endpoint refs accumulate on the primary). */
  async markDuplicate(id: string, duplicateOf: string, mergedEndpoints: string[]): Promise<FindingRecord | null> {
    const result = await this.pool.query(
      `UPDATE findings SET duplicate_of = $2, status = 'DUPLICATE',
         affected_endpoints = affected_endpoints || $3::jsonb, updated_at = now()
       WHERE id = $1
       RETURNING ${FINDING_COLUMNS}`,
      [id, duplicateOf, JSON.stringify(mergedEndpoints)],
    );
    return result.rows[0] ? mapFinding(result.rows[0]) : null;
  }

  /** Part 7 §18: persist the deterministic CVSS representation. */
  async applyCvss(
    id: string,
    cvss: {
      version: string;
      vector: string;
      baseScore: number;
      temporalScore: number | null;
      environmentalScore: number | null;
      baseSeverity: string;
      severity: string;
      source: 'CVSS_CALCULATOR' | 'HUMAN_OVERRIDE';
    },
  ): Promise<FindingRecord | null> {
    const result = await this.pool.query(
      `UPDATE findings SET
         cvss_version = $2, cvss_vector = $3, cvss_base_score = $4,
         cvss_temporal_score = $5, cvss_environmental_score = $6, cvss_base_severity = $7,
         severity = $8, severity_source = $9, updated_at = now()
       WHERE id = $1
       RETURNING ${FINDING_COLUMNS}`,
      [
        id,
        cvss.version,
        cvss.vector,
        cvss.baseScore,
        cvss.temporalScore,
        cvss.environmentalScore,
        cvss.baseSeverity,
        cvss.severity,
        cvss.source,
      ],
    );
    return result.rows[0] ? mapFinding(result.rows[0]) : null;
  }

  /** Part 7 §38: update the retest state. */
  async setRetestState(id: string, retestState: string): Promise<FindingRecord | null> {
    const result = await this.pool.query(
      `UPDATE findings SET retest_state = $2, updated_at = now() WHERE id = $1
       RETURNING ${FINDING_COLUMNS}`,
      [id, retestState],
    );
    return result.rows[0] ? mapFinding(result.rows[0]) : null;
  }

  /** Part 7 §4: record an auditable lifecycle transition (engine or human). */
  async recordLifecycleEvent(
    findingId: string,
    engagementId: string,
    from: string,
    to: string,
    reason: string,
    actor: 'ENGINE' | 'HUMAN',
  ): Promise<FindingLifecycleEventRecord> {
    const id = generateId('FLE');
    const result = await this.pool.query(
      `INSERT INTO finding_lifecycle_events (id, finding_id, engagement_id, from_status, to_status, reason, actor)
       VALUES ($1, $2, $3, $4, $5, $6, $7)
       RETURNING id, finding_id, engagement_id, from_status, to_status, reason, actor, created_at`,
      [id, findingId, engagementId, from, to, reason, actor],
    );
    const row = result.rows[0]!;
    return {
      id: row.id,
      finding_id: row.finding_id,
      engagement_id: row.engagement_id,
      from_status: row.from_status,
      to_status: row.to_status,
      reason: row.reason,
      actor: row.actor,
      created_at: requireIso(row.created_at),
    };
  }

  async listLifecycleEvents(findingId: string, limit = 50): Promise<FindingLifecycleEventRecord[]> {
    const result = await this.pool.query(
      `SELECT id, finding_id, engagement_id, from_status, to_status, reason, actor, created_at
       FROM finding_lifecycle_events WHERE finding_id = $1 ORDER BY created_at ASC LIMIT $2`,
      [findingId, Math.min(Math.max(limit, 1), 200)],
    );
    return result.rows.map((row) => ({
      id: row.id,
      finding_id: row.finding_id,
      engagement_id: row.engagement_id,
      from_status: row.from_status,
      to_status: row.to_status,
      reason: row.reason,
      actor: row.actor,
      created_at: requireIso(row.created_at),
    }));
  }

  /** Part 7 §70: record evidence quality per finding. */
  async setEvidenceQuality(
    findingId: string,
    engagementId: string,
    entries: Array<{ evidence_id: string; quality: string; note?: string }>,
  ): Promise<void> {
    for (const entry of entries) {
      await this.pool.query(
        `INSERT INTO finding_evidence_quality (id, finding_id, engagement_id, evidence_id, quality, note)
         VALUES ($1, $2, $3, $4, $5, $6)
         ON CONFLICT (finding_id, evidence_id) DO UPDATE SET quality = EXCLUDED.quality, note = EXCLUDED.note`,
        [generateId('FEQ'), findingId, engagementId, entry.evidence_id, entry.quality, entry.note ?? null],
      );
    }
  }

  async listEvidenceQuality(findingId: string): Promise<FindingEvidenceQualityRecord[]> {
    const result = await this.pool.query(
      `SELECT id, finding_id, engagement_id, evidence_id, quality, note, created_at
       FROM finding_evidence_quality WHERE finding_id = $1`,
      [findingId],
    );
    return result.rows.map((row) => ({
      id: row.id,
      finding_id: row.finding_id,
      engagement_id: row.engagement_id,
      evidence_id: row.evidence_id,
      quality: row.quality,
      note: row.note,
      created_at: requireIso(row.created_at),
    }));
  }

  /** Part 7 §6: candidate creation with structured observed/expected fields. */
  async createCandidate(
    input: CreateFindingInput & {
      category: string;
      observedBehavior: string;
      expectedBehavior: string | null;
      targetRefs?: string[];
      affectedEndpoints?: string[];
      affectedIdentities?: string[];
      dedupKey?: string;
    },
  ): Promise<FindingRecord> {
    const id = generateId('FND');
    const result = await this.pool.query(
      `INSERT INTO findings (id, engagement_id, hypothesis_id, title, description, severity, status,
         evidence_ids, category, observed_behavior, expected_behavior, target_refs, affected_endpoints,
         affected_identities, dedup_key)
       VALUES ($1, $2, $3, $4, $5, $6, 'CANDIDATE', $7::jsonb, $8, $9, $10, $11::jsonb, $12::jsonb, $13::jsonb, $14)
       RETURNING ${FINDING_COLUMNS}`,
      [
        id,
        input.engagementId,
        input.hypothesisId,
        input.title,
        input.description,
        input.severity,
        JSON.stringify(input.evidenceIds ?? []),
        input.category,
        input.observedBehavior,
        input.expectedBehavior,
        JSON.stringify(input.targetRefs ?? []),
        JSON.stringify(input.affectedEndpoints ?? []),
        JSON.stringify(input.affectedIdentities ?? []),
        input.dedupKey ?? null,
      ],
    );
    return mapFinding(result.rows[0]!);
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
  retest_state: string | null;
  cvss_version: string | null;
  cvss_vector: string | null;
  cvss_base_score: number | null;
  cvss_temporal_score: number | null;
  cvss_environmental_score: number | null;
  cvss_base_severity: string | null;
  severity_source: string | null;
  dedup_key: string | null;
  duplicate_of: string | null;
  observed_behavior: string | null;
  expected_behavior: string | null;
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
    retest_state: (row.retest_state ?? 'NOT_RETESTED') as FindingRecord['retest_state'],
    cvss: row.cvss_vector
      ? {
          version: row.cvss_version ?? '3.1',
          vector: row.cvss_vector,
          base_score: row.cvss_base_score ?? 0,
          temporal_score: row.cvss_temporal_score,
          environmental_score: row.cvss_environmental_score,
          base_severity: row.cvss_base_severity ?? 'NONE',
        }
      : null,
    severity_source: (row.severity_source ?? 'CVSS_CALCULATOR') as FindingRecord['severity_source'],
    dedup_key: row.dedup_key,
    duplicate_of: row.duplicate_of,
    observed_behavior: row.observed_behavior,
    expected_behavior: row.expected_behavior,
    created_at: requireIso(row.created_at),
    updated_at: requireIso(row.updated_at),
  };
}
