/**
 * Part 4 repositories — workflow/state, data-flow, differential and
 * verification records (spec §30-§35, §37-§41, §25-§28, §72-§74).
 */
import type { Pool } from 'pg';
import { generateId } from '@aegis/shared';
import type {
  CorrelationKind,
  TransitionObservationKind,
  VerificationCheckStatus,
  VerificationStatus,
  WorkflowStatus,
} from '@aegis/shared';
import type {
  DataFlowRecord,
  DifferentialResultRecord,
  VerificationAlternativeRecord,
  VerificationCheckRecord,
  VerificationRecord,
  WorkflowRecord,
  WorkflowStateRecord,
  WorkflowTransitionRecord,
} from '../types.js';
import { iso } from './util.js';

// -- Workflows (§30, §34-§35) ---------------------------------------------------

export class WorkflowsRepository {
  constructor(readonly pool: Pool) {}

  async findByName(engagementId: string, name: string): Promise<WorkflowRecord | null> {
    const result = await this.pool.query(
      'SELECT * FROM workflows WHERE engagement_id = $1 AND name = $2',
      [engagementId, name],
    );
    return result.rows[0] ? mapWorkflowRow(result.rows[0]) : null;
  }

  async findById(id: string): Promise<WorkflowRecord | null> {
    const result = await this.pool.query('SELECT * FROM workflows WHERE id = $1', [id]);
    return result.rows[0] ? mapWorkflowRow(result.rows[0]) : null;
  }

  async create(input: {
    engagementId: string;
    name: string;
    requiredIdentity: string | null;
    confidence: number;
  }): Promise<WorkflowRecord> {
    const id = generateId('WFL');
    const result = await this.pool.query(
      `INSERT INTO workflows (id, engagement_id, name, required_identity, confidence)
       VALUES ($1,$2,$3,$4,$5) RETURNING *`,
      [id, input.engagementId, input.name, input.requiredIdentity, input.confidence],
    );
    return mapWorkflowRow(result.rows[0]!);
  }

  async updateCounts(id: string, stateCount: number, transitionCount: number): Promise<void> {
    await this.pool.query(
      'UPDATE workflows SET state_count = $2, transition_count = $3, updated_at = now() WHERE id = $1',
      [id, stateCount, transitionCount],
    );
  }

  async updateStatus(id: string, status: WorkflowStatus): Promise<void> {
    await this.pool.query('UPDATE workflows SET status = $2, updated_at = now() WHERE id = $1', [id, status]);
  }

  async listByEngagement(engagementId: string): Promise<WorkflowRecord[]> {
    const result = await this.pool.query(
      'SELECT * FROM workflows WHERE engagement_id = $1 ORDER BY created_at',
      [engagementId],
    );
    return result.rows.map(mapWorkflowRow);
  }

  async countByEngagement(engagementId: string): Promise<number> {
    const result = await this.pool.query(
      'SELECT count(*)::int AS total FROM workflows WHERE engagement_id = $1',
      [engagementId],
    );
    return (result.rows[0] as { total: number }).total;
  }
}

export class WorkflowStatesRepository {
  constructor(readonly pool: Pool) {}

  async upsert(input: {
    workflowId: string;
    engagementId: string;
    name: string;
    detection: Record<string, unknown>;
    observed: boolean;
    confidence: number;
    at: string;
  }): Promise<WorkflowStateRecord> {
    const id = generateId('WST');
    const result = await this.pool.query(
      `INSERT INTO workflow_states (id, engagement_id, workflow_id, name, detection, observed, confidence, first_seen, last_seen)
       VALUES ($1,$2,$3,$4,$5::jsonb,$6,$7,$8,$8)
       ON CONFLICT (workflow_id, name) DO UPDATE SET last_seen = EXCLUDED.last_seen
       RETURNING *`,
      [id, input.engagementId, input.workflowId, input.name, JSON.stringify(input.detection), input.observed, input.confidence, input.at],
    );
    return mapWorkflowStateRow(result.rows[0]!);
  }

  async listByWorkflow(workflowId: string): Promise<WorkflowStateRecord[]> {
    const result = await this.pool.query(
      'SELECT * FROM workflow_states WHERE workflow_id = $1 ORDER BY first_seen',
      [workflowId],
    );
    return result.rows.map(mapWorkflowStateRow);
  }
}

export class WorkflowTransitionsRepository {
  constructor(readonly pool: Pool) {}

  async upsert(input: {
    workflowId: string;
    engagementId: string;
    fromStateId: string | null;
    toStateId: string;
    triggerEndpointId: string | null;
    triggerSummary: string;
    identityId: string | null;
    observationKind: TransitionObservationKind;
    confidence: number;
    evidenceIds: string[];
    fingerprint: string;
    at: string;
  }): Promise<{ record: WorkflowTransitionRecord; created: boolean }> {
    const id = generateId('WTR');
    const result = await this.pool.query(
      `INSERT INTO workflow_transitions (id, engagement_id, workflow_id, from_state_id, to_state_id,
         trigger_endpoint_id, trigger_summary, identity_id, observation_kind, confidence, evidence_ids, fingerprint, first_seen, last_seen)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11::jsonb,$12,$13,$13)
       ON CONFLICT (engagement_id, fingerprint) DO UPDATE SET
         occurrence_count = workflow_transitions.occurrence_count + 1,
         last_seen = EXCLUDED.last_seen
       RETURNING *`,
      [
        id,
        input.engagementId,
        input.workflowId,
        input.fromStateId,
        input.toStateId,
        input.triggerEndpointId,
        input.triggerSummary,
        input.identityId,
        input.observationKind,
        input.confidence,
        JSON.stringify(input.evidenceIds),
        input.fingerprint,
        input.at,
      ],
    );
    const row = result.rows[0]!;
    return { record: mapWorkflowTransitionRow(row), created: (row.id as string) === id };
  }

  async listByWorkflow(workflowId: string): Promise<WorkflowTransitionRecord[]> {
    const result = await this.pool.query(
      'SELECT * FROM workflow_transitions WHERE workflow_id = $1 ORDER BY first_seen',
      [workflowId],
    );
    return result.rows.map(mapWorkflowTransitionRow);
  }

  async listByEngagement(engagementId: string, limit = 500): Promise<WorkflowTransitionRecord[]> {
    const result = await this.pool.query(
      'SELECT * FROM workflow_transitions WHERE engagement_id = $1 ORDER BY first_seen LIMIT $2',
      [engagementId, Math.min(Math.max(limit, 1), 2000)],
    );
    return result.rows.map(mapWorkflowTransitionRow);
  }

  async listByIdentity(engagementId: string, identityId: string): Promise<WorkflowTransitionRecord[]> {
    const result = await this.pool.query(
      'SELECT * FROM workflow_transitions WHERE engagement_id = $1 AND identity_id = $2 ORDER BY first_seen',
      [engagementId, identityId],
    );
    return result.rows.map(mapWorkflowTransitionRow);
  }
}

// -- Data flows (§37-§41) ---------------------------------------------------------

export class DataFlowsRepository {
  constructor(readonly pool: Pool) {}

  async insert(input: {
    engagementId: string;
    source: Record<string, unknown>;
    transformations: string[];
    sink: Record<string, unknown>;
    correlation: CorrelationKind;
    confidence: number;
    evidenceIds: string[];
    fingerprint: string;
  }): Promise<{ record: DataFlowRecord; created: boolean }> {
    const id = generateId('DFL');
    const result = await this.pool.query(
      `INSERT INTO data_flows (id, engagement_id, source, transformations, sink, correlation, confidence, evidence_ids, fingerprint)
       VALUES ($1,$2,$3::jsonb,$4::jsonb,$5::jsonb,$6,$7,$8::jsonb,$9)
       ON CONFLICT (engagement_id, fingerprint) DO NOTHING
       RETURNING *`,
      [
        id,
        input.engagementId,
        JSON.stringify(input.source),
        JSON.stringify(input.transformations),
        JSON.stringify(input.sink),
        input.correlation,
        input.confidence,
        JSON.stringify(input.evidenceIds),
        input.fingerprint,
      ],
    );
    if (!result.rows[0]) {
      const existing = await this.findByFingerprint(input.engagementId, input.fingerprint);
      return { record: existing!, created: false };
    }
    return { record: mapDataFlowRow(result.rows[0]), created: true };
  }

  async findByFingerprint(engagementId: string, fingerprint: string): Promise<DataFlowRecord | null> {
    const result = await this.pool.query(
      'SELECT * FROM data_flows WHERE engagement_id = $1 AND fingerprint = $2',
      [engagementId, fingerprint],
    );
    return result.rows[0] ? mapDataFlowRow(result.rows[0]) : null;
  }

  async listByEngagement(engagementId: string, limit = 200): Promise<DataFlowRecord[]> {
    const result = await this.pool.query(
      'SELECT * FROM data_flows WHERE engagement_id = $1 ORDER BY created_at DESC LIMIT $2',
      [engagementId, Math.min(Math.max(limit, 1), 1000)],
    );
    return result.rows.map(mapDataFlowRow);
  }

  async countByEngagement(engagementId: string): Promise<number> {
    const result = await this.pool.query(
      'SELECT count(*)::int AS total FROM data_flows WHERE engagement_id = $1',
      [engagementId],
    );
    return (result.rows[0] as { total: number }).total;
  }
}

// -- Differential results (§25-§28) ----------------------------------------------------

export class DifferentialResultsRepository {
  constructor(readonly pool: Pool) {}

  async insert(input: {
    engagementId: string;
    testId: string | null;
    hypothesisId: string | null;
    baselineRequestId: string | null;
    candidateRequestId: string | null;
    baselineIdentity: string | null;
    candidateIdentity: string | null;
    summary: Record<string, unknown>;
    detail: Record<string, unknown>;
  }): Promise<DifferentialResultRecord> {
    const id = generateId('DFC');
    const result = await this.pool.query(
      `INSERT INTO differential_results (id, engagement_id, test_id, hypothesis_id, baseline_request_id,
         candidate_request_id, baseline_identity, candidate_identity, summary, detail)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9::jsonb,$10::jsonb)
       RETURNING *`,
      [
        id,
        input.engagementId,
        input.testId,
        input.hypothesisId,
        input.baselineRequestId,
        input.candidateRequestId,
        input.baselineIdentity,
        input.candidateIdentity,
        JSON.stringify(input.summary),
        JSON.stringify(input.detail),
      ],
    );
    return mapDifferentialRow(result.rows[0]!);
  }

  async listByEngagement(engagementId: string, limit = 100): Promise<DifferentialResultRecord[]> {
    const result = await this.pool.query(
      'SELECT * FROM differential_results WHERE engagement_id = $1 ORDER BY created_at DESC LIMIT $2',
      [engagementId, Math.min(Math.max(limit, 1), 500)],
    );
    return result.rows.map(mapDifferentialRow);
  }

  async listByHypothesis(hypothesisId: string): Promise<DifferentialResultRecord[]> {
    const result = await this.pool.query(
      'SELECT * FROM differential_results WHERE hypothesis_id = $1 ORDER BY created_at',
      [hypothesisId],
    );
    return result.rows.map(mapDifferentialRow);
  }

  async listByBaselineRequest(requestId: string): Promise<DifferentialResultRecord[]> {
    const result = await this.pool.query(
      'SELECT * FROM differential_results WHERE baseline_request_id = $1 OR candidate_request_id = $1 ORDER BY created_at',
      [requestId],
    );
    return result.rows.map(mapDifferentialRow);
  }

  async countByEngagement(engagementId: string): Promise<number> {
    const result = await this.pool.query(
      'SELECT count(*)::int AS total FROM differential_results WHERE engagement_id = $1',
      [engagementId],
    );
    return (result.rows[0] as { total: number }).total;
  }
}

// -- Verifications (§72-§74) -------------------------------------------------------------

export class VerificationsRepository {
  constructor(readonly pool: Pool) {}

  async create(input: {
    engagementId: string;
    hypothesisId: string | null;
    kind: string;
    alternatives: VerificationAlternativeRecord[];
    checklist: VerificationCheckRecord[];
    evidenceIds: string[];
  }): Promise<VerificationRecord> {
    const id = generateId('VER');
    const result = await this.pool.query(
      `INSERT INTO verifications (id, engagement_id, hypothesis_id, kind, alternatives, checklist, evidence_ids)
       VALUES ($1,$2,$3,$4,$5::jsonb,$6::jsonb,$7::jsonb)
       RETURNING *`,
      [
        id,
        input.engagementId,
        input.hypothesisId,
        input.kind,
        JSON.stringify(input.alternatives),
        JSON.stringify(input.checklist),
        JSON.stringify(input.evidenceIds),
      ],
    );
    return mapVerificationRow(result.rows[0]!);
  }

  async findById(id: string): Promise<VerificationRecord | null> {
    const result = await this.pool.query('SELECT * FROM verifications WHERE id = $1', [id]);
    return result.rows[0] ? mapVerificationRow(result.rows[0]) : null;
  }

  async complete(
    id: string,
    input: {
      status: VerificationStatus;
      result: Record<string, unknown>;
      checklist: VerificationCheckRecord[];
      evidenceIds: string[];
    },
  ): Promise<VerificationRecord> {
    const result = await this.pool.query(
      `UPDATE verifications SET
         status = $2, result = $3::jsonb, checklist = $4::jsonb, evidence_ids = $5::jsonb,
         completed_at = now()
       WHERE id = $1 RETURNING *`,
      [id, input.status, JSON.stringify(input.result), JSON.stringify(input.checklist), JSON.stringify(input.evidenceIds)],
    );
    return mapVerificationRow(result.rows[0]!);
  }

  async listByEngagement(engagementId: string, limit = 100): Promise<VerificationRecord[]> {
    const result = await this.pool.query(
      'SELECT * FROM verifications WHERE engagement_id = $1 ORDER BY created_at DESC LIMIT $2',
      [engagementId, Math.min(Math.max(limit, 1), 500)],
    );
    return result.rows.map(mapVerificationRow);
  }

  async listByHypothesis(hypothesisId: string): Promise<VerificationRecord[]> {
    const result = await this.pool.query(
      'SELECT * FROM verifications WHERE hypothesis_id = $1 ORDER BY created_at',
      [hypothesisId],
    );
    return result.rows.map(mapVerificationRow);
  }

  async countByEngagement(engagementId: string): Promise<number> {
    const result = await this.pool.query(
      'SELECT count(*)::int AS total FROM verifications WHERE engagement_id = $1',
      [engagementId],
    );
    return (result.rows[0] as { total: number }).total;
  }
}

// -- Row mappers ---------------------------------------------------------------------------

function mapWorkflowRow(row: Record<string, unknown>): WorkflowRecord {
  return {
    id: row.id as string,
    engagement_id: row.engagement_id as string,
    name: row.name as string,
    status: row.status as WorkflowStatus,
    required_identity: (row.required_identity as string | null) ?? null,
    confidence: Number(row.confidence),
    state_count: row.state_count as number,
    transition_count: row.transition_count as number,
    evidence_ids: (row.evidence_ids as string[]) ?? [],
    created_at: iso(row.created_at as Date) ?? '',
    updated_at: iso(row.updated_at as Date) ?? '',
  };
}

function mapWorkflowStateRow(row: Record<string, unknown>): WorkflowStateRecord {
  return {
    id: row.id as string,
    engagement_id: row.engagement_id as string,
    workflow_id: row.workflow_id as string,
    name: row.name as string,
    detection: (row.detection as Record<string, unknown>) ?? {},
    observed: Boolean(row.observed),
    confidence: Number(row.confidence),
    first_seen: iso(row.first_seen as Date) ?? '',
    last_seen: iso(row.last_seen as Date) ?? '',
  };
}

function mapWorkflowTransitionRow(row: Record<string, unknown>): WorkflowTransitionRecord {
  return {
    id: row.id as string,
    engagement_id: row.engagement_id as string,
    workflow_id: row.workflow_id as string,
    from_state_id: (row.from_state_id as string | null) ?? null,
    to_state_id: row.to_state_id as string,
    trigger_endpoint_id: (row.trigger_endpoint_id as string | null) ?? null,
    trigger_summary: row.trigger_summary as string,
    identity_id: (row.identity_id as string | null) ?? null,
    observation_kind: row.observation_kind as TransitionObservationKind,
    confidence: Number(row.confidence),
    occurrence_count: row.occurrence_count as number,
    evidence_ids: (row.evidence_ids as string[]) ?? [],
    fingerprint: row.fingerprint as string,
    first_seen: iso(row.first_seen as Date) ?? '',
    last_seen: iso(row.last_seen as Date) ?? '',
  };
}

function mapDataFlowRow(row: Record<string, unknown>): DataFlowRecord {
  return {
    id: row.id as string,
    engagement_id: row.engagement_id as string,
    source: (row.source as Record<string, unknown>) ?? {},
    transformations: (row.transformations as string[]) ?? [],
    sink: (row.sink as Record<string, unknown>) ?? {},
    correlation: row.correlation as CorrelationKind,
    confidence: Number(row.confidence),
    evidence_ids: (row.evidence_ids as string[]) ?? [],
    fingerprint: row.fingerprint as string,
    created_at: iso(row.created_at as Date) ?? '',
  };
}

function mapDifferentialRow(row: Record<string, unknown>): DifferentialResultRecord {
  return {
    id: row.id as string,
    engagement_id: row.engagement_id as string,
    test_id: (row.test_id as string | null) ?? null,
    hypothesis_id: (row.hypothesis_id as string | null) ?? null,
    baseline_request_id: (row.baseline_request_id as string | null) ?? null,
    candidate_request_id: (row.candidate_request_id as string | null) ?? null,
    baseline_identity: (row.baseline_identity as string | null) ?? null,
    candidate_identity: (row.candidate_identity as string | null) ?? null,
    summary: (row.summary as Record<string, unknown>) ?? {},
    detail: (row.detail as Record<string, unknown>) ?? {},
    created_at: iso(row.created_at as Date) ?? '',
  };
}

function mapVerificationRow(row: Record<string, unknown>): VerificationRecord {
  return {
    id: row.id as string,
    engagement_id: row.engagement_id as string,
    hypothesis_id: (row.hypothesis_id as string | null) ?? null,
    kind: row.kind as string,
    alternatives: (row.alternatives as VerificationAlternativeRecord[]) ?? [],
    checklist: (row.checklist as VerificationCheckRecord[]) ?? [],
    status: row.status as VerificationStatus,
    result: (row.result as Record<string, unknown>) ?? {},
    evidence_ids: (row.evidence_ids as string[]) ?? [],
    created_at: iso(row.created_at as Date) ?? '',
    completed_at: iso(row.completed_at as Date | null),
  };
}

export type { VerificationCheckStatus };
export type { VerificationStatus };
