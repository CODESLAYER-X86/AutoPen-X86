/**
 * Part 6 repositories — autonomous engine state, reasoning branches, CTF
 * challenge context/clues/flag conditions, human approvals and benchmark
 * runs (spec Part 6 §6, §29-§31, §48-§49, §58, §65, §79).
 *
 * Concurrency safety (§56): engine phase transitions use conditional UPDATE
 * guarded on the expected current phase + version (optimistic concurrency).
 * Approvals are decided exactly once under a `decision IS NULL` guard.
 */
import type { Pool } from 'pg';
import { generateId } from '@aegis/shared';
import type {
  ApprovalDecision,
  AutonomousMode,
  AutonomousPhase,
  BranchStatus,
  CtfClueSource,
  CtfClueStatus,
  CtfStatus,
  EngineRiskLevel,
  FlagConditionStatus,
  ReplanTrigger,
} from '@aegis/shared';
import type {
  AutonomousEngineStateRecord,
  BenchmarkRunRecord,
  CtfClueInterpretation,
  CtfContextRecord,
  CtfClueRecord,
  EngagementApprovalRecord,
  FlagConditionRecord,
  ReasoningBranchRecord,
} from '../types.js';
import { iso, requireIso, type RepoBase } from './util.js';

// -- Autonomous engine state (§6) -----------------------------------------------

const ENGINE_STATE_COLUMNS =
  `id, engagement_id, phase, mode, waiting_reason, strategy_summary, replan_count, cycle_count,
   last_replan_trigger, knowledge_query_repeats, engine_instance_id, stop_reason, started_at,
   finished_at, last_transition_at, created_at, version`;

export interface CreateEngineStateInput {
  engagementId: string;
  mode: AutonomousMode;
  strategySummary?: string | null;
}

export class AutonomousEngineStatesRepository implements RepoBase {
  constructor(readonly pool: Pool) {}

  async create(input: CreateEngineStateInput): Promise<AutonomousEngineStateRecord> {
    const id = generateId('AEN');
    const result = await this.pool.query(
      `INSERT INTO autonomous_engine_states
         (id, engagement_id, phase, mode, strategy_summary, started_at)
       VALUES ($1, $2, 'CREATED', $3, $4, now())
       ON CONFLICT (engagement_id) DO UPDATE SET id = EXCLUDED.id
       RETURNING ${ENGINE_STATE_COLUMNS}`,
      [id, input.engagementId, input.mode, input.strategySummary ?? null],
    );
    return mapEngineState(result.rows[0]!);
  }

  async findByEngagement(engagementId: string): Promise<AutonomousEngineStateRecord | null> {
    const result = await this.pool.query(
      `SELECT ${ENGINE_STATE_COLUMNS} FROM autonomous_engine_states WHERE engagement_id = $1`,
      [engagementId],
    );
    return result.rows[0] ? mapEngineState(result.rows[0]) : null;
  }

  /**
   * Conditional phase transition (§56 concurrency safety): the update only
   * applies while the row still holds `expectedPhase`; version bumps on every
   * successful write. Returns null when another writer won the race.
   */
  async transitionPhase(
    engagementId: string,
    expectedPhase: AutonomousPhase,
    toPhase: AutonomousPhase,
    options: {
      waitingReason?: string | null;
      strategySummary?: string | null;
      stopReason?: string | null;
      finish?: boolean;
    } = {},
  ): Promise<AutonomousEngineStateRecord | null> {
    const result = await this.pool.query(
      `UPDATE autonomous_engine_states
         SET phase = $3,
             waiting_reason = COALESCE($4, waiting_reason),
             strategy_summary = COALESCE($5, strategy_summary),
             stop_reason = $6,
             finished_at = CASE WHEN $7 THEN now() ELSE finished_at END,
             last_transition_at = now(),
             version = version + 1
       WHERE engagement_id = $1 AND phase = $2
       RETURNING ${ENGINE_STATE_COLUMNS}`,
      [
        engagementId,
        expectedPhase,
        toPhase,
        options.waitingReason ?? null,
        options.strategySummary ?? null,
        options.stopReason ?? null,
        options.finish ?? false,
      ],
    );
    return result.rows[0] ? mapEngineState(result.rows[0]) : null;
  }

  /** Unconditional transition used by control actions (pause/cancel/stop). */
  async forcePhase(
    engagementId: string,
    toPhase: AutonomousPhase,
    options: {
      waitingReason?: string | null;
      stopReason?: string | null;
      finish?: boolean;
    } = {},
  ): Promise<AutonomousEngineStateRecord | null> {
    const result = await this.pool.query(
      `UPDATE autonomous_engine_states
         SET phase = $2,
             waiting_reason = $3,
             stop_reason = $4,
             finished_at = CASE WHEN $5 THEN now() ELSE finished_at END,
             last_transition_at = now(),
             version = version + 1
       WHERE engagement_id = $1
       RETURNING ${ENGINE_STATE_COLUMNS}`,
      [engagementId, toPhase, options.waitingReason ?? null, options.stopReason ?? null, options.finish ?? false],
    );
    return result.rows[0] ? mapEngineState(result.rows[0]) : null;
  }

  async incrementCycle(engagementId: string): Promise<number> {
    const result = await this.pool.query(
      `UPDATE autonomous_engine_states
         SET cycle_count = cycle_count + 1, version = version + 1
       WHERE engagement_id = $1
       RETURNING cycle_count`,
      [engagementId],
    );
    return result.rows[0] ? (result.rows[0] as { cycle_count: number }).cycle_count : 0;
  }

  async recordReplan(engagementId: string, trigger: ReplanTrigger): Promise<number> {
    const result = await this.pool.query(
      `UPDATE autonomous_engine_states
         SET replan_count = replan_count + 1,
             last_replan_trigger = $2,
             last_transition_at = now(),
             version = version + 1
       WHERE engagement_id = $1
       RETURNING replan_count`,
      [engagementId, trigger],
    );
    return result.rows[0] ? (result.rows[0] as { replan_count: number }).replan_count : 0;
  }

  async setEngineInstance(engagementId: string, engineInstanceId: string | null): Promise<void> {
    await this.pool.query(
      `UPDATE autonomous_engine_states SET engine_instance_id = $2, version = version + 1
       WHERE engagement_id = $1`,
      [engagementId, engineInstanceId],
    );
  }

  async incrementKnowledgeQueryRepeats(engagementId: string): Promise<number> {
    const result = await this.pool.query(
      `UPDATE autonomous_engine_states SET knowledge_query_repeats = knowledge_query_repeats + 1
       WHERE engagement_id = $1 RETURNING knowledge_query_repeats`,
      [engagementId],
    );
    return result.rows[0] ? (result.rows[0] as { knowledge_query_repeats: number }).knowledge_query_repeats : 0;
  }

  async listRunnable(): Promise<AutonomousEngineStateRecord[]> {
    const result = await this.pool.query(
      `SELECT ${ENGINE_STATE_COLUMNS} FROM autonomous_engine_states
       WHERE phase NOT IN ('COMPLETED', 'STOPPED', 'CANCELLED', 'FAILED')
       ORDER BY created_at`,
    );
    return result.rows.map(mapEngineState);
  }
}

// -- Reasoning branches (§65-§66) ------------------------------------------------

const BRANCH_COLUMNS =
  `id, engagement_id, parent_branch_id, origin, origin_ref, focus, hypothesis_ids, score,
   status, pruned_reason, metadata, created_at, updated_at`;

export interface CreateBranchInput {
  engagementId: string;
  parentBranchId?: string | null;
  origin: string;
  originRef?: string | null;
  focus: string;
  hypothesisIds?: string[];
  score?: number;
  metadata?: Record<string, unknown>;
}

export class ReasoningBranchesRepository implements RepoBase {
  constructor(readonly pool: Pool) {}

  async create(input: CreateBranchInput): Promise<ReasoningBranchRecord> {
    const id = generateId('BRN');
    const result = await this.pool.query(
      `INSERT INTO reasoning_branches
         (id, engagement_id, parent_branch_id, origin, origin_ref, focus, hypothesis_ids, score, metadata)
       VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb, $8, $9::jsonb)
       RETURNING ${BRANCH_COLUMNS}`,
      [
        id,
        input.engagementId,
        input.parentBranchId ?? null,
        input.origin,
        input.originRef ?? null,
        input.focus,
        JSON.stringify(input.hypothesisIds ?? []),
        input.score ?? 0.5,
        JSON.stringify(input.metadata ?? {}),
      ],
    );
    return mapBranch(result.rows[0]!);
  }

  async findById(id: string): Promise<ReasoningBranchRecord | null> {
    const result = await this.pool.query(`SELECT ${BRANCH_COLUMNS} FROM reasoning_branches WHERE id = $1`, [id]);
    return result.rows[0] ? mapBranch(result.rows[0]) : null;
  }

  async findByIdAndEngagement(id: string, engagementId: string): Promise<ReasoningBranchRecord | null> {
    const result = await this.pool.query(
      `SELECT ${BRANCH_COLUMNS} FROM reasoning_branches WHERE id = $1 AND engagement_id = $2`,
      [id, engagementId],
    );
    return result.rows[0] ? mapBranch(result.rows[0]) : null;
  }

  async updateScore(id: string, score: number): Promise<void> {
    await this.pool.query(
      `UPDATE reasoning_branches SET score = $2, updated_at = now() WHERE id = $1`,
      [id, score],
    );
  }

  async attachHypothesis(id: string, hypothesisId: string): Promise<void> {
    await this.pool.query(
      `UPDATE reasoning_branches
         SET hypothesis_ids = (
           SELECT jsonb_agg(DISTINCT h) FROM jsonb_array_elements(hypothesis_ids || $2::jsonb) AS h
         ), updated_at = now()
       WHERE id = $1`,
      [id, JSON.stringify([hypothesisId])],
    );
  }

  async updateStatus(id: string, status: BranchStatus, prunedReason?: string | null): Promise<void> {
    await this.pool.query(
      `UPDATE reasoning_branches
         SET status = $2, pruned_reason = COALESCE($3, pruned_reason), updated_at = now()
       WHERE id = $1`,
      [id, status, prunedReason ?? null],
    );
  }

  async listByEngagement(engagementId: string, statuses?: readonly BranchStatus[]): Promise<ReasoningBranchRecord[]> {
    const filter =
      statuses && statuses.length > 0
        ? `AND status = ANY($2)`
        : '';
    const params: unknown[] = statuses && statuses.length > 0 ? [engagementId, statuses] : [engagementId];
    const result = await this.pool.query(
      `SELECT ${BRANCH_COLUMNS} FROM reasoning_branches WHERE engagement_id = $1 ${filter}
       ORDER BY score DESC, created_at`,
      params,
    );
    return result.rows.map(mapBranch);
  }

  async countByEngagement(engagementId: string, status: BranchStatus): Promise<number> {
    const result = await this.pool.query(
      `SELECT count(*)::int AS total FROM reasoning_branches WHERE engagement_id = $1 AND status = $2`,
      [engagementId, status],
    );
    return (result.rows[0] as { total: number }).total;
  }
}

// -- CTF context, clues and flag conditions (§29-§31) -----------------------------

const CTF_CONTEXT_COLUMNS =
  `id, engagement_id, title, description, hints, flag_format, status, flag_value, flag_evidence_id,
   solved_at, analysis, created_at, updated_at`;

export interface UpsertCtfContextInput {
  engagementId: string;
  title?: string;
  description?: string;
  hints?: string[];
  flagFormat?: string | null;
}

export class CtfContextsRepository implements RepoBase {
  constructor(readonly pool: Pool) {}

  async upsert(input: UpsertCtfContextInput): Promise<CtfContextRecord> {
    const id = generateId('CTF');
    // Stable per-engagement row: insert or update fields that are provided.
    const result = await this.pool.query(
      `INSERT INTO ctf_contexts (id, engagement_id, title, description, hints, flag_format)
       VALUES ($1, $2, $3, $4, $5::jsonb, $6)
       ON CONFLICT (engagement_id) DO UPDATE SET
         title = CASE WHEN EXCLUDED.title <> '' THEN EXCLUDED.title ELSE ctf_contexts.title END,
         description = CASE WHEN EXCLUDED.description <> '' THEN EXCLUDED.description ELSE ctf_contexts.description END,
         hints = CASE WHEN jsonb_array_length(EXCLUDED.hints) > 0 THEN EXCLUDED.hints ELSE ctf_contexts.hints END,
         flag_format = COALESCE(EXCLUDED.flag_format, ctf_contexts.flag_format),
         updated_at = now()
       RETURNING ${CTF_CONTEXT_COLUMNS}`,
      [id, input.engagementId, input.title ?? '', input.description ?? '', JSON.stringify(input.hints ?? []), input.flagFormat ?? null],
    );
    return mapCtfContext(result.rows[0]!);
  }

  async findByEngagement(engagementId: string): Promise<CtfContextRecord | null> {
    const result = await this.pool.query(
      `SELECT ${CTF_CONTEXT_COLUMNS} FROM ctf_contexts WHERE engagement_id = $1`,
      [engagementId],
    );
    return result.rows[0] ? mapCtfContext(result.rows[0]) : null;
  }

  async updateAnalysis(engagementId: string, analysis: Record<string, unknown>): Promise<void> {
    await this.pool.query(
      `UPDATE ctf_contexts SET analysis = $2::jsonb, updated_at = now() WHERE engagement_id = $1`,
      [engagementId, JSON.stringify(analysis)],
    );
  }

  async markSolved(
    engagementId: string,
    flagValue: string,
    flagEvidenceId: string | null,
    status: CtfStatus = 'SOLVED',
  ): Promise<CtfContextRecord | null> {
    const result = await this.pool.query(
      `UPDATE ctf_contexts
         SET status = $2,
             flag_value = CASE WHEN $2 = 'SOLVED' THEN $3 ELSE flag_value END,
             flag_evidence_id = CASE WHEN $2 = 'SOLVED' THEN $4 ELSE flag_evidence_id END,
             solved_at = CASE WHEN $2 = 'SOLVED' THEN now() ELSE solved_at END,
             updated_at = now()
       WHERE engagement_id = $1
       RETURNING ${CTF_CONTEXT_COLUMNS}`,
      [engagementId, status, flagValue, flagEvidenceId],
    );
    return result.rows[0] ? mapCtfContext(result.rows[0]) : null;
  }
}

const CTF_CLUE_COLUMNS =
  `id, engagement_id, source, text_content, interpretations, branch_id, status, dead_end_reason,
   created_at, updated_at`;

export interface CreateCtfClueInput {
  engagementId: string;
  source: CtfClueSource;
  text: string;
}

export class CtfCluesRepository implements RepoBase {
  constructor(readonly pool: Pool) {}

  async create(input: CreateCtfClueInput): Promise<CtfClueRecord> {
    const id = generateId('CLU');
    const result = await this.pool.query(
      `INSERT INTO ctf_clues (id, engagement_id, source, text_content)
       VALUES ($1, $2, $3, $4)
       RETURNING ${CTF_CLUE_COLUMNS}`,
      [id, input.engagementId, input.source, input.text],
    );
    return mapCtfClue(result.rows[0]!);
  }

  async listByEngagement(engagementId: string): Promise<CtfClueRecord[]> {
    const result = await this.pool.query(
      `SELECT ${CTF_CLUE_COLUMNS} FROM ctf_clues WHERE engagement_id = $1 ORDER BY created_at`,
      [engagementId],
    );
    return result.rows.map(mapCtfClue);
  }

  async recordInterpretations(
    id: string,
    interpretations: CtfClueInterpretation[],
    status: CtfClueStatus = 'INTERPRETED',
  ): Promise<void> {
    await this.pool.query(
      `UPDATE ctf_clues
         SET interpretations = $2::jsonb, status = $3, updated_at = now()
       WHERE id = $1`,
      [id, JSON.stringify(interpretations), status],
    );
  }

  async attachBranch(id: string, branchId: string): Promise<void> {
    await this.pool.query(
      `UPDATE ctf_clues SET branch_id = $2, updated_at = now() WHERE id = $1`,
      [id, branchId],
    );
  }

  async markStatus(id: string, status: CtfClueStatus, deadEndReason?: string | null): Promise<void> {
    await this.pool.query(
      `UPDATE ctf_clues
         SET status = $2, dead_end_reason = COALESCE($3, dead_end_reason), updated_at = now()
       WHERE id = $1`,
      [id, status, deadEndReason ?? null],
    );
  }
}

const FLAG_CONDITION_COLUMNS =
  `id, engagement_id, hypothesis_id, condition_description, pattern, evidence_ids, evidence_kinds,
   detected_value, status, detected_at, created_at, updated_at`;

export interface CreateFlagConditionInput {
  engagementId: string;
  hypothesisId?: string | null;
  description: string;
  pattern?: string | null;
}

export class FlagConditionsRepository implements RepoBase {
  constructor(readonly pool: Pool) {}

  async create(input: CreateFlagConditionInput): Promise<FlagConditionRecord> {
    const id = generateId('FLC');
    const result = await this.pool.query(
      `INSERT INTO flag_conditions (id, engagement_id, hypothesis_id, condition_description, pattern)
       VALUES ($1, $2, $3, $4, $5)
       RETURNING ${FLAG_CONDITION_COLUMNS}`,
      [id, input.engagementId, input.hypothesisId ?? null, input.description, input.pattern ?? null],
    );
    return mapFlagCondition(result.rows[0]!);
  }

  async listByEngagement(engagementId: string): Promise<FlagConditionRecord[]> {
    const result = await this.pool.query(
      `SELECT ${FLAG_CONDITION_COLUMNS} FROM flag_conditions WHERE engagement_id = $1 ORDER BY created_at`,
      [engagementId],
    );
    return result.rows.map(mapFlagCondition);
  }

  async markDetected(
    id: string,
    detectedValue: string,
    evidenceIds: string[],
    evidenceKinds: string[],
  ): Promise<void> {
    await this.pool.query(
      `UPDATE flag_conditions
         SET status = 'DETECTED', detected_value = $2, evidence_ids = $3::jsonb,
             evidence_kinds = $4::jsonb, detected_at = now(), updated_at = now()
       WHERE id = $1`,
      [id, detectedValue, JSON.stringify(evidenceIds), JSON.stringify(evidenceKinds)],
    );
  }

  async markStatus(id: string, status: FlagConditionStatus): Promise<void> {
    await this.pool.query(
      `UPDATE flag_conditions SET status = $2, updated_at = now() WHERE id = $1`,
      [id, status],
    );
  }
}

// -- Human approvals (§48-§49) ----------------------------------------------------

const APPROVAL_COLUMNS =
  `id, engagement_id, task_id, risk, action_summary, requested_by, decided_by, decision,
   decided_reason, metadata, created_at, decided_at`;

export interface CreateApprovalInput {
  engagementId: string;
  taskId: string | null;
  risk: EngineRiskLevel;
  actionSummary: string;
  requestedBy?: string;
  metadata?: Record<string, unknown>;
}

export class EngagementApprovalsRepository implements RepoBase {
  constructor(readonly pool: Pool) {}

  async create(input: CreateApprovalInput): Promise<EngagementApprovalRecord> {
    const id = generateId('APV');
    const result = await this.pool.query(
      `INSERT INTO engagement_approvals (id, engagement_id, task_id, risk, action_summary, requested_by, metadata)
       VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb)
       RETURNING ${APPROVAL_COLUMNS}`,
      [id, input.engagementId, input.taskId, input.risk, input.actionSummary, input.requestedBy ?? 'engine', JSON.stringify(input.metadata ?? {})],
    );
    return mapApproval(result.rows[0]!);
  }

  async findById(id: string): Promise<EngagementApprovalRecord | null> {
    const result = await this.pool.query(`SELECT ${APPROVAL_COLUMNS} FROM engagement_approvals WHERE id = $1`, [id]);
    return result.rows[0] ? mapApproval(result.rows[0]) : null;
  }

  async findByIdAndEngagement(id: string, engagementId: string): Promise<EngagementApprovalRecord | null> {
    const result = await this.pool.query(
      `SELECT ${APPROVAL_COLUMNS} FROM engagement_approvals WHERE id = $1 AND engagement_id = $2`,
      [id, engagementId],
    );
    return result.rows[0] ? mapApproval(result.rows[0]) : null;
  }

  /** Decide an approval exactly once (§49). Returns null if already decided. */
  async decide(
    id: string,
    decision: ApprovalDecision,
    decidedBy: string,
    reason?: string | null,
  ): Promise<EngagementApprovalRecord | null> {
    const result = await this.pool.query(
      `UPDATE engagement_approvals
         SET decision = $2, decided_by = $3, decided_reason = $4, decided_at = now()
       WHERE id = $1 AND decision IS NULL
       RETURNING ${APPROVAL_COLUMNS}`,
      [id, decision, decidedBy, reason ?? null],
    );
    return result.rows[0] ? mapApproval(result.rows[0]) : null;
  }

  async findPendingForTask(taskId: string): Promise<EngagementApprovalRecord | null> {
    const result = await this.pool.query(
      `SELECT ${APPROVAL_COLUMNS} FROM engagement_approvals
       WHERE task_id = $1 AND decision IS NULL ORDER BY created_at LIMIT 1`,
      [taskId],
    );
    return result.rows[0] ? mapApproval(result.rows[0]) : null;
  }

  async listByEngagement(
    engagementId: string,
    options: { pendingOnly?: boolean; limit?: number } = {},
  ): Promise<EngagementApprovalRecord[]> {
    const conditions = ['engagement_id = $1'];
    const params: unknown[] = [engagementId];
    if (options.pendingOnly) {
      conditions.push('decision IS NULL');
    }
    const limit = options.limit ?? 100;
    params.push(limit);
    const result = await this.pool.query(
      `SELECT ${APPROVAL_COLUMNS} FROM engagement_approvals
       WHERE ${conditions.join(' AND ')}
       ORDER BY created_at DESC LIMIT $${params.length}`,
      params,
    );
    return result.rows.map(mapApproval);
  }
}

// -- Benchmark runs (§79) ----------------------------------------------------------

const BENCHMARK_COLUMNS = 'id, benchmark, engagement_id, outcome, metrics, started_at, completed_at';

export class BenchmarkRunsRepository implements RepoBase {
  constructor(readonly pool: Pool) {}

  async create(benchmark: string, engagementId: string): Promise<BenchmarkRunRecord> {
    const id = generateId('BMK');
    const result = await this.pool.query(
      `INSERT INTO benchmark_runs (id, benchmark, engagement_id, outcome)
       VALUES ($1, $2, $3, 'COMPLETED')
       RETURNING ${BENCHMARK_COLUMNS}`,
      [id, benchmark, engagementId],
    );
    return mapBenchmarkRun(result.rows[0]!);
  }

  async complete(
    id: string,
    outcome: BenchmarkRunRecord['outcome'],
    metrics: Record<string, unknown>,
  ): Promise<BenchmarkRunRecord | null> {
    const result = await this.pool.query(
      `UPDATE benchmark_runs
         SET outcome = $2, metrics = $3::jsonb, completed_at = now()
       WHERE id = $1
       RETURNING ${BENCHMARK_COLUMNS}`,
      [id, outcome, JSON.stringify(metrics)],
    );
    return result.rows[0] ? mapBenchmarkRun(result.rows[0]) : null;
  }

  async listByBenchmark(benchmark: string, limit = 20): Promise<BenchmarkRunRecord[]> {
    const result = await this.pool.query(
      `SELECT ${BENCHMARK_COLUMNS} FROM benchmark_runs WHERE benchmark = $1
       ORDER BY started_at DESC LIMIT $2`,
      [benchmark, limit],
    );
    return result.rows.map(mapBenchmarkRun);
  }
}

// -- Row mappers --------------------------------------------------------------------

function mapEngineState(row: Record<string, unknown>): AutonomousEngineStateRecord {
  return {
    id: row.id as string,
    engagement_id: row.engagement_id as string,
    phase: row.phase as AutonomousPhase,
    mode: row.mode as AutonomousMode,
    waiting_reason: (row.waiting_reason as string | null) ?? null,
    strategy_summary: (row.strategy_summary as string | null) ?? null,
    replan_count: row.replan_count as number,
    cycle_count: row.cycle_count as number,
    last_replan_trigger: (row.last_replan_trigger as string | null) ?? null,
    knowledge_query_repeats: row.knowledge_query_repeats as number,
    engine_instance_id: (row.engine_instance_id as string | null) ?? null,
    stop_reason: (row.stop_reason as string | null) ?? null,
    started_at: iso(row.started_at as Date | string | null),
    finished_at: iso(row.finished_at as Date | string | null),
    last_transition_at: requireIso(row.last_transition_at as Date | string),
    created_at: requireIso(row.created_at as Date | string),
    version: row.version as number,
  };
}

function mapBranch(row: Record<string, unknown>): ReasoningBranchRecord {
  return {
    id: row.id as string,
    engagement_id: row.engagement_id as string,
    parent_branch_id: (row.parent_branch_id as string | null) ?? null,
    origin: row.origin as string,
    origin_ref: (row.origin_ref as string | null) ?? null,
    focus: row.focus as string,
    hypothesis_ids: (row.hypothesis_ids as string[]) ?? [],
    score: row.score as number,
    status: row.status as BranchStatus,
    pruned_reason: (row.pruned_reason as string | null) ?? null,
    metadata: (row.metadata as Record<string, unknown>) ?? {},
    created_at: requireIso(row.created_at as Date | string),
    updated_at: requireIso(row.updated_at as Date | string),
  };
}

function mapCtfContext(row: Record<string, unknown>): CtfContextRecord {
  return {
    id: row.id as string,
    engagement_id: row.engagement_id as string,
    title: row.title as string,
    description: row.description as string,
    hints: (row.hints as string[]) ?? [],
    flag_format: (row.flag_format as string | null) ?? null,
    status: row.status as CtfStatus,
    flag_value: (row.flag_value as string | null) ?? null,
    flag_evidence_id: (row.flag_evidence_id as string | null) ?? null,
    solved_at: iso(row.solved_at as Date | string | null),
    analysis: (row.analysis as Record<string, unknown>) ?? {},
    created_at: requireIso(row.created_at as Date | string),
    updated_at: requireIso(row.updated_at as Date | string),
  };
}

function mapCtfClue(row: Record<string, unknown>): CtfClueRecord {
  return {
    id: row.id as string,
    engagement_id: row.engagement_id as string,
    source: row.source as CtfClueSource,
    text_content: row.text_content as string,
    interpretations: (row.interpretations as CtfClueInterpretation[]) ?? [],
    branch_id: (row.branch_id as string | null) ?? null,
    status: row.status as CtfClueStatus,
    dead_end_reason: (row.dead_end_reason as string | null) ?? null,
    created_at: requireIso(row.created_at as Date | string),
    updated_at: requireIso(row.updated_at as Date | string),
  };
}

function mapFlagCondition(row: Record<string, unknown>): FlagConditionRecord {
  return {
    id: row.id as string,
    engagement_id: row.engagement_id as string,
    hypothesis_id: (row.hypothesis_id as string | null) ?? null,
    condition_description: row.condition_description as string,
    pattern: (row.pattern as string | null) ?? null,
    evidence_ids: (row.evidence_ids as string[]) ?? [],
    evidence_kinds: (row.evidence_kinds as string[]) ?? [],
    detected_value: (row.detected_value as string | null) ?? null,
    status: row.status as FlagConditionStatus,
    detected_at: iso(row.detected_at as Date | string | null),
    created_at: requireIso(row.created_at as Date | string),
    updated_at: requireIso(row.updated_at as Date | string),
  };
}

function mapApproval(row: Record<string, unknown>): EngagementApprovalRecord {
  return {
    id: row.id as string,
    engagement_id: row.engagement_id as string,
    task_id: (row.task_id as string | null) ?? null,
    risk: row.risk as EngineRiskLevel,
    action_summary: row.action_summary as string,
    requested_by: row.requested_by as string,
    decided_by: (row.decided_by as string | null) ?? null,
    decision: (row.decision as ApprovalDecision | null) ?? null,
    decided_reason: (row.decided_reason as string | null) ?? null,
    metadata: (row.metadata as Record<string, unknown>) ?? {},
    created_at: requireIso(row.created_at as Date | string),
    decided_at: iso(row.decided_at as Date | string | null),
  };
}

function mapBenchmarkRun(row: Record<string, unknown>): BenchmarkRunRecord {
  return {
    id: row.id as string,
    benchmark: row.benchmark as string,
    engagement_id: row.engagement_id as string,
    outcome: row.outcome as BenchmarkRunRecord['outcome'],
    metrics: (row.metrics as Record<string, unknown>) ?? {},
    started_at: requireIso(row.started_at as Date | string),
    completed_at: iso(row.completed_at as Date | string | null),
  };
}
