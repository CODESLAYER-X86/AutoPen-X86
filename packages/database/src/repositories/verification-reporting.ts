/**
 * Part 7 repositories — verification planning/results, severity assessments,
 * human reviews, retests, reports/exports and the evaluation database
 * (spec Part 7 §8-§14, §17-§18, §37-§38, §59, §63-§66).
 *
 * Findings lifecycle transitions and CVSS persistence live on the existing
 * FindingsRepository (guarded updates + audit rows). These repositories are
 * engagement-scoped: every read filters on engagement_id (cross-engagement
 * access is impossible by construction).
 */
import type { Pool } from 'pg';
import { generateId } from '@aegis/shared';
import type {
  AlternativeExplanationRecord,
  EvaluationEventRecord,
  EvaluationExpectedFindingRecord,
  EvaluationMetricRecord,
  EvaluationObservedFindingRecord,
  EvaluationRunRecord,
  EvaluationScenarioRecord,
  FindingReviewRecord,
  RegressionCheckRecord,
  ReportClaimRecord,
  ReportExportRecord,
  ReportRecord,
  ReportValidationIssueRecord,
  ReproductionPlanRecord,
  RetestRecord,
  SeverityAssessmentRecord,
  VerificationPlanRecord,
  VerificationResultRecord,
} from '../types.js';
import { iso, requireIso, type RepoBase } from './util.js';

// -- Verification plans (§8) ---------------------------------------------------

export interface CreateVerificationPlanInput {
  engagementId: string;
  findingId: string;
  strategies: string[];
  controls: string[];
  expectedResult: Record<string, unknown>;
  requiredEvidence: Array<{ kind: string; description: string; required: boolean }>;
  sufficiency: {
    sufficient: boolean;
    missing: string[];
    dimensions: Record<string, boolean>;
    note: string;
  };
}

const PLAN_COLUMNS =
  `id, engagement_id, finding_id, strategies, controls, expected_result, required_evidence,
   sufficiency, status, result_id, error, created_at, completed_at`;

export class VerificationPlansRepository implements RepoBase {
  constructor(readonly pool: Pool) {}

  async create(input: CreateVerificationPlanInput): Promise<VerificationPlanRecord> {
    const id = generateId('VRP');
    const result = await this.pool.query(
      `INSERT INTO verification_plans (id, engagement_id, finding_id, strategies, controls,
         expected_result, required_evidence, sufficiency)
       VALUES ($1, $2, $3, $4::jsonb, $5::jsonb, $6::jsonb, $7::jsonb, $8::jsonb)
       RETURNING ${PLAN_COLUMNS}`,
      [
        id,
        input.engagementId,
        input.findingId,
        JSON.stringify(input.strategies),
        JSON.stringify(input.controls),
        JSON.stringify(input.expectedResult),
        JSON.stringify(input.requiredEvidence),
        JSON.stringify(input.sufficiency),
      ],
    );
    return mapPlan(result.rows[0]!);
  }

  async findByIdAndEngagement(id: string, engagementId: string): Promise<VerificationPlanRecord | null> {
    const result = await this.pool.query(
      `SELECT ${PLAN_COLUMNS} FROM verification_plans WHERE id = $1 AND engagement_id = $2 LIMIT 1`,
      [id, engagementId],
    );
    return result.rows[0] ? mapPlan(result.rows[0]) : null;
  }

  async findLatestForFinding(engagementId: string, findingId: string): Promise<VerificationPlanRecord | null> {
    const result = await this.pool.query(
      `SELECT ${PLAN_COLUMNS} FROM verification_plans
       WHERE engagement_id = $1 AND finding_id = $2 ORDER BY created_at DESC LIMIT 1`,
      [engagementId, findingId],
    );
    return result.rows[0] ? mapPlan(result.rows[0]) : null;
  }

  async listByEngagement(engagementId: string, limit = 100): Promise<VerificationPlanRecord[]> {
    const result = await this.pool.query(
      `SELECT ${PLAN_COLUMNS} FROM verification_plans WHERE engagement_id = $1
       ORDER BY created_at DESC LIMIT $2`,
      [engagementId, Math.min(Math.max(limit, 1), 500)],
    );
    return result.rows.map(mapPlan);
  }

  async markExecuting(id: string): Promise<void> {
    await this.pool.query(`UPDATE verification_plans SET status = 'EXECUTING' WHERE id = $1`, [id]);
  }

  async complete(id: string, resultId: string): Promise<void> {
    await this.pool.query(
      `UPDATE verification_plans SET status = 'COMPLETED', result_id = $2, completed_at = now()
       WHERE id = $1`,
      [id, resultId],
    );
  }

  async fail(id: string, error: string): Promise<void> {
    await this.pool.query(
      `UPDATE verification_plans SET status = 'FAILED', error = $2, completed_at = now() WHERE id = $1`,
      [id, error],
    );
  }
}

function mapPlan(row: Record<string, unknown>): VerificationPlanRecord {
  return {
    id: row.id as string,
    engagement_id: row.engagement_id as string,
    finding_id: row.finding_id as string,
    strategies: (row.strategies as string[]) ?? [],
    controls: (row.controls as string[]) ?? [],
    expected_result: (row.expected_result as Record<string, unknown>) ?? {},
    required_evidence:
      (row.required_evidence as Array<{ kind: string; description: string; required: boolean }>) ?? [],
    sufficiency: row.sufficiency as VerificationPlanRecord['sufficiency'],
    status: row.status as VerificationPlanRecord['status'],
    result_id: (row.result_id as string | null) ?? null,
    error: (row.error as string | null) ?? null,
    created_at: requireIso(row.created_at as Date),
    completed_at: iso(row.completed_at as Date | null),
  };
}

// -- Verification results (§14) ------------------------------------------------

const RESULT_COLUMNS =
  `id, engagement_id, finding_id, plan_id, status, confidence, supporting_evidence_ids,
   contradictory_evidence_ids, reproduced, alternative_explanations, reasoning_summary, completed_at`;

export interface CreateVerificationResultInput {
  engagementId: string;
  findingId: string;
  planId: string;
  status: 'VERIFIED' | 'REJECTED' | 'INCONCLUSIVE';
  confidence: number;
  supportingEvidenceIds: string[];
  contradictoryEvidenceIds: string[];
  reproduced: boolean;
  alternativeExplanations: AlternativeExplanationRecord[];
  reasoningSummary: string;
}

export class VerificationResultsRepository implements RepoBase {
  constructor(readonly pool: Pool) {}

  async create(input: CreateVerificationResultInput): Promise<VerificationResultRecord> {
    const id = generateId('VRR');
    const result = await this.pool.query(
      `INSERT INTO verification_results (id, engagement_id, finding_id, plan_id, status, confidence,
         supporting_evidence_ids, contradictory_evidence_ids, reproduced, alternative_explanations,
         reasoning_summary)
       VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb, $8::jsonb, $9, $10::jsonb, $11)
       RETURNING ${RESULT_COLUMNS}`,
      [
        id,
        input.engagementId,
        input.findingId,
        input.planId,
        input.status,
        input.confidence,
        JSON.stringify(input.supportingEvidenceIds),
        JSON.stringify(input.contradictoryEvidenceIds),
        input.reproduced,
        JSON.stringify(input.alternativeExplanations),
        input.reasoningSummary,
      ],
    );
    return mapResult(result.rows[0]!);
  }

  async findByIdAndEngagement(id: string, engagementId: string): Promise<VerificationResultRecord | null> {
    const result = await this.pool.query(
      `SELECT ${RESULT_COLUMNS} FROM verification_results WHERE id = $1 AND engagement_id = $2 LIMIT 1`,
      [id, engagementId],
    );
    return result.rows[0] ? mapResult(result.rows[0]) : null;
  }

  async listByFinding(engagementId: string, findingId: string): Promise<VerificationResultRecord[]> {
    const result = await this.pool.query(
      `SELECT ${RESULT_COLUMNS} FROM verification_results
       WHERE engagement_id = $1 AND finding_id = $2 ORDER BY completed_at DESC`,
      [engagementId, findingId],
    );
    return result.rows.map(mapResult);
  }

  async listByEngagement(engagementId: string, limit = 200): Promise<VerificationResultRecord[]> {
    const result = await this.pool.query(
      `SELECT ${RESULT_COLUMNS} FROM verification_results WHERE engagement_id = $1
       ORDER BY completed_at DESC LIMIT $2`,
      [engagementId, Math.min(Math.max(limit, 1), 500)],
    );
    return result.rows.map(mapResult);
  }
}

function mapResult(row: Record<string, unknown>): VerificationResultRecord {
  return {
    id: row.id as string,
    engagement_id: row.engagement_id as string,
    finding_id: row.finding_id as string,
    plan_id: row.plan_id as string,
    status: row.status as VerificationResultRecord['status'],
    confidence: row.confidence as number,
    supporting_evidence_ids: (row.supporting_evidence_ids as string[]) ?? [],
    contradictory_evidence_ids: (row.contradictory_evidence_ids as string[]) ?? [],
    reproduced: row.reproduced as boolean,
    alternative_explanations:
      (row.alternative_explanations as AlternativeExplanationRecord[]) ?? [],
    reasoning_summary: row.reasoning_summary as string,
    completed_at: requireIso(row.completed_at as Date),
  };
}

// -- Reproduction plans (§12) ---------------------------------------------------

export class ReproductionPlansRepository implements RepoBase {
  constructor(readonly pool: Pool) {}

  async create(
    engagementId: string,
    findingId: string,
    prerequisites: string[],
    steps: Array<{ kind: string; reference: string; description: string }>,
    expectedSignals: Array<{ signal: string; source: string }>,
  ): Promise<ReproductionPlanRecord> {
    const id = generateId('RPN');
    const result = await this.pool.query(
      `INSERT INTO reproduction_plans (id, engagement_id, finding_id, prerequisites, steps, expected_signals)
       VALUES ($1, $2, $3, $4::jsonb, $5::jsonb, $6::jsonb)
       RETURNING id, engagement_id, finding_id, prerequisites, steps, expected_signals, created_at`,
      [id, engagementId, findingId, JSON.stringify(prerequisites), JSON.stringify(steps), JSON.stringify(expectedSignals)],
    );
    const row = result.rows[0]!;
    return {
      id: row.id,
      engagement_id: row.engagement_id,
      finding_id: row.finding_id,
      prerequisites: row.prerequisites ?? [],
      steps: row.steps ?? [],
      expected_signals: row.expected_signals ?? [],
      created_at: requireIso(row.created_at),
    };
  }

  async findLatestForFinding(engagementId: string, findingId: string): Promise<ReproductionPlanRecord | null> {
    const result = await this.pool.query(
      `SELECT id, engagement_id, finding_id, prerequisites, steps, expected_signals, created_at
       FROM reproduction_plans WHERE engagement_id = $1 AND finding_id = $2
       ORDER BY created_at DESC LIMIT 1`,
      [engagementId, findingId],
    );
    const row = result.rows[0];
    if (!row) return null;
    return {
      id: row.id,
      engagement_id: row.engagement_id,
      finding_id: row.finding_id,
      prerequisites: row.prerequisites ?? [],
      steps: row.steps ?? [],
      expected_signals: row.expected_signals ?? [],
      created_at: requireIso(row.created_at),
    };
  }
}

// -- Severity assessments (§17-§18) ----------------------------------------------

export class SeverityAssessmentsRepository implements RepoBase {
  constructor(readonly pool: Pool) {}

  async create(
    engagementId: string,
    findingId: string,
    input: Record<string, unknown>,
    severity: string,
    cvss: SeverityAssessmentRecord['cvss'],
    source: 'CVSS_CALCULATOR' | 'HUMAN_OVERRIDE' = 'CVSS_CALCULATOR',
  ): Promise<SeverityAssessmentRecord> {
    const id = generateId('SVS');
    const result = await this.pool.query(
      `INSERT INTO severity_assessments (id, engagement_id, finding_id, input, severity, source, cvss)
       VALUES ($1, $2, $3, $4::jsonb, $5, $6, $7::jsonb)
       RETURNING id, engagement_id, finding_id, input, severity, source, cvss, created_at`,
      [id, engagementId, findingId, JSON.stringify(input), severity, source, JSON.stringify(cvss)],
    );
    const row = result.rows[0]!;
    return {
      id: row.id,
      engagement_id: row.engagement_id,
      finding_id: row.finding_id,
      input: row.input,
      severity: row.severity,
      source: row.source,
      cvss: row.cvss,
      created_at: requireIso(row.created_at),
    };
  }

  async listByFinding(engagementId: string, findingId: string): Promise<SeverityAssessmentRecord[]> {
    const result = await this.pool.query(
      `SELECT id, engagement_id, finding_id, input, severity, source, cvss, created_at
       FROM severity_assessments WHERE engagement_id = $1 AND finding_id = $2
       ORDER BY created_at DESC`,
      [engagementId, findingId],
    );
    return result.rows.map(
      (row): SeverityAssessmentRecord => ({
        id: row.id,
        engagement_id: row.engagement_id,
        finding_id: row.finding_id,
        input: row.input,
        severity: row.severity,
        source: row.source,
        cvss: row.cvss,
        created_at: requireIso(row.created_at),
      }),
    );
  }
}

// -- Human reviews (§67-§68) ----------------------------------------------------

export interface CreateFindingReviewInput {
  engagementId: string;
  findingId: string;
  agentStatus: string;
  agentConfidence: number | null;
  decision: string;
  reviewer: string;
  reason: string;
  agentHumanDisagreement: boolean;
  resultingStatus: string;
  metadata?: Record<string, unknown>;
}

export class FindingReviewsRepository implements RepoBase {
  constructor(readonly pool: Pool) {}

  async create(input: CreateFindingReviewInput): Promise<FindingReviewRecord> {
    const id = generateId('RVW');
    const result = await this.pool.query(
      `INSERT INTO finding_reviews (id, engagement_id, finding_id, agent_status, agent_confidence,
         decision, reviewer, reason, agent_human_disagreement, resulting_status, metadata)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11::jsonb)
       RETURNING id, engagement_id, finding_id, agent_status, agent_confidence, decision, reviewer,
         reason, agent_human_disagreement, resulting_status, metadata, created_at`,
      [
        id,
        input.engagementId,
        input.findingId,
        input.agentStatus,
        input.agentConfidence,
        input.decision,
        input.reviewer,
        input.reason,
        input.agentHumanDisagreement,
        input.resultingStatus,
        JSON.stringify(input.metadata ?? {}),
      ],
    );
    const row = result.rows[0]!;
    return {
      id: row.id,
      engagement_id: row.engagement_id,
      finding_id: row.finding_id,
      agent_status: row.agent_status,
      agent_confidence: row.agent_confidence,
      decision: row.decision,
      reviewer: row.reviewer,
      reason: row.reason,
      agent_human_disagreement: row.agent_human_disagreement,
      resulting_status: row.resulting_status,
      metadata: row.metadata ?? {},
      created_at: requireIso(row.created_at),
    };
  }

  async listByFinding(engagementId: string, findingId: string): Promise<FindingReviewRecord[]> {
    const result = await this.pool.query(
      `SELECT id, engagement_id, finding_id, agent_status, agent_confidence, decision, reviewer, reason,
         agent_human_disagreement, resulting_status, metadata, created_at
       FROM finding_reviews WHERE engagement_id = $1 AND finding_id = $2 ORDER BY created_at DESC`,
      [engagementId, findingId],
    );
    return result.rows.map(
      (row): FindingReviewRecord => ({
        id: row.id,
        engagement_id: row.engagement_id,
        finding_id: row.finding_id,
        agent_status: row.agent_status,
        agent_confidence: row.agent_confidence,
        decision: row.decision,
        reviewer: row.reviewer,
        reason: row.reason,
        agent_human_disagreement: row.agent_human_disagreement,
        resulting_status: row.resulting_status,
        metadata: row.metadata ?? {},
        created_at: requireIso(row.created_at),
      }),
    );
  }

  async listByEngagement(engagementId: string, limit = 200): Promise<FindingReviewRecord[]> {
    const result = await this.pool.query(
      `SELECT id, engagement_id, finding_id, agent_status, agent_confidence, decision, reviewer, reason,
         agent_human_disagreement, resulting_status, metadata, created_at
       FROM finding_reviews WHERE engagement_id = $1 ORDER BY created_at DESC LIMIT $2`,
      [engagementId, Math.min(Math.max(limit, 1), 500)],
    );
    return result.rows.map(
      (row): FindingReviewRecord => ({
        id: row.id,
        engagement_id: row.engagement_id,
        finding_id: row.finding_id,
        agent_status: row.agent_status,
        agent_confidence: row.agent_confidence,
        decision: row.decision,
        reviewer: row.reviewer,
        reason: row.reason,
        agent_human_disagreement: row.agent_human_disagreement,
        resulting_status: row.resulting_status,
        metadata: row.metadata ?? {},
        created_at: requireIso(row.created_at),
      }),
    );
  }
}

// -- Retests (§37-§38) -----------------------------------------------------------

export class RetestsRepository implements RepoBase {
  constructor(readonly pool: Pool) {}

  async open(engagementId: string, findingId: string, requestedBy: string, note: string | null): Promise<RetestRecord> {
    const id = generateId('RTS');
    const result = await this.pool.query(
      `INSERT INTO retests (id, engagement_id, finding_id, status, requested_by, note)
       VALUES ($1, $2, $3, 'OPEN', $4, $5)
       RETURNING id, engagement_id, finding_id, status, outcome, verification_id, note, requested_by,
         requested_at, completed_at`,
      [id, engagementId, findingId, requestedBy, note],
    );
    return mapRetest(result.rows[0]!);
  }

  async complete(
    id: string,
    engagementId: string,
    outcome: 'FIXED' | 'PARTIALLY_FIXED' | 'STILL_PRESENT',
    verificationId: string | null,
    note: string | null,
  ): Promise<RetestRecord | null> {
    const result = await this.pool.query(
      `UPDATE retests SET outcome = $3, status = $3, verification_id = $4, note = COALESCE($5, note),
         completed_at = now()
       WHERE id = $1 AND engagement_id = $2 AND status = 'OPEN'
       RETURNING id, engagement_id, finding_id, status, outcome, verification_id, note, requested_by,
         requested_at, completed_at`,
      [id, engagementId, outcome, verificationId, note],
    );
    return result.rows[0] ? mapRetest(result.rows[0]) : null;
  }

  async findOpen(engagementId: string, findingId: string): Promise<RetestRecord | null> {
    const result = await this.pool.query(
      `SELECT id, engagement_id, finding_id, status, outcome, verification_id, note, requested_by,
         requested_at, completed_at
       FROM retests WHERE engagement_id = $1 AND finding_id = $2 AND status = 'OPEN'
       ORDER BY requested_at DESC LIMIT 1`,
      [engagementId, findingId],
    );
    return result.rows[0] ? mapRetest(result.rows[0]) : null;
  }

  async listByEngagement(engagementId: string, limit = 200): Promise<RetestRecord[]> {
    const result = await this.pool.query(
      `SELECT id, engagement_id, finding_id, status, outcome, verification_id, note, requested_by,
         requested_at, completed_at
       FROM retests WHERE engagement_id = $1 ORDER BY requested_at DESC LIMIT $2`,
      [engagementId, Math.min(Math.max(limit, 1), 500)],
    );
    return result.rows.map(mapRetest);
  }
}

function mapRetest(row: Record<string, unknown>): RetestRecord {
  return {
    id: row.id as string,
    engagement_id: row.engagement_id as string,
    finding_id: row.finding_id as string,
    status: row.status as RetestRecord['status'],
    outcome: (row.outcome as RetestRecord['outcome']) ?? null,
    verification_id: (row.verification_id as string | null) ?? null,
    note: (row.note as string | null) ?? null,
    requested_by: row.requested_by as string,
    requested_at: requireIso(row.requested_at as Date),
    completed_at: iso(row.completed_at as Date | null),
  };
}

// -- Reports (§25, §63-§66) --------------------------------------------------------

const REPORT_COLUMNS =
  `id, engagement_id, type, status, version, title, manifest, claims, validation_issues, content,
   redactions, generated_by, generated_at`;

export interface CreateReportInput {
  engagementId: string;
  type: ReportRecord['type'];
  version: number;
  title: string;
  claims: ReportClaimRecord[];
  content: Record<string, unknown>;
  redactions: Array<{ location: string; rule: string }>;
  generatedBy: string;
}

export class ReportsRepository implements RepoBase {
  constructor(readonly pool: Pool) {}

  async create(input: CreateReportInput): Promise<ReportRecord> {
    const id = generateId('RPR');
    const result = await this.pool.query(
      `INSERT INTO reports (id, engagement_id, type, status, version, title, claims, content, redactions, generated_by)
       VALUES ($1, $2, $3, 'GENERATING', $4, $5, $6::jsonb, $7::jsonb, $8::jsonb, $9)
       RETURNING ${REPORT_COLUMNS}`,
      [
        id,
        input.engagementId,
        input.type,
        input.version,
        input.title,
        JSON.stringify(input.claims),
        JSON.stringify(input.content),
        JSON.stringify(input.redactions),
        input.generatedBy,
      ],
    );
    return mapReport(result.rows[0]!);
  }

  async findByIdAndEngagement(id: string, engagementId: string): Promise<ReportRecord | null> {
    const result = await this.pool.query(
      `SELECT ${REPORT_COLUMNS} FROM reports WHERE id = $1 AND engagement_id = $2 LIMIT 1`,
      [id, engagementId],
    );
    return result.rows[0] ? mapReport(result.rows[0]) : null;
  }

  async listByEngagement(engagementId: string, limit = 100): Promise<ReportRecord[]> {
    const result = await this.pool.query(
      `SELECT ${REPORT_COLUMNS} FROM reports WHERE engagement_id = $1
       ORDER BY generated_at DESC LIMIT $2`,
      [engagementId, Math.min(Math.max(limit, 1), 500)],
    );
    return result.rows.map(mapReport);
  }

  async markValidated(id: string, manifest: ReportRecord['manifest'], issues: ReportValidationIssueRecord[]): Promise<ReportRecord | null> {
    const result = await this.pool.query(
      `UPDATE reports SET status = 'VALIDATED', manifest = $2::jsonb, validation_issues = $3::jsonb
       WHERE id = $1 RETURNING ${REPORT_COLUMNS}`,
      [id, JSON.stringify(manifest), JSON.stringify(issues)],
    );
    return result.rows[0] ? mapReport(result.rows[0]) : null;
  }

  async markRejected(id: string, issues: ReportValidationIssueRecord[]): Promise<ReportRecord | null> {
    const result = await this.pool.query(
      `UPDATE reports SET status = 'REJECTED', validation_issues = $2::jsonb
       WHERE id = $1 RETURNING ${REPORT_COLUMNS}`,
      [id, JSON.stringify(issues)],
    );
    return result.rows[0] ? mapReport(result.rows[0]) : null;
  }

  async markExported(id: string): Promise<ReportRecord | null> {
    const result = await this.pool.query(
      `UPDATE reports SET status = 'EXPORTED' WHERE id = $1 RETURNING ${REPORT_COLUMNS}`,
      [id],
    );
    return result.rows[0] ? mapReport(result.rows[0]) : null;
  }

  async nextVersion(engagementId: string, type: string): Promise<number> {
    const result = await this.pool.query(
      `SELECT COALESCE(MAX(version), 0) + 1 AS next FROM reports WHERE engagement_id = $1 AND type = $2`,
      [engagementId, type],
    );
    return Number((result.rows[0] as { next: number }).next);
  }
}

function mapReport(row: Record<string, unknown>): ReportRecord {
  return {
    id: row.id as string,
    engagement_id: row.engagement_id as string,
    type: row.type as ReportRecord['type'],
    status: row.status as ReportRecord['status'],
    version: row.version as number,
    title: row.title as string,
    manifest: (row.manifest as ReportRecord['manifest']) ?? null,
    claims: (row.claims as ReportClaimRecord[]) ?? [],
    validation_issues: (row.validation_issues as ReportValidationIssueRecord[]) ?? [],
    content: (row.content as Record<string, unknown>) ?? {},
    redactions: (row.redactions as Array<{ location: string; rule: string }>) ?? [],
    generated_by: row.generated_by as string,
    generated_at: requireIso(row.generated_at as Date),
  };
}

export class ReportExportsRepository implements RepoBase {
  constructor(readonly pool: Pool) {}

  async create(
    engagementId: string,
    reportId: string,
    format: ReportExportRecord['format'],
    byteSize: number,
    sha256: string,
    contentReference: string,
  ): Promise<ReportExportRecord> {
    const id = generateId('CLM');
    const result = await this.pool.query(
      `INSERT INTO report_exports (id, report_id, engagement_id, format, byte_size, sha256, content_reference)
       VALUES ($1, $2, $3, $4, $5, $6, $7)
       RETURNING id, report_id, engagement_id, format, byte_size, sha256, content_reference, created_at`,
      [id, reportId, engagementId, format, byteSize, sha256, contentReference],
    );
    const row = result.rows[0]!;
    return {
      id: row.id,
      report_id: row.report_id,
      engagement_id: row.engagement_id,
      format: row.format,
      byte_size: row.byte_size,
      sha256: row.sha256,
      content_reference: row.content_reference,
      created_at: requireIso(row.created_at),
    };
  }

  async findLatest(engagementId: string, reportId: string, format: string): Promise<ReportExportRecord | null> {
    const result = await this.pool.query(
      `SELECT id, report_id, engagement_id, format, byte_size, sha256, content_reference, created_at
       FROM report_exports WHERE engagement_id = $1 AND report_id = $2 AND format = $3
       ORDER BY created_at DESC LIMIT 1`,
      [engagementId, reportId, format],
    );
    const row = result.rows[0];
    if (!row) return null;
    return {
      id: row.id,
      report_id: row.report_id,
      engagement_id: row.engagement_id,
      format: row.format,
      byte_size: row.byte_size,
      sha256: row.sha256,
      content_reference: row.content_reference,
      created_at: requireIso(row.created_at),
    };
  }

  async listByReport(engagementId: string, reportId: string): Promise<ReportExportRecord[]> {
    const result = await this.pool.query(
      `SELECT id, report_id, engagement_id, format, byte_size, sha256, content_reference, created_at
       FROM report_exports WHERE engagement_id = $1 AND report_id = $2 ORDER BY created_at DESC`,
      [engagementId, reportId],
    );
    return result.rows.map(
      (row): ReportExportRecord => ({
        id: row.id,
        report_id: row.report_id,
        engagement_id: row.engagement_id,
        format: row.format,
        byte_size: row.byte_size,
        sha256: row.sha256,
        content_reference: row.content_reference,
        created_at: requireIso(row.created_at),
      }),
    );
  }
}

// -- Evaluation database (§39, §59) ------------------------------------------------

export interface UpsertScenarioInput {
  name: string;
  kind: string;
  description: string;
  fixture: string;
  expectedFindings: Array<Omit<EvaluationExpectedFindingRecord, 'id' | 'scenario_id'>>;
  expectedObservations: string[];
  expectedHypotheses: string[];
  expectedStopCondition: string | null;
  safetyExpectations: Array<{ kind: string; detail: string }>;
}

export class EvaluationScenariosRepository implements RepoBase {
  constructor(readonly pool: Pool) {}

  /** Idempotent upsert keyed on (name, version); expected findings replaced. */
  async upsert(input: UpsertScenarioInput, version = 1): Promise<EvaluationScenarioRecord> {
    const id = generateId('EVS');
    const result = await this.pool.query(
      `INSERT INTO evaluation_scenarios (id, name, kind, description, fixture, expected_observations,
         expected_hypotheses, expected_stop_condition, safety_expectations, version)
       VALUES ($1, $2, $3, $4, $5, $6::jsonb, $7::jsonb, $8, $9::jsonb, $10)
       ON CONFLICT (name, version) DO UPDATE SET
         kind = EXCLUDED.kind, description = EXCLUDED.description, fixture = EXCLUDED.fixture,
         expected_observations = EXCLUDED.expected_observations,
         expected_hypotheses = EXCLUDED.expected_hypotheses,
         expected_stop_condition = EXCLUDED.expected_stop_condition,
         safety_expectations = EXCLUDED.safety_expectations
       RETURNING id, name, kind, description, fixture, expected_observations, expected_hypotheses,
         expected_stop_condition, safety_expectations, version, created_at`,
      [
        id,
        input.name,
        input.kind,
        input.description,
        input.fixture,
        JSON.stringify(input.expectedObservations),
        JSON.stringify(input.expectedHypotheses),
        input.expectedStopCondition,
        JSON.stringify(input.safetyExpectations),
        version,
      ],
    );
    const row = result.rows[0]!;
    const scenarioId = row.id as string;
    // Ground truth rows: replace (deterministic seeding).
    await this.pool.query(`DELETE FROM evaluation_expected_findings WHERE scenario_id = $1`, [scenarioId]);
    for (const expected of input.expectedFindings) {
      await this.pool.query(
        `INSERT INTO evaluation_expected_findings (id, scenario_id, endpoint, finding_category, severity,
           verification_required, match_tokens, description)
         VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb, $8)`,
        [
          generateId('EXF'),
          scenarioId,
          expected.endpoint,
          expected.finding_category,
          expected.severity,
          expected.verification_required,
          JSON.stringify(expected.match_tokens),
          expected.description,
        ],
      );
    }
    return (await this.findById(scenarioId))!;
  }

  async findById(id: string): Promise<EvaluationScenarioRecord | null> {
    const result = await this.pool.query(
      `SELECT id, name, kind, description, fixture, expected_observations, expected_hypotheses,
         expected_stop_condition, safety_expectations, version, created_at
       FROM evaluation_scenarios WHERE id = $1 LIMIT 1`,
      [id],
    );
    const row = result.rows[0];
    if (!row) return null;
    const expected = await this.pool.query(
      `SELECT id, scenario_id, endpoint, finding_category, severity, verification_required, match_tokens, description
       FROM evaluation_expected_findings WHERE scenario_id = $1`,
      [row.id],
    );
    return mapScenario(row, expected.rows);
  }

  async list(options: { kind?: string; limit?: number } = {}): Promise<EvaluationScenarioRecord[]> {
    const limit = Math.min(Math.max(options.limit ?? 100, 1), 500);
    const result = options.kind
      ? await this.pool.query(
          `SELECT id, name, kind, description, fixture, expected_observations, expected_hypotheses,
             expected_stop_condition, safety_expectations, version, created_at
           FROM evaluation_scenarios WHERE kind = $1 ORDER BY name LIMIT $2`,
          [options.kind, limit],
        )
      : await this.pool.query(
          `SELECT id, name, kind, description, fixture, expected_observations, expected_hypotheses,
             expected_stop_condition, safety_expectations, version, created_at
           FROM evaluation_scenarios ORDER BY name LIMIT $1`,
          [limit],
        );
    const scenarios: EvaluationScenarioRecord[] = [];
    for (const row of result.rows) {
      const expected = await this.pool.query(
        `SELECT id, scenario_id, endpoint, finding_category, severity, verification_required, match_tokens, description
         FROM evaluation_expected_findings WHERE scenario_id = $1`,
        [row.id],
      );
      scenarios.push(mapScenario(row, expected.rows));
    }
    return scenarios;
  }

  async count(): Promise<number> {
    const result = await this.pool.query(`SELECT COUNT(*)::int AS count FROM evaluation_scenarios`);
    return (result.rows[0] as { count: number }).count;
  }
}

function mapScenario(row: Record<string, unknown>, expectedRows: Record<string, unknown>[]): EvaluationScenarioRecord {
  return {
    id: row.id as string,
    name: row.name as string,
    kind: row.kind as string,
    description: row.description as string,
    fixture: row.fixture as string,
    expected_findings: expectedRows.map(
      (e): EvaluationExpectedFindingRecord => ({
        id: e.id as string,
        scenario_id: e.scenario_id as string,
        endpoint: e.endpoint as string,
        finding_category: e.finding_category as string,
        severity: e.severity as string,
        verification_required: e.verification_required as boolean,
        match_tokens: (e.match_tokens as string[]) ?? [],
        description: e.description as string,
      }),
    ),
    expected_observations: (row.expected_observations as string[]) ?? [],
    expected_hypotheses: (row.expected_hypotheses as string[]) ?? [],
    expected_stop_condition: (row.expected_stop_condition as string | null) ?? null,
    safety_expectations:
      (row.safety_expectations as Array<{ kind: string; detail: string }>) ?? [],
    version: row.version as number,
    created_at: requireIso(row.created_at as Date),
  };
}

export class EvaluationRunsRepository implements RepoBase {
  constructor(readonly pool: Pool) {}

  async create(config: Record<string, unknown>, startedBy: string, isGolden: boolean): Promise<EvaluationRunRecord> {
    const id = generateId('EVR');
    const result = await this.pool.query(
      `INSERT INTO evaluation_runs (id, status, config, started_by, is_golden)
       VALUES ($1, 'RUNNING', $2::jsonb, $3, $4)
       RETURNING id, status, config, started_by, started_at, completed_at, error, is_golden, golden_reference`,
      [id, JSON.stringify(config), startedBy, isGolden],
    );
    return mapRun(result.rows[0]!);
  }

  async findById(id: string): Promise<EvaluationRunRecord | null> {
    const result = await this.pool.query(
      `SELECT id, status, config, started_by, started_at, completed_at, error, is_golden, golden_reference
       FROM evaluation_runs WHERE id = $1 LIMIT 1`,
      [id],
    );
    return result.rows[0] ? mapRun(result.rows[0]) : null;
  }

  async list(options: { limit?: number; completedOnly?: boolean } = {}): Promise<EvaluationRunRecord[]> {
    const limit = Math.min(Math.max(options.limit ?? 50, 1), 500);
    const where = options.completedOnly ? `WHERE status = 'COMPLETED'` : '';
    const result = await this.pool.query(
      `SELECT id, status, config, started_by, started_at, completed_at, error, is_golden, golden_reference
       FROM evaluation_runs ${where} ORDER BY started_at DESC LIMIT $1`,
      [limit],
    );
    return result.rows.map(mapRun);
  }

  async complete(id: string): Promise<EvaluationRunRecord | null> {
    const result = await this.pool.query(
      `UPDATE evaluation_runs SET status = 'COMPLETED', completed_at = now() WHERE id = $1
       RETURNING id, status, config, started_by, started_at, completed_at, error, is_golden, golden_reference`,
      [id],
    );
    return result.rows[0] ? mapRun(result.rows[0]) : null;
  }

  async fail(id: string, error: string): Promise<EvaluationRunRecord | null> {
    const result = await this.pool.query(
      `UPDATE evaluation_runs SET status = 'FAILED', error = $2, completed_at = now() WHERE id = $1
       RETURNING id, status, config, started_by, started_at, completed_at, error, is_golden, golden_reference`,
      [id, error],
    );
    return result.rows[0] ? mapRun(result.rows[0]) : null;
  }

  async findLatestGolden(): Promise<EvaluationRunRecord | null> {
    const result = await this.pool.query(
      `SELECT id, status, config, started_by, started_at, completed_at, error, is_golden, golden_reference
       FROM evaluation_runs WHERE is_golden AND status = 'COMPLETED' ORDER BY started_at DESC LIMIT 1`,
    );
    return result.rows[0] ? mapRun(result.rows[0]) : null;
  }
}

function mapRun(row: Record<string, unknown>): EvaluationRunRecord {
  return {
    id: row.id as string,
    status: row.status as EvaluationRunRecord['status'],
    config: (row.config as Record<string, unknown>) ?? {},
    started_by: row.started_by as string,
    started_at: requireIso(row.started_at as Date),
    completed_at: iso(row.completed_at as Date | null),
    error: (row.error as string | null) ?? null,
    is_golden: row.is_golden as boolean,
    golden_reference: (row.golden_reference as string | null) ?? null,
  };
}

export class EvaluationMetricsRepository implements RepoBase {
  constructor(readonly pool: Pool) {}

  async insert(
    runId: string,
    scenarioId: string | null,
    metric: string,
    value: number,
    unit: string,
    scope = 'run',
    details: Record<string, unknown> = {},
  ): Promise<EvaluationMetricRecord> {
    const id = generateId('EVM');
    const result = await this.pool.query(
      `INSERT INTO evaluation_metrics (id, run_id, scenario_id, metric, scope, value, unit, details)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8::jsonb)
       RETURNING id, run_id, scenario_id, metric, scope, value, unit, details`,
      [id, runId, scenarioId, metric, scope, value, unit, JSON.stringify(details)],
    );
    const row = result.rows[0]!;
    return {
      id: row.id,
      run_id: row.run_id,
      scenario_id: row.scenario_id,
      metric: row.metric,
      scope: row.scope,
      value: row.value,
      unit: row.unit,
      details: row.details ?? {},
    };
  }

  async listByRun(runId: string, scope?: string): Promise<EvaluationMetricRecord[]> {
    const result = scope
      ? await this.pool.query(
          `SELECT id, run_id, scenario_id, metric, scope, value, unit, details
           FROM evaluation_metrics WHERE run_id = $1 AND scope = $2 ORDER BY metric`,
          [runId, scope],
        )
      : await this.pool.query(
          `SELECT id, run_id, scenario_id, metric, scope, value, unit, details
           FROM evaluation_metrics WHERE run_id = $1 ORDER BY scope, metric`,
          [runId],
        );
    return result.rows.map(
      (row): EvaluationMetricRecord => ({
        id: row.id,
        run_id: row.run_id,
        scenario_id: row.scenario_id,
        metric: row.metric,
        scope: row.scope,
        value: row.value,
        unit: row.unit,
        details: row.details ?? {},
      }),
    );
  }

  /** §88: metric lookup for regression comparison (run scope, averaged). */
  async findMetric(runId: string, metric: string): Promise<number | null> {
    const result = await this.pool.query(
      `SELECT value FROM evaluation_metrics WHERE run_id = $1 AND metric = $2 AND scope = 'run' LIMIT 1`,
      [runId, metric],
    );
    const row = result.rows[0];
    return row ? Number(row.value) : null;
  }
}

export class EvaluationEventsRepository implements RepoBase {
  constructor(readonly pool: Pool) {}

  async insert(
    runId: string,
    scenarioId: string | null,
    type: string,
    description: string,
    metadata: Record<string, unknown> = {},
  ): Promise<EvaluationEventRecord> {
    const id = generateId('EVE');
    const result = await this.pool.query(
      `INSERT INTO evaluation_events (id, run_id, scenario_id, type, description, metadata)
       VALUES ($1, $2, $3, $4, $5, $6::jsonb)
       RETURNING id, run_id, scenario_id, type, description, occurred_at, metadata`,
      [id, runId, scenarioId, type, description, JSON.stringify(metadata)],
    );
    const row = result.rows[0]!;
    return {
      id: row.id,
      run_id: row.run_id,
      scenario_id: row.scenario_id,
      type: row.type,
      description: row.description,
      occurred_at: requireIso(row.occurred_at),
      metadata: row.metadata ?? {},
    };
  }

  async listByRun(runId: string, limit = 500): Promise<EvaluationEventRecord[]> {
    const result = await this.pool.query(
      `SELECT id, run_id, scenario_id, type, description, occurred_at, metadata
       FROM evaluation_events WHERE run_id = $1 ORDER BY occurred_at LIMIT $2`,
      [runId, Math.min(Math.max(limit, 1), 2000)],
    );
    return result.rows.map(
      (row): EvaluationEventRecord => ({
        id: row.id,
        run_id: row.run_id,
        scenario_id: row.scenario_id,
        type: row.type,
        description: row.description,
        occurred_at: requireIso(row.occurred_at),
        metadata: row.metadata ?? {},
      }),
    );
  }
}

export class EvaluationObservedFindingsRepository implements RepoBase {
  constructor(readonly pool: Pool) {}

  async insert(
    runId: string,
    scenarioId: string,
    expectedFindingId: string | null,
    findingId: string,
    outcome: EvaluationObservedFindingRecord['outcome'],
    matchedTokens: string[],
    category: string,
  ): Promise<void> {
    await this.pool.query(
      `INSERT INTO evaluation_observed_findings (id, run_id, scenario_id, expected_finding_id, finding_id,
         outcome, matched_tokens, category)
       VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb, $8)`,
      [generateId('EOF'), runId, scenarioId, expectedFindingId, findingId, outcome, JSON.stringify(matchedTokens), category],
    );
  }

  async listByRun(runId: string): Promise<EvaluationObservedFindingRecord[]> {
    const result = await this.pool.query(
      `SELECT id, run_id, scenario_id, expected_finding_id, finding_id, outcome, matched_tokens, category
       FROM evaluation_observed_findings WHERE run_id = $1`,
      [runId],
    );
    return result.rows.map(
      (row): EvaluationObservedFindingRecord => ({
        id: row.id,
        run_id: row.run_id,
        scenario_id: row.scenario_id,
        expected_finding_id: row.expected_finding_id,
        finding_id: row.finding_id,
        outcome: row.outcome,
        matched_tokens: row.matched_tokens ?? [],
        category: row.category,
      }),
    );
  }
}

export class EvaluationModelConfigsRepository implements RepoBase {
  constructor(readonly pool: Pool) {}

  async create(
    runId: string,
    snapshot: {
      label: string;
      strategicModel: string;
      tacticalModel: string;
      promptVersions: Record<string, string>;
      toolVersions: Record<string, string>;
      knowledgeIndexVersion: string | null;
      budget: Record<string, unknown>;
      randomSeed: number | null;
      agentVersion: string;
    },
  ): Promise<void> {
    await this.pool.query(
      `INSERT INTO evaluation_model_configs (id, run_id, label, strategic_model, tactical_model,
         prompt_versions, tool_versions, knowledge_index_version, budget, random_seed, agent_version)
       VALUES ($1, $2, $3, $4, $5, $6::jsonb, $7::jsonb, $8, $9::jsonb, $10, $11)`,
      [
        generateId('EMC'),
        runId,
        snapshot.label,
        snapshot.strategicModel,
        snapshot.tacticalModel,
        JSON.stringify(snapshot.promptVersions),
        JSON.stringify(snapshot.toolVersions),
        snapshot.knowledgeIndexVersion,
        JSON.stringify(snapshot.budget),
        snapshot.randomSeed,
        snapshot.agentVersion,
      ],
    );
  }
}

export class RegressionChecksRepository implements RepoBase {
  constructor(readonly pool: Pool) {}

  async create(
    runId: string,
    baselineRunId: string,
    verdict: RegressionCheckRecord['verdict'],
    thresholds: Record<string, number>,
    deltas: Record<string, number>,
    failures: RegressionCheckRecord['failures'],
  ): Promise<RegressionCheckRecord> {
    const id = generateId('GRN');
    const result = await this.pool.query(
      `INSERT INTO evaluation_regression_checks (id, run_id, baseline_run_id, verdict, thresholds, deltas, failures)
       VALUES ($1, $2, $3, $4, $5::jsonb, $6::jsonb, $7::jsonb)
       RETURNING id, run_id, baseline_run_id, verdict, thresholds, deltas, failures, checked_at`,
      [id, runId, baselineRunId, verdict, JSON.stringify(thresholds), JSON.stringify(deltas), JSON.stringify(failures)],
    );
    const row = result.rows[0]!;
    return {
      id: row.id,
      run_id: row.run_id,
      baseline_run_id: row.baseline_run_id,
      verdict: row.verdict,
      thresholds: row.thresholds ?? {},
      deltas: row.deltas ?? {},
      failures: row.failures ?? [],
      checked_at: requireIso(row.checked_at),
    };
  }

  async findLatestForRun(runId: string): Promise<RegressionCheckRecord | null> {
    const result = await this.pool.query(
      `SELECT id, run_id, baseline_run_id, verdict, thresholds, deltas, failures, checked_at
       FROM evaluation_regression_checks WHERE run_id = $1 ORDER BY checked_at DESC LIMIT 1`,
      [runId],
    );
    const row = result.rows[0];
    if (!row) return null;
    return {
      id: row.id,
      run_id: row.run_id,
      baseline_run_id: row.baseline_run_id,
      verdict: row.verdict,
      thresholds: row.thresholds ?? {},
      deltas: row.deltas ?? {},
      failures: row.failures ?? [],
      checked_at: requireIso(row.checked_at),
    };
  }
}
