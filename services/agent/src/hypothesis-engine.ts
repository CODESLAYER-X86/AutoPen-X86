/**
 * Hypothesis engine (spec Part 2 §22-§27, §54-§55).
 *
 * Owns the deterministic half of hypothesis lifecycle:
 *  - confidence updates driven ONLY by evidence events (never arbitrary)
 *  - status transitions (PROPOSED -> ACTIVE -> TESTING -> SUPPORTED ->
 *    CONFIRMED / DISPROVED / ABANDONED)
 *  - branch budgets (max active, max depth, max parallel branches, §54)
 *  - dead-end recording (§27)
 *  - finding promotion (§55): a hypothesis never becomes a finding without
 *    verification — CONFIRMED status requires a verification outcome.
 *
 * The mathematical model is intentionally heuristic and REPLACEABLE via the
 * ConfidenceStrategy interface (spec §25).
 */
import type { EventBus } from '@aegis/events';
import type {
  DeadEndsRepository,
  FindingsRepository,
  HypothesisRecord,
  HypothesesRepository,
  HypothesisLinkRecord,
} from '@aegis/database';
import type { HypothesisChange, HypothesisStatus, HypothesisType } from '@aegis/shared';
import { ValidationError, generateId } from '@aegis/shared';

/** Confidence at/above which a hypothesis becomes SUPPORTED (§55 ladder). */
export const SUPPORTED_CONFIDENCE_THRESHOLD = 0.75;

export interface BranchBudget {
  maxActiveHypotheses: number;
  maxBranchDepth: number;
  maxParallelBranches: number;
}

export const DEFAULT_BRANCH_BUDGET: BranchBudget = {
  maxActiveHypotheses: 12,
  maxBranchDepth: 4,
  maxParallelBranches: 4,
};

/**
 * Replaceable confidence arithmetic (spec §25). Default: saturating update —
 * supporting evidence moves confidence toward 1 by (1 - c) * w; contradicting
 * evidence moves it toward 0 by c * w. Bounded, monotonic, order-sensitive.
 */
export interface ConfidenceStrategy {
  increase(current: number, evidenceWeight: number): number;
  decrease(current: number, evidenceWeight: number): number;
}

export class SaturatingConfidenceStrategy implements ConfidenceStrategy {
  increase(current: number, weight: number): number {
    const w = clampWeight(weight);
    return clamp01(current + (1 - current) * w);
  }

  decrease(current: number, weight: number): number {
    const w = clampWeight(weight);
    return clamp01(current - current * w);
  }
}

export interface HypothesisEngineDeps {
  hypotheses: HypothesesRepository;
  deadEnds: DeadEndsRepository;
  findings: FindingsRepository;
  eventBus: EventBus;
  strategy?: ConfidenceStrategy;
  branchBudget?: BranchBudget;
}

export interface EvidenceEvent {
  type: 'SUPPORTING' | 'CONTRADICTING' | 'NEUTRAL';
  weight: number;
  ref?: { refType: 'OBSERVATION' | 'TEST' | 'EVIDENCE'; refId: string };
}

export class HypothesisEngine {
  private readonly confidence: ConfidenceStrategy;
  private readonly branchBudget: BranchBudget;

  constructor(private readonly deps: HypothesisEngineDeps) {
    this.confidence = deps.strategy ?? new SaturatingConfidenceStrategy();
    this.branchBudget = deps.branchBudget ?? DEFAULT_BRANCH_BUDGET;
  }

  get budget(): BranchBudget {
    return { ...this.branchBudget };
  }

  /**
   * Creates a hypothesis after branch-budget validation (§54). Competing
   * hypotheses are preserved — creation is never blocked because a sibling
   * exists (§26); it is blocked only when budgets are exceeded.
   */
  async createHypothesis(input: {
    engagementId: string;
    type: HypothesisType;
    statement: string;
    confidence?: number;
    priority?: number;
    source: string;
    parentHypothesisId?: string | null;
  }): Promise<HypothesisRecord> {
    const actionable = await this.deps.hypotheses.countActionable(input.engagementId);
    if (actionable >= this.branchBudget.maxActiveHypotheses) {
      throw new ValidationError(
        `Branch budget exceeded: ${actionable} active hypotheses (max ${this.branchBudget.maxActiveHypotheses}); abandon or confirm hypotheses before creating more`,
        'HYPOTHESIS_BRANCH_BUDGET_EXCEEDED',
        { actionable, max: this.branchBudget.maxActiveHypotheses },
      );
    }

    if (input.parentHypothesisId) {
      const depth = await this.deps.hypotheses.maxBranchDepth(input.engagementId);
      if (depth >= this.branchBudget.maxBranchDepth) {
        throw new ValidationError(
          `Branch budget exceeded: depth ${depth} (max ${this.branchBudget.maxBranchDepth})`,
          'HYPOTHESIS_BRANCH_DEPTH_EXCEEDED',
          { depth, max: this.branchBudget.maxBranchDepth },
        );
      }
      const siblings = await this.deps.hypotheses.listByEngagement(input.engagementId, {
        statuses: ['PROPOSED', 'ACTIVE', 'TESTING', 'SUPPORTED'],
      });
      const sameParent = siblings.filter((h) => h.parent_hypothesis_id === input.parentHypothesisId);
      if (sameParent.length >= this.branchBudget.maxParallelBranches) {
        throw new ValidationError(
          `Branch budget exceeded: ${sameParent.length} parallel branches under the parent (max ${this.branchBudget.maxParallelBranches})`,
          'HYPOTHESIS_PARALLEL_BRANCHES_EXCEEDED',
          { siblings: sameParent.length, max: this.branchBudget.maxParallelBranches },
        );
      }
    }

    const created = await this.deps.hypotheses.create(input);
    await this.deps.eventBus.publish({
      type: 'HYPOTHESIS_CREATED',
      engagement_id: input.engagementId,
      task_id: null,
      trace_id: generateId('TRC'),
      actor_id: null,
      payload: {
        hypothesis_id: created.id,
        type: created.type,
        statement: created.statement,
        confidence: created.confidence,
        source: created.source,
        parent_hypothesis_id: created.parent_hypothesis_id,
      },
      occurred_at: new Date().toISOString(),
    });
    return created;
  }

  /**
   * Confidence updates are event-driven (§25): each evidence event moves
   * confidence through the strategy; status changes follow thresholds.
   */
  async applyEvidenceEvent(
    hypothesis: HypothesisRecord,
    event: EvidenceEvent,
  ): Promise<HypothesisRecord> {
    if (isTerminalHypothesis(hypothesis.status)) return hypothesis;

    let confidence = hypothesis.confidence;
    if (event.type === 'SUPPORTING') {
      confidence = this.confidence.increase(confidence, event.weight);
    } else if (event.type === 'CONTRADICTING') {
      confidence = this.confidence.decrease(confidence, event.weight);
    }

    if (event.ref) {
      await this.deps.hypotheses.link({
        hypothesisId: hypothesis.id,
        refType: event.ref.refType,
        refId: event.ref.refId,
      });
    }

    let status: HypothesisStatus = hypothesis.status;
    if (status === 'PROPOSED' && (event.type === 'SUPPORTING' || event.type === 'CONTRADICTING')) {
      status = 'ACTIVE';
    }
    if (confidence >= SUPPORTED_CONFIDENCE_THRESHOLD && status !== 'TESTING') {
      status = 'SUPPORTED';
    }

    const updated = await this.deps.hypotheses.update(hypothesis.id, {
      status,
      confidence,
    });
    if (!updated) return hypothesis;

    await this.deps.eventBus.publish({
      type: 'HYPOTHESIS_UPDATED',
      engagement_id: hypothesis.engagement_id,
      task_id: null,
      trace_id: generateId('TRC'),
      actor_id: null,
      payload: {
        hypothesis_id: hypothesis.id,
        event: event.type,
        weight: event.weight,
        from_confidence: hypothesis.confidence,
        to_confidence: confidence,
        status,
      },
      occurred_at: new Date().toISOString(),
    });

    return updated;
  }

  /**
   * Worker/leader-requested status changes. CONFIRMED and DISPROVED are only
   * reachable through verification (§55-§56): the caller must pass
   * `viaVerification: true` (the scheduler grants it only for VERIFICATION
   * tasks). CONFIRMED triggers finding promotion.
   */
  async applyChange(
    hypothesis: HypothesisRecord,
    change: HypothesisChange | 'CREATE' | 'ACTIVATE',
    options: {
      confidence?: number;
      viaVerification?: boolean;
      verificationRef?: string;
    } = {},
  ): Promise<HypothesisRecord> {
    switch (change) {
      case 'CREATE':
        throw new ValidationError(
          'CREATE is not a status change; use createHypothesis',
          'HYPOTHESIS_INVALID_CHANGE',
        );
      case 'ACTIVATE': {
        assertHypothesisTransition(hypothesis.status, 'ACTIVE');
        return this.deps.hypotheses.update(hypothesis.id, { status: 'ACTIVE' }).then((h) => h!);
      }
      case 'INCREASE_CONFIDENCE':
      case 'SUPPORT':
        return this.applyEvidenceEvent(hypothesis, {
          type: 'SUPPORTING',
          weight: options.confidence ?? 0.3,
        });
      case 'DECREASE_CONFIDENCE':
      case 'CONTRADICT':
        return this.applyEvidenceEvent(hypothesis, {
          type: 'CONTRADICTING',
          weight: options.confidence ?? 0.3,
        });
      case 'ABANDON':
        return this.abandon(hypothesis, 'explicit abandon request');
      case 'CONFIRM': {
        if (!options.viaVerification) {
          throw new ValidationError(
            'CONFIRM requires verification evidence; a hypothesis never becomes a finding without it (spec Part 2 §55)',
            'HYPOTHESIS_CONFIRM_REQUIRES_VERIFICATION',
          );
        }
        assertHypothesisTransition(hypothesis.status, 'CONFIRMED');
        const updated = (await this.deps.hypotheses.update(hypothesis.id, {
          status: 'CONFIRMED',
          confidence: options.confidence ?? Math.max(hypothesis.confidence, 0.9),
        }))!;
        if (options.verificationRef) {
          await this.deps.hypotheses.link({
            hypothesisId: hypothesis.id,
            refType: 'TEST',
            refId: options.verificationRef,
          });
        }
        await this.promoteFinding(updated, options.verificationRef ?? null);
        await this.deps.eventBus.publish({
          type: 'HYPOTHESIS_CONFIRMED',
          engagement_id: hypothesis.engagement_id,
          task_id: null,
          trace_id: generateId('TRC'),
          actor_id: null,
          payload: { hypothesis_id: hypothesis.id },
          occurred_at: new Date().toISOString(),
        });
        return updated;
      }
      case 'DISPROVE': {
        // Disproof always counts as verification-grade evidence (§56
        // skepticism: attempting to disprove is the preferred direction).
        assertHypothesisTransition(hypothesis.status, 'DISPROVED');
        const updated = (await this.deps.hypotheses.update(hypothesis.id, {
          status: 'DISPROVED',
          confidence: options.confidence ?? Math.min(hypothesis.confidence, 0.15),
        }))!;
        await this.deps.eventBus.publish({
          type: 'HYPOTHESIS_DISPROVED',
          engagement_id: hypothesis.engagement_id,
          task_id: null,
          trace_id: generateId('TRC'),
          actor_id: null,
          payload: { hypothesis_id: hypothesis.id },
          occurred_at: new Date().toISOString(),
        });
        return updated;
      }
      default:
        throw new ValidationError(`Unknown hypothesis change '${String(change)}'`, 'HYPOTHESIS_INVALID_CHANGE');
    }
  }

  /** Marks a hypothesis TESTING when a task targeting it is scheduled. */
  async markTesting(hypothesis: HypothesisRecord): Promise<HypothesisRecord> {
    if (isTerminalHypothesis(hypothesis.status)) return hypothesis;
    assertHypothesisTransition(hypothesis.status, 'TESTING');
    return (await this.deps.hypotheses.update(hypothesis.id, { status: 'TESTING' }))!;
  }

  /**
   * Dead-end memory (§27): records the abandoned hypothesis, the tests that
   * exhausted it and the reason, so the leader sees it before re-proposing.
   */
  async abandon(hypothesis: HypothesisRecord, reason: string): Promise<HypothesisRecord> {
    assertHypothesisTransition(hypothesis.status, 'ABANDONED');
    const updated = (await this.deps.hypotheses.update(hypothesis.id, { status: 'ABANDONED' }))!;

    const links = await this.deps.hypotheses.linksByHypothesis(hypothesis.id);
    const tests = links.filter((l) => l.ref_type === 'TEST').map((l) => l.ref_id);

    await this.deps.deadEnds.create({
      engagementId: hypothesis.engagement_id,
      hypothesisId: hypothesis.id,
      description: hypothesis.statement,
      tests,
      reason,
    });
    await this.deps.eventBus.publish({
      type: 'DEAD_END_RECORDED',
      engagement_id: hypothesis.engagement_id,
      task_id: null,
      trace_id: generateId('TRC'),
      actor_id: null,
      payload: { hypothesis_id: hypothesis.id, reason },
      occurred_at: new Date().toISOString(),
    });
    return updated;
  }

  /** Finding promotion (§55) — idempotent per hypothesis. */
  async promoteFinding(
    hypothesis: HypothesisRecord,
    verificationRef: string | null,
  ): Promise<{ created: boolean; findingId: string }> {
    const existing = await this.deps.findings.findByHypothesis(hypothesis.id);
    if (existing) return { created: false, findingId: existing.id };

    const links = await this.deps.hypotheses.linksByHypothesis(hypothesis.id);
    const evidenceIds = links.filter((l) => l.ref_type === 'EVIDENCE').map((l) => l.ref_id);

    const finding = await this.deps.findings.create({
      engagementId: hypothesis.engagement_id,
      hypothesisId: hypothesis.id,
      title: `Confirmed: ${hypothesis.statement.slice(0, 120)}`,
      description: hypothesis.statement,
      severity: severityFromType(hypothesis.type),
      evidenceIds,
      status: 'CONFIRMED',
    });
    void verificationRef;
    await this.deps.eventBus.publish({
      type: 'FINDING_CREATED',
      engagement_id: hypothesis.engagement_id,
      task_id: null,
      trace_id: generateId('TRC'),
      actor_id: null,
      payload: { finding_id: finding.id, hypothesis_id: hypothesis.id, status: 'CONFIRMED' },
      occurred_at: new Date().toISOString(),
    });
    return { created: true, findingId: finding.id };
  }

  /** Links evidence references to a hypothesis (§24 auditability). */
  async linkEvidence(
    hypothesisId: string,
    refs: Array<{ refType: 'OBSERVATION' | 'TEST' | 'EVIDENCE'; refId: string }>,
  ): Promise<void> {
    for (const ref of refs) {
      await this.deps.hypotheses.link({ hypothesisId, refType: ref.refType, refId: ref.refId });
    }
  }
}

// ---------------------------------------------------------------------------
// Deterministic hypothesis status table (superset of §22 semantics)
// ---------------------------------------------------------------------------

export const HYPOTHESIS_TRANSITIONS: Readonly<Record<HypothesisStatus, readonly HypothesisStatus[]>> = {
  PROPOSED: ['ACTIVE', 'TESTING', 'ABANDONED', 'DISPROVED'],
  ACTIVE: ['TESTING', 'SUPPORTED', 'ABANDONED', 'DISPROVED'],
  // TESTING: verification may CONFIRM directly (via verification tasks only)
  // or fall back to SUPPORTED before confirmation (§55 ladder).
  TESTING: ['SUPPORTED', 'CONFIRMED', 'DISPROVED', 'ABANDONED', 'ACTIVE'],
  // SUPPORTED: awaiting verification; CONFIRMED only via verification.
  SUPPORTED: ['CONFIRMED', 'DISPROVED', 'ABANDONED', 'TESTING'],
  CONFIRMED: [],
  DISPROVED: [],
  ABANDONED: [],
};

export function assertHypothesisTransition(from: HypothesisStatus, to: HypothesisStatus): void {
  const allowed = HYPOTHESIS_TRANSITIONS[from];
  if (!allowed || !allowed.includes(to)) {
    throw new ValidationError(
      `Invalid hypothesis transition: ${from} -> ${to}`,
      'INVALID_HYPOTHESIS_TRANSITION',
      { from, to, allowed_from: allowed ?? [] },
    );
  }
}

export function isTerminalHypothesis(status: HypothesisStatus): boolean {
  return status === 'CONFIRMED' || status === 'DISPROVED' || status === 'ABANDONED';
}

function severityFromType(type: HypothesisType): string {
  switch (type) {
    case 'AUTHORIZATION':
    case 'INJECTION':
    case 'CRYPTOGRAPHIC':
      return 'HIGH';
    case 'AUTHENTICATION':
    case 'SESSION':
      return 'HIGH';
    case 'DATA_EXPOSURE':
    case 'CONFIGURATION':
      return 'MEDIUM';
    case 'CTF_CLUE':
    case 'UNKNOWN':
      return 'LOW';
    default:
      return 'MEDIUM';
  }
}

function clamp01(value: number): number {
  return Math.min(1, Math.max(0, value));
}

function clampWeight(weight: number): number {
  return Math.min(1, Math.max(0.01, weight));
}

export type { HypothesisLinkRecord };
