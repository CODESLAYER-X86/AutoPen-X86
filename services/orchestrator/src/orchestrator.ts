/**
 * Orchestrator service (Part 1 scope).
 *
 * Owns the engagement lifecycle: readiness evaluation, deterministic status
 * transitions, event emission and audit records. It sits ABOVE the model
 * layer (spec §40): even when the strategic model exists (Part 2), its
 * structured decisions are executed through this service, never directly
 * against the database or the target.
 *
 * NOT implemented in Part 1 (explicit): the autonomous run loop, task
 * compilation/scheduling, hypothesis management, replanning. Calling
 * startRun() fails with NotImplementedError rather than pretending.
 */
import type { Logger } from '@aegis/logging';
import type { PlatformEvent, Engagement } from '@aegis/contracts';
import type {
  EngagementRecord,
  EventsRepository,
  EngagementsRepository,
  ScopeRepository,
  TargetsRepository,
  AuditRepository,
} from '@aegis/database';
import {
  NotImplementedError,
  ValidationError,
  generateId,
  type EngagementStatus,
} from '@aegis/shared';
import { EngagementStateMachine } from './state-machine.js';

export interface OrchestratorDeps {
  engagements: EngagementsRepository;
  targets: TargetsRepository;
  scope: ScopeRepository;
  events: EventsRepository;
  audit: AuditRepository;
  eventBus: { publish(event: PlatformEvent): Promise<void> };
  logger: Logger;
}

export interface ReadinessResult {
  has_scope: boolean;
  has_targets: boolean;
  ready: boolean;
}

export interface TransitionResult {
  engagement: EngagementRecord;
  from: EngagementStatus;
  to: EngagementStatus;
}

/** Event type per target status (spec §14 event vocabulary). */
const STATUS_EVENT: Record<EngagementStatus, string> = {
  DRAFT: 'ENGAGEMENT_CREATED',
  READY: 'ENGAGEMENT_READY',
  RUNNING: 'ENGAGEMENT_STARTED',
  PAUSED: 'ENGAGEMENT_PAUSED',
  COMPLETED: 'ENGAGEMENT_COMPLETED',
  FAILED: 'ENGAGEMENT_FAILED',
  CANCELLED: 'ENGAGEMENT_CANCELLED',
};

export class OrchestratorService {
  private readonly deps: OrchestratorDeps;

  constructor(deps: OrchestratorDeps) {
    this.deps = deps;
  }

  async evaluateReadiness(engagementId: string): Promise<ReadinessResult> {
    const scope = await this.deps.scope.findByEngagement(engagementId);
    const targetCount = await this.deps.targets.countByEngagement(engagementId);
    const hasScope = scope !== null;
    const hasTargets = targetCount > 0;
    return { has_scope: hasScope, has_targets: hasTargets, ready: hasScope && hasTargets };
  }

  /**
   * DRAFT -> READY happens automatically once an engagement has BOTH a
   * scope and at least one in-scope target. Callers invoke this after
   * scope/target mutations.
   */
  async markReadyIfEligible(engagement: EngagementRecord, actorId: string | null): Promise<EngagementRecord | null> {
    if (engagement.status !== 'DRAFT') return null;
    const readiness = await this.evaluateReadiness(engagement.id);
    if (!readiness.ready) return null;
    const result = await this.transition(engagement, 'READY', { actorId });
    return result.engagement;
  }

  async transition(
    engagement: EngagementRecord,
    to: EngagementStatus,
    options: { actorId: string | null; reason?: string } = { actorId: null },
  ): Promise<TransitionResult> {
    const from = engagement.status;
    EngagementStateMachine.assertTransition(from, to);

    const updated = await this.deps.engagements.updateStatus(engagement.id, to);
    if (!updated) {
      throw new ValidationError('Engagement disappeared during transition', 'ENGAGEMENT_NOT_FOUND');
    }

    const traceId = generateId('TRC');
    await this.deps.eventBus.publish({
      type: STATUS_EVENT[to] as PlatformEvent['type'],
      engagement_id: engagement.id,
      trace_id: traceId,
      actor_id: options.actorId,
      payload: { from, to, ...(options.reason ? { reason: options.reason } : {}) },
      occurred_at: new Date().toISOString(),
    });

    await this.deps.audit.create({
      actorUserId: options.actorId,
      action: `ENGAGEMENT_${to}`,
      resource: 'engagement',
      resourceId: engagement.id,
      engagementId: engagement.id,
      metadata: { from, to },
    });

    this.deps.logger.info('engagement.transitioned', {
      engagement_id: engagement.id,
      from,
      to,
      trace_id: traceId,
    });

    return { engagement: updated, from, to };
  }

  /** start: DRAFT auto-promotes to READY when preconditions hold, then -> RUNNING. */
  async start(engagement: EngagementRecord, actorId: string | null): Promise<TransitionResult> {
    if (engagement.status === 'DRAFT') {
      const readiness = await this.evaluateReadiness(engagement.id);
      if (!readiness.ready) {
        throw new ValidationError(
          'Engagement is not ready to start: it requires a configured scope and at least one in-scope target',
          'ENGAGEMENT_PRECONDITIONS_NOT_MET',
          readiness,
        );
      }
      const promoted = await this.transition(engagement, 'READY', { actorId });
      return this.transition(promoted.engagement, 'RUNNING', { actorId });
    }
    if (engagement.status === 'READY') {
      return this.transition(engagement, 'RUNNING', { actorId });
    }
    if (engagement.status === 'RUNNING') {
      throw new ValidationError('Engagement is already running', 'INVALID_ENGAGEMENT_TRANSITION');
    }
    return this.transition(engagement, 'RUNNING', { actorId });
  }

  async pause(engagement: EngagementRecord, actorId: string | null): Promise<TransitionResult> {
    return this.transition(engagement, 'PAUSED', { actorId });
  }

  async resume(engagement: EngagementRecord, actorId: string | null): Promise<TransitionResult> {
    return this.transition(engagement, 'RUNNING', { actorId });
  }

  async cancel(engagement: EngagementRecord, actorId: string | null): Promise<TransitionResult> {
    return this.transition(engagement, 'CANCELLED', { actorId });
  }

  async complete(engagement: EngagementRecord, actorId: string | null): Promise<TransitionResult> {
    return this.transition(engagement, 'COMPLETED', { actorId });
  }

  async fail(engagement: EngagementRecord, actorId: string | null, reason: string): Promise<TransitionResult> {
    return this.transition(engagement, 'FAILED', { actorId, reason });
  }

  /**
   * The autonomous execution loop (strategic model -> decisions -> tasks ->
   * workers -> observations -> replanning). Explicitly NOT implemented in
   * Part 1 — this is the documented boundary for Part 2.
   */
  startRun(_engagement: Pick<Engagement, 'id'>): never {
    void _engagement;
    throw new NotImplementedError(
      'The autonomous run loop is not implemented in Part 1; it is the subject of Part 2 (Agent Operating System)',
      'ORCHESTRATOR_RUN_LOOP_NOT_IMPLEMENTED',
    );
  }
}
