/**
 * Engine lifecycle manager (spec Part 6 §6, §54).
 *
 * Persists every meaningful engine transition to the database, emits
 * AUTONOMOUS_PHASE_CHANGED events and writes audit rows. Conditional
 * transitions use the expected-phase guard (optimistic concurrency, §56):
 * if another writer advanced the phase first, the transition returns null
 * instead of silently overwriting.
 */
import type { Repositories } from '@aegis/database';
import type { PlatformEvent } from '@aegis/contracts';
import type { EventBus } from '@aegis/events';
import type { Logger } from '@aegis/logging';
import { generateId, type AutonomousPhase, type AutonomousMode, type ReplanTrigger, type StopReason } from '@aegis/shared';
import { AutonomousPhaseStateMachine } from './state-machine.js';

export interface LifecycleDeps {
  repos: Repositories;
  eventBus: EventBus;
  logger?: Pick<Logger, 'info' | 'warn'>;
}

export interface TransitionOptions {
  waitingReason?: string | null;
  strategySummary?: string | null;
  actorId?: string | null;
}

export class LifecycleManager {
  constructor(private readonly deps: LifecycleDeps) {}

  /** Create (idempotently) the engine state row for an engagement. */
  async initialize(engagementId: string, mode: AutonomousMode, strategySummary?: string) {
    const existing = await this.deps.repos.autonomousStates.findByEngagement(engagementId);
    if (existing) return existing;
    return this.deps.repos.autonomousStates.create({ engagementId, mode, strategySummary: strategySummary ?? null });
  }

  async get(engagementId: string) {
    return this.deps.repos.autonomousStates.findByEngagement(engagementId);
  }

  /**
   * Conditional guarded transition: only applies while the current phase is
   * still `expected`. Returns null when the guard failed (another writer won
   * or the phase already moved on) — callers treat this as benign.
   */
  async transitionIf(
    engagementId: string,
    expected: AutonomousPhase,
    to: AutonomousPhase,
    options: TransitionOptions = {},
  ): Promise<boolean> {
    AutonomousPhaseStateMachine.assertTransition(expected, to);
    const updated = await this.deps.repos.autonomousStates.transitionPhase(engagementId, expected, to, {
      waitingReason: options.waitingReason ?? null,
      strategySummary: options.strategySummary ?? null,
      stopReason: AutonomousPhaseStateMachine.isTerminal(to) ? (to === 'COMPLETED' ? 'OBJECTIVE_COMPLETED' : null) : null,
      finish: AutonomousPhaseStateMachine.isTerminal(to),
    });
    if (!updated) return false;
    await this.publishPhaseChange(engagementId, expected, to, options);
    return true;
  }

  /** Unconditional transition used by control actions (§48). */
  async force(
    engagementId: string,
    to: AutonomousPhase,
    options: TransitionOptions & { stopReason?: StopReason | null } = {},
  ): Promise<void> {
    const current = await this.get(engagementId);
    const from = current?.phase ?? 'CREATED';
    if (from === to) return;
    if (current && !AutonomousPhaseStateMachine.canTransition(from, to)) {
      // Terminal overrides (user stop) bypass the cycle guards.
      if (!AutonomousPhaseStateMachine.isTerminal(to)) {
        this.deps.logger?.warn('autonomous.phase.transition_rejected', { engagement_id: engagementId, from, to });
        return;
      }
    }
    const updated = await this.deps.repos.autonomousStates.forcePhase(engagementId, to, {
      waitingReason: options.waitingReason ?? null,
      stopReason: options.stopReason ?? null,
      finish: AutonomousPhaseStateMachine.isTerminal(to),
    });
    if (!updated) return;
    await this.publishPhaseChange(engagementId, from, to, options);
  }

  async recordReplan(engagementId: string, trigger: ReplanTrigger): Promise<number> {
    const count = await this.deps.repos.autonomousStates.recordReplan(engagementId, trigger);
    await this.deps.eventBus.publish({
      type: 'REPLAN_REQUESTED',
      engagement_id: engagementId,
      trace_id: generateId('TRC'),
      actor_id: null,
      payload: { trigger, replan_count: count },
      occurred_at: new Date().toISOString(),
    });
    return count;
  }

  async incrementCycle(engagementId: string): Promise<number> {
    return this.deps.repos.autonomousStates.incrementCycle(engagementId);
  }

  private async publishPhaseChange(
    engagementId: string,
    from: AutonomousPhase,
    to: AutonomousPhase,
    options: TransitionOptions,
  ): Promise<void> {
    const event: PlatformEvent = {
      type: 'AUTONOMOUS_PHASE_CHANGED',
      engagement_id: engagementId,
      trace_id: generateId('TRC'),
      actor_id: options.actorId ?? null,
      payload: {
        from,
        to,
        terminal: AutonomousPhaseStateMachine.isTerminal(to),
        ...(options.waitingReason ? { waiting_reason: options.waitingReason } : {}),
      },
      occurred_at: new Date().toISOString(),
      dedup_key: `autonomous-phase:${engagementId}:${from}:${to}:${Date.now()}`,
    };
    await this.deps.eventBus.publish(event);
    await this.deps.repos.audit
      .create({
        actorUserId: options.actorId ?? null,
        action: `AUTONOMOUS_PHASE_${to}`,
        resource: 'engagement',
        resourceId: engagementId,
        engagementId,
        metadata: { from, to },
      })
      .catch(() => undefined);
    this.deps.logger?.info('autonomous.phase.changed', { engagement_id: engagementId, from, to });
  }
}
