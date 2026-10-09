/**
 * Recovery manager (spec Part 6 §54-§55 crash recovery).
 *
 * If the API server crashes mid-run:
 *
 *   restart -> load engagement -> find incomplete tasks -> recover -> continue
 *
 * Tasks carry leases: RUNNING tasks whose lease expired (worker heartbeat
 * stopped) move to RECOVERY_PENDING and receive a recovery policy:
 *   - SAFE_RETRY for idempotent, read-only tasks (GET, analysis);
 *   - MARK_FAILED for potentially state-changing tasks (POST/PUT/DELETE with
 *     mutations) — never blindly repeated (§55);
 *   - RECOMPILE when the underlying plan changed.
 */
import type { Repositories, TaskRecord } from '@aegis/database';
import type { PlatformEvent } from '@aegis/contracts';
import type { EventBus } from '@aegis/events';
import { generateId, type RecoveryPolicy } from '@aegis/shared';

export interface RecoveryManagerOptions {
  sweepIntervalMs: number;
}

export interface RecoveryOutcome {
  swept: number;
  policies: Array<{ taskId: string; policy: RecoveryPolicy; reason: string }>;
}

export class RecoveryManager {
  private lastSweepAt = Date.now();

  constructor(
    private readonly deps: { repos: Repositories | null; eventBus: EventBus | null },
    private readonly opts: RecoveryManagerOptions,
  ) {}

  /**
   * Sweep expired leases for one engagement (§55). Throttled by the sweep
   * interval; returns empty when the sweep is skipped.
   */
  async sweep(engagementId: string, force = false): Promise<RecoveryOutcome> {
    const now = Date.now();
    if (!force && now - this.lastSweepAt < this.opts.sweepIntervalMs) {
      return { swept: 0, policies: [] };
    }
    this.lastSweepAt = now;

    const repos = this.deps.repos;
    if (!repos) return { swept: 0, policies: [] };
    const expired = await repos.tasks.findExpiredLeases(engagementId, 20);
    const policies: Array<{ taskId: string; policy: RecoveryPolicy; reason: string }> = [];

    for (const task of expired) {
      const policy = this.policyFor(task);
      policies.push({ taskId: task.id, policy: policy.policy, reason: policy.reason });

      // RECOVERY_PENDING is the crash-state (Part 2 §19); the Part 2
      // scheduler + loop recovery handle re-queuing. State-changing tasks
      // are failed instead of retried (§55).
      if (policy.policy === 'MARK_FAILED') {
        await repos.tasks
          .recordFailure(task.id, 'LEASE_EXPIRED_STATE_CHANGING', policy.reason)
          .catch(() => undefined);
        await repos.tasks.updateStatus(task.id, 'FAILED').catch(() => undefined);
        await repos.tasks.releaseLease(task.id).catch(() => undefined);
      } else {
        await repos.tasks.updateStatus(task.id, 'RECOVERY_PENDING').catch(() => undefined);
        await repos.tasks.releaseLease(task.id).catch(() => undefined);
      }
    }

    if (policies.length > 0 && this.deps.eventBus) {
      const event: PlatformEvent = {
        type: 'TASK_LEASE_EXPIRED',
        engagement_id: engagementId,
        trace_id: generateId('TRC'),
        actor_id: null,
        payload: { expired: expired.length, policies: policies.slice(0, 10) },
        occurred_at: new Date().toISOString(),
        dedup_key: `lease-expired:${engagementId}:${now}`,
      };
      await this.deps.eventBus.publish(event).catch(() => undefined);
    }
    return { swept: expired.length, policies };
  }

  /**
   * Startup recovery (§54): non-terminal RUNNING tasks from a dead engine
   * instance move to RECOVERY_PENDING; QUEUED/READY/WAITING survive and a
   * fresh run picks them up.
   */
  async recoverIncomplete(engagementId: string): Promise<RecoveryOutcome> {
    const repos = this.deps.repos;
    if (!repos) return { swept: 0, policies: [] };
    const running = await repos.tasks.listByEngagement(engagementId, {
      statuses: ['RUNNING', 'RECOVERY_PENDING'],
      limit: 100,
    });
    const policies: Array<{ taskId: string; policy: RecoveryPolicy; reason: string }> = [];
    for (const task of running) {
      const decision = this.policyFor(task);
      policies.push({ taskId: task.id, policy: decision.policy, reason: decision.reason });
      if (decision.policy === 'MARK_FAILED') {
        await repos.tasks
          .recordFailure(task.id, 'RECOVERED_STATE_CHANGING', decision.reason)
          .catch(() => undefined);
        await repos.tasks.updateStatus(task.id, 'FAILED').catch(() => undefined);
      } else {
        await repos.tasks.updateStatus(task.id, 'RECOVERY_PENDING').catch(() => undefined);
      }
      await repos.tasks.releaseLease(task.id).catch(() => undefined);
    }
    if (policies.length > 0 && this.deps.eventBus) {
      const event: PlatformEvent = {
        type: 'AUTONOMOUS_RECOVERY_COMPLETED',
        engagement_id: engagementId,
        trace_id: generateId('TRC'),
        actor_id: null,
        payload: { recovered: policies.length, policies: policies.slice(0, 10) },
        occurred_at: new Date().toISOString(),
        dedup_key: `recovery:${engagementId}:${Date.now()}`,
      };
      await this.deps.eventBus.publish(event).catch(() => undefined);
    }
    return { swept: policies.length, policies };
  }

  /**
   * Recovery policy (§55): read-only / idempotent tasks retry safely;
   * state-changing tasks are marked failed — the planner may recompile a
   * materially different plan if the hypothesis still warrants it.
   */
  private policyFor(task: TaskRecord): { policy: RecoveryPolicy; reason: string } {
    const mode = typeof task.inputs.mode === 'string' ? task.inputs.mode : '';
    const mutations = Array.isArray(task.inputs.mutations) ? task.inputs.mutations.length : 0;
    const hasStateChange =
      task.type === 'VERIFICATION'
        ? false
        : mode === 'TEST_CANDIDATE' && mutations > 0;
    const isReadOnly =
      task.type === 'RECON' ||
      task.type === 'GENERAL_ANALYSIS' ||
      task.type === 'KNOWLEDGE_SUMMARY' ||
      task.type === 'SOURCE_ANALYSIS' ||
      (mode !== 'TEST_CANDIDATE' && mutations === 0);

    if (hasStateChange) {
      return {
        policy: 'MARK_FAILED',
        reason: 'potentially state-changing mutation test: never blindly repeated after a crash (§55)',
      };
    }
    if (isReadOnly) {
      return { policy: 'SAFE_RETRY', reason: 'read-only/idempotent task: safe to retry' };
    }
    return { policy: 'RESUME', reason: 'observation task resumable from persisted state' };
  }
}
