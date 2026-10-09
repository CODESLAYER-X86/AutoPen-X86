/**
 * Task scheduler (spec Part 2 §19, §32-§33, §36, §40, §43-§44).
 *
 * Dependency-aware, quota-aware, priority-ordered task execution:
 *  - QUEUED tasks whose dependencies are all satisfied become READY (§33).
 *  - READY tasks are ordered by priority, adjusted for quota pressure (§40),
 *    and executed with bounded concurrency.
 *  - Worker failures are classified; transient failures retry with bounded
 *    backoff, permanent failures never retry (§43-§44).
 *  - Cancellation cascades through dependents.
 *
 * The scheduler never executes tools itself — the worker runtime calls the
 * ToolGateway, which enforces policy + scope (§69).
 */
import type { TaskRecord, Repositories, ScopeRecord, EngagementRecord } from '@aegis/database';
import type { EventBus } from '@aegis/events';
import type { WorkerResult, WorkerRuntime } from '@aegis/worker-runtime';
import type { ToolGateway } from '@aegis/tools';
import { generateId, type TaskStatus } from '@aegis/shared';
import { TaskStateMachine, TERMINAL_TASK_STATUSES } from './state-machines.js';
import { AgentPolicy } from './policy.js';
import type { TaskCompiler } from './task-compiler.js';
import type { ResultNormalizer, NormalizedResult } from './result-normalizer.js';
import {
  failureCodeForWorkerStatus,
  taskStatusForWorkerStatus,
} from './result-normalizer.js';
import type { QuotaManager, TokenBudgeter } from './quota.js';
import { estimateTokens } from './quota.js';
import { quotaAdjustedPriority } from './priority.js';
import { classifyError } from './retry.js';

export interface SchedulerOptions {
  maxConcurrentTasks: number;
  retryDelayMs: number;
  /** Part 6 §55: lease owner identity + lease duration for claimed tasks. */
  leaseOwner?: string;
  taskLeaseMs?: number;
}

export const DEFAULT_SCHEDULER_OPTIONS: SchedulerOptions = {
  maxConcurrentTasks: 2,
  retryDelayMs: 800,
};

/** Worker failure codes that are PERMANENT (never retried, §44). */
const PERMANENT_WORKER_CODES = new Set([
  'WORKER_BLOCKED',
  'WORKER_NEEDS_CONTEXT',
  'WORKER_NEEDS_TOOL',
  'WORKER_NEEDS_IDENTITY',
  'WORKER_TURN_INVALID',
  'WORKER_OUTPUT_INVALID',
  'WORKER_TURN_BUDGET_EXCEEDED',
]);

export interface TaskSchedulerDeps {
  repos: Repositories;
  eventBus: EventBus;
  workerRuntime: WorkerRuntime;
  compiler: TaskCompiler;
  normalizer: ResultNormalizer;
  toolGateway: ToolGateway;
  quota: QuotaManager;
  tokenBudgets: TokenBudgeter;
  options?: Partial<SchedulerOptions>;
}

export interface TaskExecutionOutcome {
  task: TaskRecord;
  workerStatus: WorkerResult['status'] | null;
  normalized: NormalizedResult | null;
  retried: boolean;
}

export class TaskScheduler {
  private readonly opts: SchedulerOptions;
  private readonly retryNotBefore = new Map<string, number>();

  constructor(private readonly deps: TaskSchedulerDeps) {
    this.opts = { ...DEFAULT_SCHEDULER_OPTIONS, ...deps.options };
  }

  get options(): SchedulerOptions {
    return { ...this.opts };
  }

  /**
   * Dependency resolution (§33): QUEUED -> READY when every dependency is
   * COMPLETED/PARTIAL; QUEUED -> CANCELLED (cascade) when any dependency
   * failed terminally. Returns the number of tasks promoted.
   */
  async resolveDependencies(engagementId: string): Promise<number> {
    const queued = await this.deps.repos.tasks.listByEngagement(engagementId, {
      statuses: ['QUEUED', 'WAITING'],
      limit: 500,
    });
    let promoted = 0;
    for (const task of queued) {
      if (task.depends_on.length === 0) {
        await this.transition(task, 'READY');
        promoted += 1;
        continue;
      }
      const dependencies = await Promise.all(
        task.depends_on.map((id) => this.deps.repos.tasks.findById(id)),
      );
      const allResolved = dependencies.every((d) => d !== null);
      if (!allResolved) {
        await this.transition(task, 'CANCELLED', 'DEPENDENCY_NOT_FOUND');
        continue;
      }
      const allSucceeded = dependencies.every(
        (d) => d!.status === 'COMPLETED' || d!.status === 'PARTIAL',
      );
      const anyFailed = dependencies.some((d) =>
        ['FAILED', 'CANCELLED', 'EXPIRED'].includes(d!.status),
      );
      if (allSucceeded) {
        await this.transition(task, 'READY');
        promoted += 1;
      } else if (anyFailed) {
        await this.transition(task, 'CANCELLED', 'DEPENDENCY_FAILED');
      }
      // else: dependencies still in-flight; stay WAITING.
    }
    return promoted;
  }

  /**
   * Quota-aware dispatchable selection (§40): READY tasks ordered by
   * priority adjusted for estimated token cost; tasks in retry backoff are
   * skipped; the quota manager gates each dispatch.
   */
  selectDispatchable(
    tasks: TaskRecord[],
    inFlight: ReadonlySet<string>,
    now: number = Date.now(),
  ): { selected: TaskRecord[]; quotaDelayed: number } {
    const candidates = tasks
      .filter((t) => t.status === 'READY')
      .filter((t) => !inFlight.has(t.id))
      .filter((t) => (this.retryNotBefore.get(t.id) ?? 0) <= now);

    const ordered = [...candidates].sort(
      (a, b) =>
        quotaAdjustedPriority(b.priority, this.estimateTaskTokens(b)) -
        quotaAdjustedPriority(a.priority, this.estimateTaskTokens(a)),
    );

    const selected: TaskRecord[] = [];
    let quotaDelayed = 0;
    for (const task of ordered) {
      if (selected.length >= this.opts.maxConcurrentTasks - inFlight.size) break;
      const estimate = this.estimateTaskTokens(task);
      const canDispatch = this.deps.quota.canDispatch(estimate, Math.ceil(estimate * 0.5));
      if (canDispatch.allowed) {
        selected.push(task);
      } else {
        quotaDelayed += 1;
      }
    }
    return { selected, quotaDelayed };
  }

  /** Records a quota delay event (machine-readable, §59). */
  async recordQuotaDelay(engagementId: string, retryAfterMs: number): Promise<void> {
    await this.deps.eventBus.publish({
      type: 'QUOTA_DELAY',
      engagement_id: engagementId,
      task_id: null,
      trace_id: generateId('TRC'),
      actor_id: null,
      payload: { retry_after_ms: retryAfterMs },
      occurred_at: new Date().toISOString(),
    });
  }

  /**
   * Executes one READY task end-to-end: RUNNING -> worker -> normalize ->
   * terminal status (or retry re-queue). Policy gates before RUNNING.
   */
  async executeTask(
    task: TaskRecord,
    input: { runId: string; engagement: EngagementRecord; scope: ScopeRecord | null },
  ): Promise<TaskExecutionOutcome> {
    const { repos } = this.deps;

    // Policy gate (§67): is this action allowed right now?
    const policy = new AgentPolicy();
    const budget = await repos.budgets.getOrDefault(task.engagement_id, {});
    const usage = await repos.budgets.getUsage(task.engagement_id);
    const policyDecision = policy.evaluateTask(
      { engagement: input.engagement, scope: input.scope, usage, budget },
      { type: task.type, worker_type: task.worker_type, allowed_tools: task.allowed_tools },
    );
    if (policyDecision.outcome === 'DENY') {
      await repos.tasks.recordFailure(task.id, 'POLICY_DENIED', policyDecision.reason);
      await this.transition(task, 'FAILED', policyDecision.rule);
      return { task: (await repos.tasks.findById(task.id))!, workerStatus: null, normalized: null, retried: false };
    }
    if (policyDecision.outcome === 'REQUIRE_USER_APPROVAL') {
      await repos.tasks.recordFailure(task.id, 'USER_APPROVAL_REQUIRED', policyDecision.reason);
      await this.transition(task, 'WAITING', policyDecision.rule);
      return { task: (await repos.tasks.findById(task.id))!, workerStatus: null, normalized: null, retried: false };
    }

    // RUNNING transition + attempt increment — Part 6 §55-§56: a DB-level
    // claim. The conditional UPDATE atomically moves READY/QUEUED -> RUNNING,
    // increments attempts and takes the lease. A second engine instance can
    // never claim the same task; a null result means another writer won.
    TaskStateMachine.assertTransition(task.status, 'RUNNING');
    const claimed = await repos.tasks.claimForExecution(
      task.id,
      this.opts.leaseOwner ?? 'scheduler',
      this.opts.taskLeaseMs ?? 120_000,
    );
    if (!claimed) {
      // Another engine instance claimed it first — treat as no-op.
      return { task: (await repos.tasks.findById(task.id))!, workerStatus: null, normalized: null, retried: false };
    }
    await this.deps.eventBus.publish({
      type: 'TASK_STARTED',
      engagement_id: task.engagement_id,
      task_id: task.id,
      trace_id: generateId('TRC'),
      actor_id: null,
      payload: {},
      occurred_at: new Date().toISOString(),
    });
    const running = claimed;

    await this.deps.eventBus.publish({
      type: 'TASK_DISPATCHED',
      engagement_id: task.engagement_id,
      task_id: task.id,
      trace_id: generateId('TRC'),
      actor_id: null,
      payload: {
        run_id: input.runId,
        attempt: running.attempts,
        worker_type: running.worker_type,
      },
      occurred_at: new Date().toISOString(),
      dedup_key: `task-dispatched:${task.id}:${running.attempts}`,
    });

    // Build the packet from PERSISTED state (§19: never model memory).
    const packet = await this.deps.compiler.packetForTask(running);
    packet.run_id = input.runId;
    packet.identity_id =
      (typeof running.inputs.identity_id === 'string' && running.inputs.identity_id) ||
      (typeof running.inputs.identity === 'string' && running.inputs.identity) ||
      null;

    // Execute via the worker runtime; the gateway is the only tool path (§69).
    const result = await this.deps.workerRuntime.runTask(packet, {
      engagementId: task.engagement_id,
      runId: input.runId,
      attemptNumber: running.attempts,
      scope: AgentPolicy.scopeRules(input.scope),
      permissions: {
        network: input.scope !== null,
        // Part 3: browser tools are real; the gateway still enforces the
        // BROWSER capability + scope per invocation (§69).
        browser: input.scope !== null,
        destructive: input.scope?.destructive_actions_allowed ?? false,
        // Part 5 §84: live web knowledge access is granted only when the
        // engagement has a scope (authorized testing context) and the
        // knowledge subsystem is enabled; the gateway still fail-closes
        // on the capability check.
        knowledgeWeb: input.scope !== null,
      },
      toolGateway: this.deps.toolGateway,
      requestId: generateId('REQ'),
    });

    // Normalize the result (§42) — observations, hypothesis updates.
    const normalized = await this.deps.normalizer.normalize(running, result, {
      runId: input.runId,
    });

    // Task status mapping + retry decision (§43).
    const targetStatus = taskStatusForWorkerStatus(result.status);
    // Prefer the worker's own structured error code (WORKER_TURN_INVALID,
    // WORKER_DURATION_EXCEEDED, model codes...) over the generic mapping.
    const failureCode = result.error?.code ?? failureCodeForWorkerStatus(result.status);

    if (targetStatus === 'FAILED') {
      const classification = classifyError(
        Object.assign(new Error(result.error?.message ?? 'worker failure'), {
          code: PERMANENT_WORKER_CODES.has(failureCode) ? 'WORKER_OUTPUT_INVALID' : 'MODEL_REQUEST_FAILED',
        }),
      );
      const canRetry =
        !PERMANENT_WORKER_CODES.has(failureCode) &&
        classification.retryable &&
        running.attempts < running.max_attempts;

      await repos.tasks.recordFailure(
        task.id,
        failureCode,
        result.error?.message ?? 'Worker failed without error detail',
      );
      await repos.tasks.attachResult(task.id, {
        worker_status: result.status,
        summary: normalized.summary,
        ...(result.needs ? { needs: result.needs } : {}),
        ...(result.error ? { error: result.error } : {}),
      });

      if (canRetry) {
        this.retryNotBefore.set(task.id, Date.now() + this.opts.retryDelayMs);
        // Retry re-queue: RUNNING -> QUEUED; dependency resolution promotes
        // it back to READY after the backoff (§44 bounded attempts).
        await this.transition(running, 'QUEUED');
        await this.deps.eventBus.publish({
          type: 'TASK_RETRY',
          engagement_id: task.engagement_id,
          task_id: task.id,
          trace_id: generateId('TRC'),
          actor_id: null,
          payload: {
            attempt: running.attempts,
            next_attempt: running.attempts + 1,
            code: failureCode,
            delay_ms: this.opts.retryDelayMs,
          },
          occurred_at: new Date().toISOString(),
        });
        return {
          task: (await repos.tasks.findById(task.id))!,
          workerStatus: result.status,
          normalized,
          retried: true,
        };
      }

      await this.transition(running, 'FAILED', failureCode);
      await this.deps.eventBus.publish({
        type: 'TASK_FAILED',
        engagement_id: task.engagement_id,
        task_id: task.id,
        trace_id: generateId('TRC'),
        actor_id: null,
        payload: { code: failureCode, attempts: running.attempts, ...(result.needs ? { needs: result.needs } : {}) },
        occurred_at: new Date().toISOString(),
      });
      return { task: (await repos.tasks.findById(task.id))!, workerStatus: result.status, normalized, retried: false };
    }

    // COMPLETED / PARTIAL.
    await repos.tasks.attachResult(task.id, {
      worker_status: result.status,
      summary: normalized.summary,
      observations: normalized.observations.map((o) => o.id),
    });
    await this.transition(running, targetStatus);
    await this.deps.eventBus.publish({
      type: targetStatus === 'COMPLETED' ? 'TASK_COMPLETED' : 'TASK_COMPLETED',
      engagement_id: task.engagement_id,
      task_id: task.id,
      trace_id: generateId('TRC'),
      actor_id: null,
      payload: {
        status: targetStatus,
        observations: normalized.observations.length,
        hypotheses_updated: normalized.hypothesesUpdated.length,
        findings: normalized.findingsPromoted.length,
      },
      occurred_at: new Date().toISOString(),
      dedup_key: `task-completed:${task.id}`,
    });

    // Token bookkeeping for the worker purpose.
    this.deps.tokenBudgets.record(
      task.type === 'VERIFICATION' ? 'verification' : 'worker',
      result.usage.inputTokens,
      result.usage.outputTokens,
    );

    return { task: (await repos.tasks.findById(task.id))!, workerStatus: result.status, normalized, retried: false };
  }

  /** Human/task cancellation with dependents cascade (§45-§46). */
  async cancelTask(task: TaskRecord, reason: string): Promise<TaskRecord> {
    if (TERMINAL_TASK_STATUSES.includes(task.status)) return task;
    await this.transition(task, 'CANCELLED', reason);
    // Cascade: cancel queued dependents.
    const all = await this.deps.repos.tasks.listByEngagement(task.engagement_id, { limit: 500 });
    for (const other of all) {
      if (other.status === 'QUEUED' || other.status === 'WAITING' || other.status === 'READY') {
        if (other.depends_on.includes(task.id)) {
          await this.transition(other, 'CANCELLED', `dependency ${task.id} cancelled`);
        }
      }
    }
    return (await this.deps.repos.tasks.findById(task.id))!;
  }

  private async transition(task: TaskRecord, to: TaskStatus, reason?: string): Promise<void> {
    if (task.status === to) return;
    TaskStateMachine.assertTransition(task.status, to);
    await this.deps.repos.tasks.updateStatus(task.id, to);
    // Part 6 §55: terminal transitions release the lease.
    if (TERMINAL_TASK_STATUSES.includes(to) || to === 'QUEUED' || to === 'WAITING') {
      await this.deps.repos.tasks.releaseLease(task.id);
    }
    // NOTE: failure codes are recorded by the CALLER (recordFailure) so the
    // specific worker error code is never overwritten by a generic one.
    // `reason` is only used for event payloads here.
    void reason;
    if (to === 'RUNNING') {
      await this.deps.eventBus.publish({
        type: 'TASK_STARTED',
        engagement_id: task.engagement_id,
        task_id: task.id,
        trace_id: generateId('TRC'),
        actor_id: null,
        payload: {},
        occurred_at: new Date().toISOString(),
      });
    } else if (to === 'CANCELLED') {
      await this.deps.eventBus.publish({
        type: 'TASK_CANCELLED',
        engagement_id: task.engagement_id,
        task_id: task.id,
        trace_id: generateId('TRC'),
        actor_id: null,
        payload: { ...(reason ? { reason } : {}) },
        occurred_at: new Date().toISOString(),
      });
    }
  }

  private estimateTaskTokens(task: TaskRecord): number {
    return estimateTokens(task.objective) + estimateTokens(JSON.stringify(task.inputs)) + 800;
  }
}
