/**
 * Execution controller (spec Part 6 §47, §55-§56).
 *
 * Owns the engine instance identity used for task leases, launches the
 * agent-run loop (the Part 2 scheduler remains the ONLY dispatch path), and
 * exposes claim/heartbeat/release for DB-level concurrency control. A task
 * can be claimed by exactly one engine instance at a time (§56).
 */
import type { Repositories, TaskRecord, EngagementRecord } from '@aegis/database';
import { generateId } from '@aegis/shared';

export interface LoopLauncher {
  start(engagement: EngagementRecord, actorId: string | null, reason?: string): Promise<{ runId: string }>;
  pause(engagementId: string, actorId: string | null, reason?: string): Promise<void>;
  resume(engagementId: string, actorId: string | null): Promise<void>;
  cancel(engagementId: string, actorId: string | null, reason?: string): Promise<void>;
}

export interface ExecutionControllerOptions {
  taskLeaseMs: number;
}

export class ExecutionController {
  readonly instanceId: string;

  constructor(
    private readonly deps: { repos: Repositories },
    private readonly opts: ExecutionControllerOptions,
  ) {
    // Engine instance identity — leases are owned by this id (§55).
    this.instanceId = `AEN-${generateId('TRC').slice(4)}`;
  }

  /** Claim a task for this engine instance (atomic conditional update). */
  async claim(taskId: string): Promise<TaskRecord | null> {
    return this.deps.repos.tasks.claimForExecution(taskId, this.instanceId, this.opts.taskLeaseMs);
  }

  /** Extend the lease while the worker is alive (§55 heartbeat). */
  async heartbeat(taskId: string): Promise<boolean> {
    return this.deps.repos.tasks.heartbeat(taskId, this.instanceId, this.opts.taskLeaseMs);
  }

  /** Release a completed task's lease (§55). */
  async release(taskId: string): Promise<void> {
    return this.deps.repos.tasks.releaseLease(taskId);
  }

  /** Running tasks owned by this engine instance. */
  async myRunning(engagementId: string): Promise<TaskRecord[]> {
    const running = await this.deps.repos.tasks.listByEngagement(engagementId, {
      statuses: ['RUNNING'],
      limit: 200,
    });
    return running.filter((task) => task.leased_by === this.instanceId);
  }

  async launchRun(
    launcher: LoopLauncher,
    engagement: EngagementRecord,
    actorId: string | null,
    reason?: string,
  ): Promise<{ runId: string }> {
    await this.deps.repos.autonomousStates.setEngineInstance(engagement.id, this.instanceId);
    return launcher.start(engagement, actorId, reason);
  }
}
