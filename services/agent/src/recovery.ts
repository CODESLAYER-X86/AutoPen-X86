/**
 * Crash recovery (spec Part 2 §63-§65).
 *
 * The agent is restartable: state lives in the database, not memory. On
 * startup/resume:
 *   1. RUNNING tasks become RECOVERY_PENDING (explicit state, §64).
 *   2. For each, the recovery logic inspects the recorded task attempts:
 *      - an attempt with a structured output exists -> the operation
 *        COMPLETED before the crash -> finalize from the recorded output
 *        (avoiding duplicate network actions where possible, §64).
 *      - an attempt exists without output -> the operation may not have
 *        finished -> retry is safe ONLY for idempotent test types; state-
 *        changing types are failed rather than blindly replayed (§65).
 *   3. Idempotency keys ensure task creation and evidence registration are
 *      not duplicated on replay (§65).
 */
import type { TaskRecord, Repositories } from '@aegis/database';
import type { EventBus } from '@aegis/events';
import { generateId, type TaskType } from '@aegis/shared';
import { TaskStateMachine } from './state-machines.js';
import type { ResultNormalizer } from './result-normalizer.js';
import { taskStatusForWorkerStatus } from './result-normalizer.js';

/** Task types that are safe to re-run after an uncertain crash (§65). */
const IDEMPOTENT_TASK_TYPES = new Set<TaskType>([
  'RECON',
  'SOURCE_ANALYSIS',
  'KNOWLEDGE_SUMMARY',
  'CTF_CLUE_ANALYSIS',
  'VERIFICATION',
  'GENERAL_ANALYSIS',
]);

export interface RecoveryReport {
  recovered: number;
  finalizedFromOutput: number;
  requeued: number;
  failed: number;
  details: Array<{ task_id: string; action: 'FINALIZED' | 'REQUEUED' | 'FAILED'; reason: string }>;
}

export interface RecoveryDeps {
  repos: Repositories;
  eventBus: EventBus;
  normalizer: ResultNormalizer;
}

export class CrashRecovery {
  constructor(private readonly deps: RecoveryDeps) {}

  async recoverEngagement(engagementId: string, runId: string | null): Promise<RecoveryReport> {
    const report: RecoveryReport = {
      recovered: 0,
      finalizedFromOutput: 0,
      requeued: 0,
      failed: 0,
      details: [],
    };

    // 1. Mark RUNNING tasks as RECOVERY_PENDING (§64).
    const running = await this.deps.repos.tasks.findRunningByEngagement(engagementId);
    for (const task of running) {
      await this.deps.repos.tasks.updateStatus(task.id, 'RECOVERY_PENDING');
      await this.deps.eventBus.publish({
        type: 'TASK_RECOVERY_PENDING',
        engagement_id: engagementId,
        task_id: task.id,
        trace_id: generateId('TRC'),
        actor_id: null,
        payload: { run_id: runId },
        occurred_at: new Date().toISOString(),
        dedup_key: `task-recovery:${task.id}`,
      });
    }

    // 2. Inspect each RECOVERY_PENDING task's attempts.
    const pending = await this.deps.repos.tasks.listByEngagement(engagementId, {
      statuses: ['RECOVERY_PENDING'],
      limit: 500,
    });
    for (const task of pending) {
      report.recovered += 1;
      const attempts = await this.deps.repos.taskAttempts.listByTask(task.id);
      const lastAttempt = attempts[0];

      if (lastAttempt && lastAttempt.output) {
        // The worker finalized before the crash — apply the recorded output.
        const workerStatus = (lastAttempt.output.status as string) ?? 'COMPLETED';
        const result = {
          task_id: task.id,
          attempt_id: lastAttempt.id,
          status: workerStatus as 'COMPLETED',
          observations: (lastAttempt.output.observations as []) ?? [],
          evidence_ids: (lastAttempt.output.evidence_ids as string[]) ?? [],
          hypothesis_updates: (lastAttempt.output.hypothesis_updates as []) ?? [],
          usage: {
            inputTokens: lastAttempt.input_tokens,
            outputTokens: lastAttempt.output_tokens,
            toolCalls: lastAttempt.tool_calls,
            networkRequests: lastAttempt.network_requests,
            durationMs: lastAttempt.duration_ms ?? 0,
          },
        };
        await this.deps.normalizer.normalize(task, result, { runId: runId ?? task.run_id ?? '' });
        const finalStatus = taskStatusForWorkerStatus(result.status);
        await this.deps.repos.tasks.updateStatus(task.id, finalStatus);
        report.finalizedFromOutput += 1;
        report.details.push({
          task_id: task.id,
          action: 'FINALIZED',
          reason: `attempt ${lastAttempt.attempt} had recorded output; finalized as ${finalStatus}`,
        });
        continue;
      }

      if (IDEMPOTENT_TASK_TYPES.has(task.type)) {
        // Safe to retry: re-queue; the scheduler will rebuild the packet.
        await this.deps.repos.tasks.updateStatus(task.id, 'READY');
        report.requeued += 1;
        report.details.push({
          task_id: task.id,
          action: 'REQUEUED',
          reason: `${task.type} is idempotent; re-queued for retry`,
        });
      } else {
        // State-changing types are NOT blindly replayed (§65).
        await this.deps.repos.tasks.recordFailure(
          task.id,
          'RECOVERY_UNCERTAIN',
          'Task may not have completed before the crash and is not idempotent; manual review required',
        );
        await this.deps.repos.tasks.updateStatus(task.id, 'FAILED');
        report.failed += 1;
        report.details.push({
          task_id: task.id,
          action: 'FAILED',
          reason: `${task.type} is not idempotent; failing rather than replaying a possibly state-changing operation`,
        });
      }
    }

    return report;
  }

  /** Whether a task type is safe to re-run (exposed for the scheduler). */
  static isIdempotent(task: TaskRecord): boolean {
    return IDEMPOTENT_TASK_TYPES.has(task.type);
  }

  /** Validates the transition table stays consistent with recovery states. */
  static assertRecoveryTransition(from: TaskRecord['status'], to: TaskRecord['status']): void {
    TaskStateMachine.assertTransition(from, to);
  }
}
