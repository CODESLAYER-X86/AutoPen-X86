/**
 * Retry manager (spec Part 6 §40 anti-loop controls).
 *
 * Tracks failure fingerprints (failure code + target + task type). After a
 * configurable threshold the engine STOPS RETRYING unless the plan is
 * materially different (§40). Combined with the Part 2 test-registry
 * fingerprints (execution duplicates) this covers: same task repeated, same
 * mutation repeated, same failure repeated.
 */
import { createHash } from 'node:crypto';
import type { Repositories, TaskRecord } from '@aegis/database';

export interface RetryManagerOptions {
  maxRepeatsPerFingerprint: number;
}

interface FailureCounter {
  count: number;
  lastCode: string | null;
  lastAt: number;
}

export class RetryManager {
  private readonly counters = new Map<string, FailureCounter>();

  constructor(
    private readonly repos: Repositories | null,
    private readonly opts: RetryManagerOptions,
  ) {}

  /** Fingerprint of a failure (§40): code + task identity. */
  static fingerprint(task: TaskRecord, code: string | null): string {
    return createHash('sha256')
      .update(`${task.engagement_id}:${task.type}:${task.worker_type}:${task.failure_code ?? code ?? ''}:${task.objective.slice(0, 120)}`)
      .digest('hex')
      .slice(0, 32);
  }

  /**
   * Record a failure and decide whether retrying is allowed (§40). After
   * the threshold the task is escalated to FAILED with LOOP_PROTECTION.
   */
  async recordFailure(task: TaskRecord, code: string | null): Promise<{ allowRetry: boolean; repeats: number }> {
    const fingerprint = RetryManager.fingerprint(task, code);
    const counter = this.counters.get(fingerprint) ?? { count: 0, lastCode: code, lastAt: Date.now() };
    counter.count += 1;
    counter.lastCode = code;
    counter.lastAt = Date.now();
    this.counters.set(fingerprint, counter);

    const allowRetry = counter.count < this.opts.maxRepeatsPerFingerprint;
    if (!allowRetry) {
      await this.repos?.tasks
        .recordFailure(task.id, 'LOOP_PROTECTION', `same failure repeated ${counter.count} times (§40 anti-loop)`)
        .catch(() => undefined);
    }
    return { allowRetry, repeats: counter.count };
  }

  /** Knowledge-query anti-loop (§40): same query repeated. */
  knowledgeQueryRepeatAllowed(currentRepeats: number, max: number): boolean {
    return currentRepeats < max;
  }

  /** Reset counters for an engagement's recovered tasks (new plan, §40). */
  reset(): void {
    this.counters.clear();
  }
}
