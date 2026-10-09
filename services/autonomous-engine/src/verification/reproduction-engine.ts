/**
 * Reproduction engine (spec Part 6 §26-§27).
 *
 * Verification strategies include "repeat test" and "independent
 * observation": a behavior that cannot be reproduced must not become a
 * verified finding. When a SUPPORTED hypothesis lacks reproduction
 * evidence, the reproduction engine plans a bounded repeat of the
 * original test (independent request, same fingerprint family).
 */
import type { Repositories, TaskRecord } from '@aegis/database';

export interface ReproductionPlan {
  hypothesisId: string;
  originalTaskId: string | null;
  required: boolean;
  reason: string;
  repeatCount: number;
}

export class ReproductionEngine {
  constructor(private readonly repos: Repositories) {}

  /**
   * Decide whether reproduction is required for a hypothesis (§27):
   * required when the supporting test has no recorded verdict repetition.
   */
  async plan(engagementId: string, hypothesisId: string): Promise<ReproductionPlan> {
    const links = await this.repos.hypotheses.linksByHypothesis(hypothesisId);
    const testIds = links.filter((l) => l.ref_type === 'TEST').map((l) => l.ref_id);
    const allTests = await this.repos.tests.listByEngagement(engagementId, 200);
    const hypothesisTests = allTests.filter((t) => t.hypothesis_id === hypothesisId || testIds.includes(t.id));
    const concluded = hypothesisTests.filter((t) => t.status === 'COMPLETED' && t.result && t.result !== 'INCONCLUSIVE');

    if (concluded.length === 0) {
      return {
        hypothesisId,
        originalTaskId: hypothesisTests[0]?.task_id ?? null,
        required: true,
        reason: 'no concluded test yet — verify after the test completes (§27)',
        repeatCount: 0,
      };
    }

    // Reproduction evidence: the same fingerprint concluded more than once,
    // or two different fingerprints concluding the same direction.
    const byFingerprint = new Map<string, number>();
    for (const test of concluded) {
      byFingerprint.set(test.fingerprint, (byFingerprint.get(test.fingerprint) ?? 0) + 1);
    }
    const reproduced = [...byFingerprint.values()].some((count) => count > 1) || byFingerprint.size > 1;

    return {
      hypothesisId,
      originalTaskId: concluded[0]?.task_id ?? null,
      required: !reproduced,
      reason: reproduced
        ? 'reproduction evidence present (independent conclusion)'
        : 'single observation only — one more independent confirmation required (§27)',
      repeatCount: reproduced ? 0 : 1,
    };
  }

  /** Bounded repeat task spec for reproduction (§26 repeat test strategy). */
  reproductionTask(original: TaskRecord): {
    objective: string;
    task_type: string;
    worker_type: string;
    hypothesis_id: string | null;
    inputs: Record<string, unknown>;
  } | null {
    if (original.hypothesis_id === null) return null;
    return {
      objective: `Reproduce the previously observed behavior for hypothesis ${original.hypothesis_id}: repeat the exact same structured request and confirm the outcome matches the recorded signal (independent reproduction, §26).`,
      task_type: original.type,
      worker_type: original.worker_type,
      hypothesis_id: original.hypothesis_id,
      inputs: {
        ...original.inputs,
        mode: 'REPRODUCTION',
        reproduce_of: original.id,
        instruction:
          'Repeat the recorded test EXACTLY (same base request, same mutations). Do not vary parameters — reproduction requires identical conditions (§27).',
      },
    };
  }
}
