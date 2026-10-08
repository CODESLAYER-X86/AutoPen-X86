/**
 * Anti-loop protection + oscillation detection (spec Part 2 §51-§52).
 *
 * Repetition detection (configurable thresholds):
 *  - same hypothesis repeatedly tested
 *  - same target/endpoint repeatedly queried
 *  - same worker type repeatedly failing
 *  - leader repeatedly proposing rejected decisions
 *
 * Oscillation detection: strategy focus alternating A -> B -> A -> B without
 * new evidence between flips. When detected: record the event, force an
 * evidence review, require a distinguishing test, or stop that branch.
 */
import type { Repositories } from '@aegis/database';
import type { EventBus } from '@aegis/events';
import { generateId } from '@aegis/shared';

export interface AntiLoopThresholds {
  maxTestsPerHypothesis: number;
  maxTestsPerTarget: number;
  maxWorkerFailures: number;
  maxConsecutiveRejectedDecisions: number;
  oscillationWindow: number;
}

export const DEFAULT_ANTI_LOOP_THRESHOLDS: AntiLoopThresholds = {
  maxTestsPerHypothesis: 4,
  maxTestsPerTarget: 6,
  maxWorkerFailures: 4,
  maxConsecutiveRejectedDecisions: 3,
  oscillationWindow: 4,
};

export type AntiLoopAction =
  | { type: 'MARK_DEAD_END'; hypothesisId: string; reason: string }
  | { type: 'REDUCE_PRIORITY'; target: string; reason: string }
  | { type: 'PAUSE_STRATEGY'; reason: string }
  | { type: 'REQUEST_ALTERNATIVE_HYPOTHESIS'; reason: string };

export interface AntiLoopReport {
  actions: AntiLoopAction[];
  signals: Record<string, number>;
  oscillation: {
    detected: boolean;
    focuses: string[];
    evidenceSinceLastChange: boolean;
  };
}

export interface AntiLoopDeps {
  repos: Repositories;
  eventBus: EventBus;
  thresholds?: Partial<AntiLoopThresholds>;
}

export class AntiLoopDetector {
  private readonly thresholds: AntiLoopThresholds;

  constructor(private readonly deps: AntiLoopDeps) {
    this.thresholds = { ...DEFAULT_ANTI_LOOP_THRESHOLDS, ...deps.thresholds };
  }

  get thresholdSet(): AntiLoopThresholds {
    return { ...this.thresholds };
  }

  async evaluate(engagementId: string, runId: string): Promise<AntiLoopReport> {
    const { repos } = this.deps;
    const actions: AntiLoopAction[] = [];
    const signals: Record<string, number> = {};

    // -- Same hypothesis repeatedly tested (§51) --
    const tests = await repos.tests.listByEngagement(engagementId, 500);
    const testsPerHypothesis = new Map<string, number>();
    for (const test of tests) {
      if (!test.hypothesis_id) continue;
      testsPerHypothesis.set(test.hypothesis_id, (testsPerHypothesis.get(test.hypothesis_id) ?? 0) + 1);
    }
    for (const [hypothesisId, count] of testsPerHypothesis) {
      if (count >= this.thresholds.maxTestsPerHypothesis) {
        signals[`tests_per_hypothesis:${hypothesisId}`] = count;
        actions.push({
          type: 'MARK_DEAD_END',
          hypothesisId,
          reason: `${count} tests registered against this hypothesis without resolution (max ${this.thresholds.maxTestsPerHypothesis})`,
        });
      }
    }

    // -- Same target repeatedly queried (§51) --
    const testsPerTarget = new Map<string, number>();
    for (const test of tests) {
      testsPerTarget.set(test.target, (testsPerTarget.get(test.target) ?? 0) + 1);
    }
    for (const [target, count] of testsPerTarget) {
      if (count >= this.thresholds.maxTestsPerTarget) {
        signals[`tests_per_target:${target}`] = count;
        actions.push({
          type: 'REDUCE_PRIORITY',
          target,
          reason: `${count} tests already target '${target}'; further work there is deprioritized`,
        });
      }
    }

    // -- Same worker repeatedly failing (§51) --
    const workerTypes = ['HTTP_WORKER', 'BROWSER_WORKER', 'SOURCE_WORKER', 'ANALYSIS_WORKER'] as const;
    for (const workerType of workerTypes) {
      const failures = await repos.taskAttempts.countWorkerFailures(engagementId, workerType);
      if (failures >= this.thresholds.maxWorkerFailures) {
        signals[`worker_failures:${workerType}`] = failures;
        actions.push({
          type: 'REDUCE_PRIORITY',
          target: workerType,
          reason: `${workerType} failed ${failures} times; routing away from this worker type`,
        });
      }
    }

    // -- Leader repeatedly proposing rejected decisions (§51) --
    const decisions = await repos.agentDecisions.listByRun(runId, 50);
    let consecutiveRejected = 0;
    for (const decision of [...decisions].sort((a, b) => b.cycle - a.cycle)) {
      if (decision.validation_status === 'REJECTED' || decision.validation_status === 'FAILED') {
        consecutiveRejected += 1;
      } else {
        break;
      }
    }
    if (consecutiveRejected >= this.thresholds.maxConsecutiveRejectedDecisions) {
      signals.consecutive_rejected_decisions = consecutiveRejected;
      actions.push({
        type: 'REQUEST_ALTERNATIVE_HYPOTHESIS',
        reason: `${consecutiveRejected} consecutive leader decisions were rejected; a different investigation direction is required`,
      });
    }

    // -- Oscillation detection (§52) --
    const oscillation = await this.detectOscillation(engagementId);
    if (oscillation.detected && !oscillation.evidenceSinceLastChange) {
      signals.oscillation = 1;
      actions.push({
        type: 'PAUSE_STRATEGY',
        reason: `Strategy focus oscillates (${oscillation.focuses.join(' -> ')}) without new evidence; a distinguishing test or branch stop is required`,
      });
    }

    // Record the protection event when any action fires (§59).
    if (actions.length > 0) {
      await this.deps.eventBus.publish({
        type: 'LOOP_PROTECTION_TRIGGERED',
        engagement_id: engagementId,
        task_id: null,
        trace_id: generateId('TRC'),
        actor_id: null,
        payload: {
          run_id: runId,
          actions: actions.map((a) => a.type),
          signals,
        },
        occurred_at: new Date().toISOString(),
      });
    }

    return { actions, signals, oscillation };
  }

  /**
   * Oscillation: focus sequence of the last strategies alternates between
   * two values (A, B, A, B) — and no new observations arrived since the
   * second-to-last strategy change (evidence must justify direction flips).
   */
  async detectOscillation(engagementId: string): Promise<{
    detected: boolean;
    focuses: string[];
    evidenceSinceLastChange: boolean;
  }> {
    const strategies = await this.deps.repos.strategies.listByEngagement(
      engagementId,
      this.thresholds.oscillationWindow,
    );
    const ordered = [...strategies].sort((a, b) => a.version - b.version);
    const focuses = ordered.map((s) => s.focus);

    let detected = false;
    if (focuses.length >= this.thresholds.oscillationWindow) {
      const window = focuses.slice(-this.thresholds.oscillationWindow);
      detected = isAlternating(window);
    }

    // Evidence since the second-to-last strategy change.
    let evidenceSinceLastChange = false;
    if (ordered.length >= 2) {
      const secondToLast = ordered[ordered.length - 2]!;
      const observations = await this.deps.repos.observations.listByEngagement(engagementId, 200);
      evidenceSinceLastChange = observations.some(
        (o) => Date.parse(o.created_at) > Date.parse(secondToLast.created_at),
      );
    } else {
      evidenceSinceLastChange = true; // not enough history to oscillate
    }

    if (detected) {
      await this.deps.eventBus.publish({
        type: 'OSCILLATION_DETECTED',
        engagement_id: engagementId,
        task_id: null,
        trace_id: generateId('TRC'),
        actor_id: null,
        payload: { focuses, evidence_since_last_change: evidenceSinceLastChange },
        occurred_at: new Date().toISOString(),
      });
    }

    return { detected, focuses, evidenceSinceLastChange };
  }
}

/** [A, B, A, B] or [A, A, B, B]? Only strict alternation counts. */
function isAlternating(values: string[]): boolean {
  if (values.length < 4) return false;
  const distinct = new Set(values);
  if (distinct.size !== 2) return false;
  for (let i = 1; i < values.length; i += 1) {
    if (values[i] === values[i - 1]) return false;
  }
  return true;
}
