/**
 * Stop evaluator (spec Part 6 §50).
 *
 * Consolidated stop conditions:
 *   - Objective completed (PENTEST: verified findings + coverage; CTF: flag)
 *   - No useful hypotheses (actionable = 0)
 *   - Budget exhausted
 *   - Scope violation risk
 *   - Repeated failure
 *   - Diminishing returns (recent tests produce negligible information)
 *   - User stop (immediate, handled by control actions)
 */
import type { Repositories, EngagementRecord } from '@aegis/database';
import type { CoverageReport } from '@aegis/contracts';
import { generateId, type StopReason } from '@aegis/shared';
import type { PlatformEvent } from '@aegis/contracts';
import type { EventBus } from '@aegis/events';
import { BudgetEvaluator } from './budget-evaluator.js';

export interface StopDecision {
  shouldStop: boolean;
  reason: StopReason | null;
  detail: string;
}

export interface StopEvaluatorOptions {
  minTests: number;
  minInformationGain: number;
  maxConsecutiveFailures: number;
}

export class StopEvaluator {
  private readonly budget: BudgetEvaluator;

  private readonly deps: { repos: Repositories; eventBus: EventBus };

  constructor(
    deps: { repos: Repositories; eventBus: EventBus },
    private readonly opts: StopEvaluatorOptions,
  ) {
    this.deps = deps;
    this.budget = new BudgetEvaluator(deps);
  }

  /**
   * Evaluate all stop conditions (§50). The engine calls this after every
   * meaningful transition; the FIRST matching condition wins.
   */
  async evaluate(engagement: EngagementRecord, coverage: CoverageReport | null): Promise<StopDecision> {
    // 1. Objective completed — CTF: flag detected (§31).
    if (engagement.mode === 'CTF') {
      const context = await this.deps.repos.ctfContexts.findByEngagement(engagement.id);
      if (context?.status === 'SOLVED') {
        return {
          shouldStop: true,
          reason: 'OBJECTIVE_COMPLETED',
          detail: 'challenge success condition verified (flag evidence, §31)',
        };
      }
    }

    // 2. No useful hypotheses (§50) — only after recon produced a surface.
    const actionable = await this.deps.repos.hypotheses.countActionable(engagement.id);
    const pendingTasks = await this.deps.repos.tasks.listByEngagement(engagement.id, {
      statuses: ['CREATED', 'QUEUED', 'READY', 'RUNNING', 'WAITING', 'RECOVERY_PENDING'],
      limit: 200,
    });
    if (actionable === 0 && pendingTasks.length === 0) {
      const endpoints = await this.deps.repos.endpoints.listByEngagement(engagement.id, { limit: 1 });
      if (endpoints.length > 0) {
        return {
          shouldStop: true,
          reason: 'NO_USEFUL_HYPOTHESES',
          detail: 'no actionable hypotheses remain and no tasks pending (§50)',
        };
      }
    }

    // 3. Budget exhausted (§42).
    const budgetStatus = await this.budget.evaluate(engagement);
    if (budgetStatus.exhausted.length > 0) {
      return {
        shouldStop: true,
        reason: 'BUDGET_EXHAUSTED',
        detail: `exhausted: ${budgetStatus.exhausted.join(', ')}`,
      };
    }

    // 4. Repeated failure (§50) — consecutive task failures.
    const tasks = await this.deps.repos.tasks.listByEngagement(engagement.id, { limit: 100 });
    const recent = tasks.slice(0, this.opts.maxConsecutiveFailures + 2);
    if (
      recent.length >= this.opts.maxConsecutiveFailures &&
      recent
        .slice(0, this.opts.maxConsecutiveFailures)
        .every((task) => task.status === 'FAILED')
    ) {
      return {
        shouldStop: true,
        reason: 'REPEATED_FAILURE',
        detail: `${this.opts.maxConsecutiveFailures} consecutive task failures (§50)`,
      };
    }

    // 5. Diminishing returns (§50): recent tests produce negligible gain.
    const tests = await this.deps.repos.tests.listByEngagement(engagement.id, 100);
    const completed = tests.filter((t) => t.status === 'COMPLETED');
    if (completed.length >= this.opts.minTests) {
      const recentTests = completed.slice(0, this.opts.minTests);
      const recentConcluded = recentTests.filter((t) => t.result && t.result !== 'INCONCLUSIVE' && t.result !== 'FAILED');
      if (recentConcluded.length === 0) {
        return {
          shouldStop: true,
          reason: 'DIMINISHING_RETURNS',
          detail: `last ${this.opts.minTests} completed tests produced no discriminating verdicts (§50)`,
        };
      }
    }

    // 6. Scope violation risk: engagement scope missing while running (§50).
    const scope = await this.deps.repos.scope.findByEngagement(engagement.id);
    if (!scope && engagement.status === 'RUNNING') {
      return {
        shouldStop: true,
        reason: 'SCOPE_VIOLATION_RISK',
        detail: 'engagement scope disappeared while running — cannot safely continue (§50)',
      };
    }

    // 7. Pentest objective: verified findings + reasonable coverage.
    if (engagement.mode === 'PENTEST' && coverage) {
      const verified = await this.deps.repos.findings.listByEngagement(engagement.id, {
        statuses: ['CONFIRMED', 'VERIFIED'],
        limit: 100,
      });
      const conclusive = await this.deps.repos.hypotheses.listByEngagement(engagement.id, {
        statuses: ['CONFIRMED', 'DISPROVED', 'ABANDONED'],
      });
      if (
        verified.length > 0 &&
        conclusive.length > 0 &&
        coverage.endpoint_coverage >= 0.5 &&
        pendingTasks.length === 0 &&
        actionable === 0
      ) {
        return {
          shouldStop: true,
          reason: 'OBJECTIVE_COMPLETED',
          detail: `${verified.length} verified findings; requested coverage achieved (§50)`,
        };
      }
    }

    void this.opts.minInformationGain;
    return { shouldStop: false, reason: null, detail: 'no stop condition met' };
  }

  /** Publish the stop decision (§50 observable). */
  async publish(engagementId: string, reason: StopReason, detail: string): Promise<void> {
    const event: PlatformEvent = {
      type: 'STOP_CONDITION_MET',
      engagement_id: engagementId,
      trace_id: generateId('TRC'),
      actor_id: null,
      payload: { reason, detail },
      occurred_at: new Date().toISOString(),
      dedup_key: `stop:${engagementId}:${reason}`,
    };
    await this.deps.eventBus.publish(event).catch(() => undefined);
  }
}
