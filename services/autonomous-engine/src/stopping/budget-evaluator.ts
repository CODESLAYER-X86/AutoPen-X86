/**
 * Budget evaluator (spec Part 6 §42-§43, §78).
 *
 * Tracks engagement budgets: max model requests, input/output tokens,
 * network requests, execution time, parallel tasks. Emits threshold
 * warnings at 80% and exhaustion events; the engine downgrades or stops
 * when budgets are exhausted (§42: stop or downgrade — never silently
 * exceed).
 */
import type { Repositories, EngagementRecord } from '@aegis/database';
import type { PlatformEvent } from '@aegis/contracts';
import type { EventBus } from '@aegis/events';
import { generateId, type AutonomousPhase } from '@aegis/shared';

export interface BudgetStatus {
  usage: Record<string, number>;
  limits: Record<string, number | null>;
  ratios: Record<string, number | null>;
  exhausted: string[];
  nearLimit: string[];
  phaseRecommendation: AutonomousPhase | null;
  warning: string | null;
}

const THRESHOLD = 0.8;

export class BudgetEvaluator {
  constructor(
    private readonly deps: { repos: Repositories; eventBus: EventBus },
  ) {}

  /** Evaluate the engagement budget (§42). */
  async evaluate(engagement: EngagementRecord): Promise<BudgetStatus> {
    const budget = await this.deps.repos.budgets.getOrDefault(engagement.id, {});
    const usage = await this.deps.repos.budgets.getUsage(engagement.id);

    const usageRecord = usage as unknown as Record<string, number>;
    const limits: Record<string, number | null> = {
      model_calls: budget.max_model_calls ?? null,
      model_tokens: budget.max_model_tokens ?? null,
      network_requests: budget.max_network_requests ?? null,
      duration_seconds: budget.max_duration_seconds ?? null,
    };

    const ratios: Record<string, number | null> = {};
    const exhausted: string[] = [];
    const nearLimit: string[] = [];

    for (const [key, limit] of Object.entries(limits)) {
      const used = usageRecord[key] ?? 0;
      if (limit === null || limit <= 0) {
        ratios[key] = null;
        continue;
      }
      const ratio = used / limit;
      ratios[key] = Number(ratio.toFixed(3));
      if (ratio >= 1) exhausted.push(key);
      else if (ratio >= THRESHOLD) nearLimit.push(key);
    }

    // Time budget from the engagement start.
    const durationLimit = limits.duration_seconds ?? null;
    if (durationLimit !== null && engagement.started_at) {
      const elapsedSeconds = (Date.now() - Date.parse(engagement.started_at)) / 1000;
      const ratio = elapsedSeconds / durationLimit;
      ratios.duration_seconds = Number(ratio.toFixed(3));
      if (ratio >= 1) exhausted.push('duration_seconds');
      else if (ratio >= THRESHOLD) nearLimit.push('duration_seconds');
    }

    let phaseRecommendation: AutonomousPhase | null = null;
    if (exhausted.length > 0) phaseRecommendation = 'STOPPED';
    else if (nearLimit.length > 0) phaseRecommendation = 'WAITING_FOR_QUOTA';

    const warning = exhausted.length > 0
      ? `budget exhausted: ${exhausted.join(', ')} (§42)`
      : nearLimit.length > 0
        ? `budget near limit: ${nearLimit.join(', ')} (§42)`
        : null;

    if (warning) {
      const event: PlatformEvent = {
        type: exhausted.length > 0 ? 'STOP_CONDITION_MET' : 'BUDGET_THRESHOLD_EXCEEDED',
        engagement_id: engagement.id,
        trace_id: generateId('TRC'),
        actor_id: null,
        payload: { reason: exhausted.length > 0 ? 'BUDGET_EXHAUSTED' : 'BUDGET_THRESHOLD', fields: exhausted.length > 0 ? exhausted : nearLimit, ratios },
        occurred_at: new Date().toISOString(),
        dedup_key: `budget:${engagement.id}:${exhausted.length > 0 ? 'exhausted' : 'near'}:${Object.entries(ratios).filter(([, v]) => v !== null).map(([k, v]) => `${k}=${v}`).join(',')}`,
      };
      await this.deps.eventBus.publish(event).catch(() => undefined);
    }

    return { usage: usageRecord, limits, ratios, exhausted, nearLimit, phaseRecommendation, warning };
  }
}
