/**
 * Quota manager + token budgeting (spec Part 2 §37-§40).
 *
 * QuotaManager: provider-independent, sliding-window rate tracking
 * (requests/minute, input tokens/minute, output tokens/minute, requests/day).
 * All numbers are configurable — never assume the defaults are permanent.
 * Windows combine in-memory tracking with persisted model-call rows so quota
 * survives restarts (best effort: DB rows are authoritative for the day).
 *
 * TokenBudgeter: separate configurable budgets per purpose
 * (leader / worker / knowledge / summarization / verification, §38).
 * Before any dispatch, `canDispatch` estimates input + output + safety
 * margin and refuses to intentionally exceed the configured quota (§39).
 */
import type { TokenPurpose } from '@aegis/shared';
import type { ModelCallsRepository } from '@aegis/database';

export interface QuotaLimits {
  requestsPerMinute: number;
  inputTokensPerMinute: number;
  outputTokensPerMinute: number;
  requestsPerDay: number;
}

export const DEFAULT_QUOTA_LIMITS: QuotaLimits = {
  requestsPerMinute: 60,
  inputTokensPerMinute: 120_000,
  outputTokensPerMinute: 16_000,
  requestsPerDay: 2_000,
};

export interface TokenBudgets {
  leader: number;
  worker: number;
  knowledge: number;
  summarization: number;
  verification: number;
}

export const DEFAULT_TOKEN_BUDGETS: TokenBudgets = {
  leader: 400_000,
  worker: 1_200_000,
  knowledge: 100_000,
  summarization: 50_000,
  verification: 150_000,
};

export interface QuotaSnapshot {
  requestsPerMinute: number;
  inputTokensPerMinute: number;
  outputTokensPerMinute: number;
  requestsPerDay: number;
  limits: QuotaLimits;
  /** Milliseconds until the tightest per-minute window frees capacity. */
  retryAfterMs: number;
}

interface UsageEvent {
  at: number;
  inputTokens: number;
  outputTokens: number;
}

const MINUTE_MS = 60_000;
const DAY_MS = 24 * 60 * 60_000;

/** Safety margin added to estimates before quota checks (spec §39). */
const SAFETY_MARGIN_FACTOR = 1.2;

export class QuotaManager {
  private readonly limits: QuotaLimits;
  private readonly minuteWindow: UsageEvent[] = [];
  private readonly dayCount = { day: Math.floor(Date.now() / DAY_MS), requests: 0 };

  constructor(limits: Partial<QuotaLimits> = {}) {
    this.limits = { ...DEFAULT_QUOTA_LIMITS, ...limits };
  }

  get limitSet(): QuotaLimits {
    return { ...this.limits };
  }

  /** Clears in-memory windows (test isolation / rebase points). */
  reset(): void {
    this.minuteWindow.length = 0;
    this.dayCount.day = Math.floor(Date.now() / DAY_MS);
    this.dayCount.requests = 0;
  }

  /** Records an in-process usage event (called after every model call). */
  recordUsage(inputTokens: number, outputTokens: number, at: number = Date.now()): void {
    this.prune(at);
    this.minuteWindow.push({ at, inputTokens, outputTokens });
    const day = Math.floor(at / DAY_MS);
    if (day !== this.dayCount.day) {
      this.dayCount.day = day;
      this.dayCount.requests = 0;
    }
    this.dayCount.requests += 1;
  }

  /** Re-bases day counters from persisted model calls (crash recovery). */
  async rebaseFromDatabase(engagementId: string, modelCalls: ModelCallsRepository): Promise<void> {
    const dayStart = Date.now() - DAY_MS;
    const result = await modelCalls.recentUsage(engagementId, DAY_MS).catch(() => null);
    void dayStart;
    if (result) {
      this.dayCount.day = Math.floor(Date.now() / DAY_MS);
      this.dayCount.requests = result.requests;
    }
  }

  snapshot(now: number = Date.now()): QuotaSnapshot {
    this.prune(now);
    let inputTokens = 0;
    let outputTokens = 0;
    let requests = 0;
    for (const event of this.minuteWindow) {
      inputTokens += event.inputTokens;
      outputTokens += event.outputTokens;
      requests += 1;
    }
    return {
      requestsPerMinute: requests,
      inputTokensPerMinute: inputTokens,
      outputTokensPerMinute: outputTokens,
      requestsPerDay: this.dayCount.requests,
      limits: { ...this.limits },
      retryAfterMs: this.minuteWindow.length > 0 ? MINUTE_MS - (now - this.minuteWindow[0]!.at) : 0,
    };
  }

  /**
   * Can a request with the given estimated tokens be dispatched now?
   * Returns a denial with a delay when any per-minute window would overflow.
   */
  canDispatch(
    estimatedInputTokens: number,
    estimatedOutputTokens: number,
    now: number = Date.now(),
  ): { allowed: true } | { allowed: false; reason: string; retryAfterMs: number } {
    this.prune(now);
    const snap = this.snapshot(now);

    if (snap.requestsPerDay >= this.limits.requestsPerDay) {
      return {
        allowed: false,
        reason: `Daily request quota exhausted (${snap.requestsPerDay}/${this.limits.requestsPerDay})`,
        retryAfterMs: DAY_MS - (now % DAY_MS),
      };
    }

    const nextRequests = snap.requestsPerMinute + 1;
    if (nextRequests > this.limits.requestsPerMinute) {
      return {
        allowed: false,
        reason: `RPM quota would be exceeded (${nextRequests}/${this.limits.requestsPerMinute})`,
        retryAfterMs: Math.max(snap.retryAfterMs, 250),
      };
    }

    const projectedInput = snap.inputTokensPerMinute + estimatedInputTokens;
    if (projectedInput > this.limits.inputTokensPerMinute) {
      return {
        allowed: false,
        reason: `Input TPM quota would be exceeded (${projectedInput}/${this.limits.inputTokensPerMinute})`,
        retryAfterMs: Math.max(snap.retryAfterMs, 250),
      };
    }

    const projectedOutput = snap.outputTokensPerMinute + estimatedOutputTokens;
    if (projectedOutput > this.limits.outputTokensPerMinute) {
      return {
        allowed: false,
        reason: `Output TPM quota would be exceeded (${projectedOutput}/${this.limits.outputTokensPerMinute})`,
        retryAfterMs: Math.max(snap.retryAfterMs, 250),
      };
    }

    return { allowed: true };
  }

  private prune(now: number): void {
    while (this.minuteWindow.length > 0 && now - this.minuteWindow[0]!.at >= MINUTE_MS) {
      this.minuteWindow.shift();
    }
  }
}

export class TokenBudgeter {
  private readonly budgets: TokenBudgets;
  private readonly spent: Record<TokenPurpose, { input: number; output: number }> = {
    leader: { input: 0, output: 0 },
    worker: { input: 0, output: 0 },
    knowledge: { input: 0, output: 0 },
    summarization: { input: 0, output: 0 },
    verification: { input: 0, output: 0 },
  };

  constructor(budgets: Partial<TokenBudgets> = {}) {
    this.budgets = { ...DEFAULT_TOKEN_BUDGETS, ...budgets };
  }

  get budgetSet(): TokenBudgets {
    return { ...this.budgets };
  }

  remaining(purpose: TokenPurpose): number {
    const spent = this.spent[purpose];
    return Math.max(0, this.budgets[purpose] - spent.input - spent.output);
  }

  /**
   * Worker-context budget gate (spec §39): estimate input + output + safety
   * margin; refuse when the request risks exceeding the configured budget.
   */
  canSpend(
    purpose: TokenPurpose,
    estimatedInputTokens: number,
    estimatedOutputTokens: number,
  ): { allowed: boolean; reason?: string } {
    const projected =
      this.spent[purpose].input +
      this.spent[purpose].output +
      Math.ceil((estimatedInputTokens + estimatedOutputTokens) * SAFETY_MARGIN_FACTOR);
    if (projected > this.budgets[purpose]) {
      return {
        allowed: false,
        reason: `Purpose budget '${purpose}' would be exceeded (projected ${projected} > ${this.budgets[purpose]})`,
      };
    }
    return { allowed: true };
  }

  record(purpose: TokenPurpose, inputTokens: number, outputTokens: number): void {
    this.spent[purpose].input += inputTokens;
    this.spent[purpose].output += outputTokens;
  }

  usage(): Record<TokenPurpose, { input: number; output: number; budget: number }> {
    return {
      leader: { ...this.spent.leader, budget: this.budgets.leader },
      worker: { ...this.spent.worker, budget: this.budgets.worker },
      knowledge: { ...this.spent.knowledge, budget: this.budgets.knowledge },
      summarization: { ...this.spent.summarization, budget: this.budgets.summarization },
      verification: { ...this.spent.verification, budget: this.budgets.verification },
    };
  }
}

/**
 * Rough token estimator (chars / 4). Providers with countTokens can refine;
 * this is the deterministic floor used before dispatch decisions.
 */
export function estimateTokens(text: string): number {
  return Math.ceil(text.length / 4);
}
