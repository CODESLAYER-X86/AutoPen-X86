/**
 * Request rate control + concurrency (spec Part 3 §53-§54).
 *
 * Every HTTP request passes through:
 *   engagement rate limiter + target(host) rate limiter + worker budget +
 *   global resource manager. The model cannot bypass rate limits — the
 * engine applies them deterministically before any socket is opened.
 *
 * Implementation: sliding-window counters per (engagement) and per
 * (engagement, host) key, plus counting semaphores for concurrency per
 * host / per engagement / global. All in-memory, single-process — the
 * same model as the Part 2 QuotaManager.
 */
import { PlatformError } from '@aegis/shared';

export class RateLimitError extends PlatformError {
  constructor(
    message: string,
    code = 'HTTP_RATE_LIMITED',
    public readonly retryAfterMs: number | null = null,
  ) {
    super(message, { code, category: 'QUOTA', statusCode: 429, details: { retry_after_ms: retryAfterMs } });
    this.name = 'RateLimitError';
  }
}

export class ConcurrencyError extends PlatformError {
  constructor(message: string, code = 'HTTP_CONCURRENCY_LIMIT') {
    super(message, { code, category: 'QUOTA', statusCode: 429 });
    this.name = 'ConcurrencyError';
  }
}

export interface RateLimiterOptions {
  /** Max requests per window per engagement. */
  perEngagement: number;
  /** Max requests per window per (engagement, host). */
  perHost: number;
  windowMs: number;
}

interface WindowState {
  timestamps: number[];
}

export class SlidingWindowRateLimiter {
  private readonly windows = new Map<string, WindowState>();

  constructor(private readonly options: RateLimiterOptions) {}

  private prune(state: WindowState, now: number): void {
    const cutoff = now - this.options.windowMs;
    while (state.timestamps.length > 0 && state.timestamps[0]! <= cutoff) {
      state.timestamps.shift();
    }
  }

  /** Throws RateLimitError when the request would exceed the window. */
  check(engagementId: string, host: string): void {
    const now = Date.now();
    const keys: Array<[string, number]> = [
      [`eng:${engagementId}`, this.options.perEngagement],
      [`host:${engagementId}:${host.toLowerCase()}`, this.options.perHost],
    ];
    for (const [key, limit] of keys) {
      let state = this.windows.get(key);
      if (!state) {
        state = { timestamps: [] };
        this.windows.set(key, state);
      }
      this.prune(state, now);
      if (state.timestamps.length >= limit) {
        const oldest = state.timestamps[0]!;
        throw new RateLimitError(
          `Rate limit exceeded for ${key} (${limit}/${this.options.windowMs}ms)`,
          'HTTP_RATE_LIMITED',
          Math.max(1, this.options.windowMs - (now - oldest)),
        );
      }
    }
  }

  /** Record consumption after checks pass. */
  consume(engagementId: string, host: string): void {
    const now = Date.now();
    for (const key of [
      `eng:${engagementId}`,
      `host:${engagementId}:${host.toLowerCase()}`,
    ]) {
      let state = this.windows.get(key);
      if (!state) {
        state = { timestamps: [] };
        this.windows.set(key, state);
      }
      state.timestamps.push(now);
    }
  }

  /** Drop stale windows (called opportunistically). */
  gc(): void {
    const now = Date.now();
    for (const [key, state] of this.windows) {
      this.prune(state, now);
      if (state.timestamps.length === 0) this.windows.delete(key);
    }
  }
}

/** Counting semaphore for bounded concurrency (§54). */
export class Semaphore {
  private active = 0;
  private readonly waiters: Array<() => void> = [];

  constructor(public readonly limit: number) {}

  get utilization(): number {
    return this.active;
  }

  async acquire(): Promise<void> {
    if (this.active < this.limit) {
      this.active += 1;
      return;
    }
    await new Promise<void>((resolve) => this.waiters.push(resolve));
    this.active += 1;
  }

  release(): void {
    this.active = Math.max(0, this.active - 1);
    const next = this.waiters.shift();
    if (next) next();
  }
}

export interface ConcurrencyLimits {
  global: number;
  perEngagement: number;
  perHost: number;
}

export class ConcurrencyManager {
  private readonly global: Semaphore;
  private readonly perEngagement = new Map<string, Semaphore>();
  private readonly perHost = new Map<string, Semaphore>();

  constructor(private readonly limits: ConcurrencyLimits) {
    this.global = new Semaphore(limits.global);
  }

  private engagementSemaphore(engagementId: string): Semaphore {
    let sem = this.perEngagement.get(engagementId);
    if (!sem) {
      sem = new Semaphore(this.limits.perEngagement);
      this.perEngagement.set(engagementId, sem);
    }
    return sem;
  }

  private hostSemaphore(engagementId: string, host: string): Semaphore {
    const key = `${engagementId}:${host.toLowerCase()}`;
    let sem = this.perHost.get(key);
    if (!sem) {
      sem = new Semaphore(this.limits.perHost);
      this.perHost.set(key, sem);
    }
    return sem;
  }

  async acquire(engagementId: string, host: string): Promise<() => void> {
    await this.global.acquire();
    const eng = this.engagementSemaphore(engagementId);
    await eng.acquire();
    const hostSem = this.hostSemaphore(engagementId, host);
    await hostSem.acquire();
    let released = false;
    return () => {
      if (released) return;
      released = true;
      hostSem.release();
      eng.release();
      this.global.release();
    };
  }
}
