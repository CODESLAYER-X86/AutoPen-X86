/**
 * Queue abstraction (spec §4: "job queue ... Do not hard-code the
 * application around one queue provider").
 *
 * `InMemoryQueue` is the Part 1 provider: priority-ordered jobs, bounded
 * concurrency, per-job timeout, retry with backoff. The interface is
 * provider-agnostic so a Redis/BullMQ-backed implementation can replace it
 * without touching callers.
 */
import { generateId } from '@aegis/shared';

export interface QueueJob<T = unknown> {
  id: string;
  type: string;
  payload: T;
  priority: number;
  attempts: number;
  maxAttempts: number;
  enqueuedAt: string;
}

export type JobHandler = (job: QueueJob) => Promise<void>;

export interface EnqueueOptions {
  priority?: number;
  maxAttempts?: number;
}

export interface QueueStats {
  pending: number;
  active: number;
  completed: number;
  failed: number;
}

export interface Queue {
  enqueue(type: string, payload: unknown, options?: EnqueueOptions): Promise<QueueJob>;
  process(type: string, handler: JobHandler): void;
  start(): void;
  stop(): Promise<void>;
  stats(): QueueStats;
}

interface QueueOptions {
  concurrency?: number;
  pollIntervalMs?: number;
  jobTimeoutMs?: number;
  baseRetryDelayMs?: number;
}

const DEFAULTS: Required<QueueOptions> = {
  concurrency: 2,
  pollIntervalMs: 25,
  jobTimeoutMs: 30_000,
  baseRetryDelayMs: 500,
};

interface InternalJob extends QueueJob {
  availableAt: number;
}

export class InMemoryQueue implements Queue {
  private readonly opts: Required<QueueOptions>;
  private readonly pending: InternalJob[] = [];
  private readonly handlers = new Map<string, JobHandler>();
  private active = 0;
  private completed = 0;
  private failed = 0;
  private running = false;
  private timer: NodeJS.Timeout | null = null;

  constructor(options: QueueOptions = {}) {
    this.opts = { ...DEFAULTS, ...options };
  }

  async enqueue(
    type: string,
    payload: unknown,
    options: EnqueueOptions = {},
  ): Promise<QueueJob> {
    const job: InternalJob = {
      id: generateId('JOB'),
      type,
      payload,
      priority: options.priority ?? 0,
      attempts: 0,
      maxAttempts: options.maxAttempts ?? 3,
      enqueuedAt: new Date().toISOString(),
      availableAt: Date.now(),
    };
    // Higher priority value = processed earlier.
    const index = this.pending.findIndex((j) => j.priority < job.priority);
    if (index === -1) this.pending.push(job);
    else this.pending.splice(index, 0, job);
    this.drain();
    return { ...job };
  }

  process(type: string, handler: JobHandler): void {
    this.handlers.set(type, handler);
  }

  start(): void {
    if (this.running) return;
    this.running = true;
    this.timer = setInterval(() => this.drain(), this.opts.pollIntervalMs);
    this.timer.unref?.();
  }

  async stop(): Promise<void> {
    this.running = false;
    if (this.timer) clearInterval(this.timer);
    this.timer = null;
    // Wait briefly for active jobs to settle (best effort).
    const deadline = Date.now() + 2000;
    while (this.active > 0 && Date.now() < deadline) {
      await new Promise((resolve) => setTimeout(resolve, 25));
    }
  }

  stats(): QueueStats {
    return {
      pending: this.pending.length,
      active: this.active,
      completed: this.completed,
      failed: this.failed,
    };
  }

  private drain(): void {
    if (!this.running) return; // Jobs only execute after start().
    while (this.active < this.opts.concurrency && this.pending.length > 0) {
      const now = Date.now();
      const index = this.pending.findIndex((job) => job.availableAt <= now);
      if (index === -1) return;
      const job = this.pending.splice(index, 1)[0]!;
      void this.run(job);
    }
  }

  private async run(job: InternalJob): Promise<void> {
    const handler = this.handlers.get(job.type);
    this.active += 1;
    try {
      if (!handler) {
        throw new Error(`No handler registered for job type '${job.type}'`);
      }
      await withTimeout(handler({ ...job }), this.opts.jobTimeoutMs, job.id);
      this.completed += 1;
    } catch (error) {
      job.attempts += 1;
      if (job.attempts < job.maxAttempts) {
        // Exponential backoff, capped at 5 seconds.
        const delay = Math.min(
          this.opts.baseRetryDelayMs * 2 ** (job.attempts - 1),
          5_000,
        );
        job.availableAt = Date.now() + delay;
        this.pending.push(job);
        this.drain();
      } else {
        this.failed += 1;
      }
      void error;
    } finally {
      this.active -= 1;
      this.drain();
    }
  }
}

function withTimeout(promise: Promise<void>, ms: number, jobId: string): Promise<void> {
  return new Promise<void>((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error(`Job ${jobId} timed out after ${ms}ms`)), ms);
    timer.unref?.();
    promise.then(
      () => {
        clearTimeout(timer);
        resolve();
      },
      (error) => {
        clearTimeout(timer);
        reject(error);
      },
    );
  });
}
