import { describe, expect, it } from 'vitest';
import { InMemoryQueue } from '@aegis/queue';

function delay(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

describe('in-memory queue abstraction (spec §4)', () => {
  it('processes jobs through registered handlers', async () => {
    const queue = new InMemoryQueue({ concurrency: 1, pollIntervalMs: 5 });
    const processed: string[] = [];
    queue.process('echo', async (job) => {
      processed.push(`${job.id}:${String(job.payload)}`);
    });
    await queue.enqueue('echo', 'one');
    await queue.enqueue('echo', 'two');
    queue.start();
    await delay(150);
    await queue.stop();
    expect(processed.length).toBe(2);
    expect(queue.stats().completed).toBe(2);
  });

  it('respects concurrency limits', async () => {
    const queue = new InMemoryQueue({ concurrency: 2, pollIntervalMs: 5 });
    let active = 0;
    let maxActive = 0;
    queue.process('work', async () => {
      active += 1;
      maxActive = Math.max(maxActive, active);
      await delay(40);
      active -= 1;
    });
    for (let i = 0; i < 6; i += 1) await queue.enqueue('work', i);
    queue.start();
    await delay(300);
    await queue.stop();
    expect(maxActive).toBeLessThanOrEqual(2);
    expect(queue.stats().completed).toBe(6);
  });

  it('prioritises higher-priority jobs', async () => {
    const queue = new InMemoryQueue({ concurrency: 1, pollIntervalMs: 5 });
    const order: number[] = [];
    queue.process('ranked', async (job) => {
      order.push(job.payload as number);
    });
    await queue.enqueue('ranked', 1, { priority: 1 });
    await queue.enqueue('ranked', 99, { priority: 10 });
    await queue.enqueue('ranked', 2, { priority: 2 });
    queue.start();
    await delay(200);
    await queue.stop();
    expect(order).toEqual([99, 2, 1]);
  });

  it('retries failed jobs up to maxAttempts, then marks them failed', async () => {
    const queue = new InMemoryQueue({
      concurrency: 1,
      pollIntervalMs: 5,
      baseRetryDelayMs: 1,
      jobTimeoutMs: 1000,
    });
    let attempts = 0;
    queue.process('flaky', async () => {
      attempts += 1;
      if (attempts < 3) throw new Error('transient');
    });
    await queue.enqueue('flaky', null, { maxAttempts: 3 });
    queue.start();
    await delay(250);
    await queue.stop();
    expect(attempts).toBe(3);
    expect(queue.stats().completed).toBe(1);
    expect(queue.stats().failed).toBe(0);
  });

  it('marks permanently failing jobs as failed', async () => {
    const queue = new InMemoryQueue({
      concurrency: 1,
      pollIntervalMs: 5,
      baseRetryDelayMs: 1,
    });
    queue.process('broken', async () => {
      throw new Error('always broken');
    });
    await queue.enqueue('broken', null, { maxAttempts: 2 });
    queue.start();
    await delay(200);
    await queue.stop();
    expect(queue.stats().failed).toBe(1);
    expect(queue.stats().pending).toBe(0);
  });

  it('treats jobs with no handler as failures (no silent loss)', async () => {
    const queue = new InMemoryQueue({ concurrency: 1, pollIntervalMs: 5, baseRetryDelayMs: 1 });
    await queue.enqueue('unknown-type', null, { maxAttempts: 1 });
    queue.start();
    await delay(150);
    await queue.stop();
    expect(queue.stats().failed).toBe(1);
  });
});
