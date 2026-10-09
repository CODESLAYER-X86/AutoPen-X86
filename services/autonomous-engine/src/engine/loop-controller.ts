/**
 * Loop controller (spec Part 6 §7-§8, §54).
 *
 * The production loop is EVENT-DRIVEN and RESUMABLE — never one blocking
 * function (§7). The controller:
 *   - subscribes to the event bus and reacts to task completions,
 *     reasoning ingestion, hypothesis updates and verification results;
 *   - runs a bounded maintenance tick (lease sweep, flag scan, stop
 *     evaluation, phase advancement) as a fallback for time-based
 *     transitions;
 *   - serializes ALL engine mutations through a promise chain (§56
 *     concurrency safety) — engine actions never interleave;
 *   - persists state after every meaningful transition (§54).
 */
import type { PlatformEvent } from '@aegis/contracts';
import type { EventBus } from '@aegis/events';
import type { Logger } from '@aegis/logging';
import type { AutonomousEngine } from '../engine/engagement-engine.js';

export interface LoopControllerOptions {
  maintenanceIntervalMs: number;
}

export class LoopController {
  private unsubscribe: (() => void) | null = null;
  private maintenanceTimer: ReturnType<typeof setInterval> | null = null;
  /** Serial queue — §56: engine mutations never interleave. */
  private queue: Promise<void> = Promise.resolve();
  private running = false;

  constructor(
    private readonly engine: AutonomousEngine,
    private readonly eventBus: EventBus,
    private readonly opts: LoopControllerOptions,
    private readonly logger?: Pick<Logger, 'info' | 'warn' | 'debug'>,
  ) {}

  get isRunning(): boolean {
    return this.running;
  }

  /** Start the event-driven loop for an engagement (§8). */
  start(engagementId: string): void {
    if (this.running) return;
    this.running = true;

    this.unsubscribe = this.eventBus.subscribe((event) => {
      this.handleEvent(engagementId, event);
    });

    this.maintenanceTimer = setInterval(() => {
      void this.enqueue(async () => {
        if (!this.running) return;
        await this.engine.maintenanceTick(engagementId);
      });
    }, this.opts.maintenanceIntervalMs);
    // Never hold the process open for the maintenance loop alone (§54: the
    // loop is restartable from persisted state).
    this.maintenanceTimer.unref?.();
    this.logger?.info('autonomous.loop.started', { engagement_id: engagementId });
  }

  /** Stop the loop (pause/cancel/stop/terminal). */
  stop(engagementId: string): void {
    this.running = false;
    this.unsubscribe?.();
    this.unsubscribe = null;
    if (this.maintenanceTimer) {
      clearInterval(this.maintenanceTimer);
      this.maintenanceTimer = null;
    }
    this.logger?.info('autonomous.loop.stopped', { engagement_id: engagementId });
  }

  /** Serialize an engine action (§56). */
  enqueue(action: () => Promise<void>): Promise<void> {
    const next = this.queue.then(action).catch((error: unknown) => {
      this.logger?.warn('autonomous.loop.action_failed', {
        error: error instanceof Error ? error.message : String(error),
      });
    });
    this.queue = next;
    return next;
  }

  private handleEvent(engagementId: string, event: PlatformEvent): void {
    if (event.engagement_id !== engagementId) return;
    const relevant =
      event.type === 'TASK_COMPLETED' ||
      event.type === 'TASK_FAILED' ||
      event.type === 'REASONING_INGEST_COMPLETED' ||
      event.type === 'HYPOTHESIS_UPDATED' ||
      event.type === 'VERIFICATION_COMPLETED' ||
      event.type === 'AGENT_RUN_COMPLETED' ||
      event.type === 'AGENT_RUN_FAILED';
    if (!relevant) return;
    void this.enqueue(async () => {
      if (!this.running) return;
      await this.engine.handlePlatformEvent(engagementId, event);
    });
  }
}
