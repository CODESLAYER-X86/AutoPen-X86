/**
 * Outbox publisher + backpressure + retention + health (spec Part 8 §44,
 * §51-§52, §58-§60).
 *
 * The outbox guarantees at-least-once delivery with idempotent processing:
 * events are appended in the same transaction as the state change and the
 * publisher drains them deterministically by sequence. Delivery failures
 * retry up to a cap, then the event is ABANDONED (observable, never silent).
 */
import type { OutboxEventRecord, RetentionPolicyRecord } from '@aegis/database';
import type { EventPort } from './ports.js';

export interface OutboxDeps {
  repos: {
    outbox: {
      append(input: {
        eventType: string;
        engagementId?: string | null;
        aggregateId: string;
        causationId?: string | null;
        correlationId?: string | null;
        payload: Record<string, unknown>;
      }): Promise<OutboxEventRecord>;
      listPending(limit?: number): Promise<OutboxEventRecord[]>;
      markDelivered(id: string): Promise<void>;
      markFailed(id: string): Promise<void>;
      countPending(): Promise<number>;
    };
    retentionPolicies: {
      list(): Promise<RetentionPolicyRecord[]>;
      update(dataClass: string, retentionDays: number, hardDelete: boolean): Promise<RetentionPolicyRecord | null>;
      findByClass(dataClass: string): Promise<RetentionPolicyRecord | null>;
    };
    events: { deleteOlderThan(days: number, limit: number): Promise<number> };
    httpResponses: { deleteOlderThan(days: number, limit: number): Promise<number> };
  };
  eventBus?: EventPort;
}

export class OutboxEngine {
  constructor(private readonly deps: OutboxDeps) {}

  /**
   * Append an event to the outbox. Callers should run their state change and
   * this append in the same transaction; this method appends durably and the
   * publisher delivers later (§44).
   */
  append(input: {
    eventType: string;
    engagementId?: string | null;
    aggregateId: string;
    causationId?: string | null;
    correlationId?: string | null;
    payload: Record<string, unknown>;
  }): Promise<OutboxEventRecord> {
    return this.deps.repos.outbox.append(input);
  }

  /**
   * Drain pending events (bounded batch — backpressure, §58). Duplicate
   * delivery is tolerated downstream because consumers key on idempotency
   * keys (§42 at-least-once + idempotent processing).
   */
  async drain(input: { batchSize?: number } = {}): Promise<{ delivered: number; failed: number; abandoned: number }> {
    const batch = await this.deps.repos.outbox.listPending(input.batchSize ?? 50);
    let delivered = 0;
    let failed = 0;
    let abandoned = 0;
    for (const event of batch) {
      try {
        if (this.deps.eventBus) {
          await this.deps.eventBus.publish({
            type: event.event_type as never,
            engagement_id: event.engagement_id,
            trace_id: event.correlation_id ?? event.id,
            actor_id: null,
            payload: event.payload,
            occurred_at: event.created_at,
          });
        }
        await this.deps.repos.outbox.markDelivered(event.id);
        delivered += 1;
      } catch {
        await this.deps.repos.outbox.markFailed(event.id);
        if (event.attempts + 1 >= 5) abandoned += 1;
        else failed += 1;
      }
    }
    return { delivered, failed, abandoned };
  }

  countPending(): Promise<number> {
    return this.deps.repos.outbox.countPending();
  }
}

// ---------------------------------------------------------------------------
// Retention sweeps (§59-§60)
// ---------------------------------------------------------------------------

export class RetentionEngine {
  constructor(private readonly deps: OutboxDeps) {}

  listPolicies(): Promise<RetentionPolicyRecord[]> {
    return this.deps.repos.retentionPolicies.list();
  }

  async updatePolicy(input: { dataClass: string; retentionDays: number; hardDelete: boolean }): Promise<RetentionPolicyRecord> {
    const updated = await this.deps.repos.retentionPolicies.update(input.dataClass, input.retentionDays, input.hardDelete);
    if (!updated) throw new Error(`Unknown retention data class '${input.dataClass}'`);
    return updated;
  }

  /**
   * Apply retention for RAW_HTTP: delete engagement event log rows and
   * HTTP response bodies older than the policy horizon. Bounded batches
   * keep the sweep cheap; audit records are NEVER touched here (§60).
   */
  async applyRetention(input: { batchSize?: number } = {}): Promise<Array<{ data_class: string; evaluated: number; deleted: number }>> {
    const results: Array<{ data_class: string; evaluated: number; deleted: number }> = [];
    const batch = input.batchSize ?? 500;
    for (const policy of await this.deps.repos.retentionPolicies.list()) {
      let deleted = 0;
      if (policy.data_class === 'RAW_HTTP') {
        deleted += await this.deps.repos.events.deleteOlderThan(policy.retention_days, batch);
        deleted += await this.deps.repos.httpResponses.deleteOlderThan(policy.retention_days, batch);
      }
      results.push({ data_class: policy.data_class, evaluated: batch, deleted });
    }
    return results;
  }
}

// ---------------------------------------------------------------------------
// Health + readiness (§51-§52)
// ---------------------------------------------------------------------------

export interface DependencyProbe {
  name: string;
  probe: () => Promise<boolean | { healthy: boolean; detail?: string }>;
}

export class HealthEngine {
  constructor(
    private readonly deps: { dbLatencyProbe: () => Promise<boolean> },
    private readonly probes: DependencyProbe[],
  ) {}

  /** Liveness never depends on external dependencies (§51). */
  liveness(): { alive: boolean; uptime_seconds: number } {
    return { alive: true, uptime_seconds: Math.floor(process.uptime()) };
  }

  /**
   * Readiness checks every dependency the orchestrator needs. When any is
   * unhealthy the platform reports WAITING_FOR_RESOURCE rather than
   * continuously failing (§52).
   */
  async readiness(): Promise<{
    ready: boolean;
    checked_at: string;
    waiting_for_resource: boolean;
    dependencies: Array<{ name: string; healthy: boolean; detail: string | null; latency_ms: number | null }>;
  }> {
    const dependencies: Array<{ name: string; healthy: boolean; detail: string | null; latency_ms: number | null }> = [];
    for (const probe of this.probes) {
      const startedAt = Date.now();
      try {
        const outcome = await probe.probe();
        const healthy = typeof outcome === 'boolean' ? outcome : outcome.healthy;
        dependencies.push({
          name: probe.name,
          healthy,
          detail: typeof outcome === 'boolean' ? null : (outcome.detail ?? null),
          latency_ms: Date.now() - startedAt,
        });
      } catch (error) {
        dependencies.push({
          name: probe.name,
          healthy: false,
          detail: (error as Error).message.slice(0, 200),
          latency_ms: Date.now() - startedAt,
        });
      }
    }
    return {
      ready: dependencies.every((d) => d.healthy),
      checked_at: new Date().toISOString(),
      waiting_for_resource: dependencies.some((d) => !d.healthy),
      dependencies,
    };
  }
}
