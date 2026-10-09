/**
 * Circuit breakers (spec Part 8 §97-§99).
 *
 * Deterministic violation counters per (subject, subject_id, category).
 * When the threshold is reached the breaker OPENS: the agent (engagement)
 * is paused for human review, or the model configuration is temporarily
 * disabled. Only a human reset closes the breaker — the model can never
 * reset its own breaker.
 */
import type { CircuitBreakerRecord } from '@aegis/database';
import type { EventPort } from '../ops/ports.js';

export interface BreakerDeps {
  repos: {
    circuitBreakers: {
      recordViolation(input: {
        subject: 'AGENT' | 'MODEL';
        subjectId: string;
        engagementId?: string | null;
        category: string;
        threshold: number;
      }): Promise<CircuitBreakerRecord>;
      findOpen(subject: 'AGENT' | 'MODEL', subjectId: string): Promise<CircuitBreakerRecord[]>;
      listOpen(): Promise<CircuitBreakerRecord[]>;
      reset(id: string): Promise<CircuitBreakerRecord | null>;
      listByEngagement(engagementId: string): Promise<CircuitBreakerRecord[]>;
    };
  };
  eventBus?: EventPort;
}

/** Default thresholds per category (§98: examples map 1:1). */
export const BREAKER_THRESHOLDS: Record<string, number> = {
  SCOPE_VIOLATION: 3,
  INVALID_TOOL_REQUEST: 5,
  CREDENTIAL_REQUEST: 3,
  RESOURCE_ABUSE: 4,
  DUPLICATE_EXECUTION: 6,
  INVALID_MODEL_OUTPUT: 5,
  MODEL_POLICY_BYPASS: 2,
};

export class CircuitBreakerEngine {
  constructor(private readonly deps: BreakerDeps) {}

  /** Record one deterministic policy violation for the subject. */
  async recordViolation(input: {
    subject: 'AGENT' | 'MODEL';
    subjectId: string;
    engagementId?: string | null;
    category: string;
  }): Promise<CircuitBreakerRecord> {
    const threshold = BREAKER_THRESHOLDS[input.category] ?? 5;
    const record = await this.deps.repos.circuitBreakers.recordViolation({
      subject: input.subject,
      subjectId: input.subjectId,
      engagementId: input.engagementId ?? null,
      category: input.category,
      threshold,
    });
    if (record.state === 'OPEN' && record.tripped_at) {
      await this.deps.eventBus?.publish({
        type: 'CIRCUIT_BREAKER_TRIPPED',
        engagement_id: input.engagementId ?? null,
        trace_id: record.id,
        actor_id: null,
        payload: { subject: record.subject, subject_id: record.subject_id, category: record.category },
        occurred_at: new Date().toISOString(),
      });
    }
    return record;
  }

  /** Hot-path check used before dispatching work to an agent/model. */
  async isOpen(input: { subject: 'AGENT' | 'MODEL'; subjectId: string }): Promise<boolean> {
    const open = await this.deps.repos.circuitBreakers.findOpen(input.subject, input.subjectId);
    return open.length > 0;
  }

  /** Human-only reset (§98: require human review). */
  async reset(id: string): Promise<CircuitBreakerRecord | null> {
    const record = await this.deps.repos.circuitBreakers.reset(id);
    if (record) {
      await this.deps.eventBus?.publish({
        type: 'CIRCUIT_BREAKER_RESET',
        engagement_id: record.engagement_id,
        trace_id: record.id,
        actor_id: null,
        payload: { subject: record.subject, subject_id: record.subject_id },
        occurred_at: new Date().toISOString(),
      });
    }
    return record;
  }

  listOpen(): Promise<CircuitBreakerRecord[]> {
    return this.deps.repos.circuitBreakers.listOpen();
  }

  listByEngagement(engagementId: string): Promise<CircuitBreakerRecord[]> {
    return this.deps.repos.circuitBreakers.listByEngagement(engagementId);
  }
}
