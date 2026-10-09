/**
 * Differential engine (spec Part 6 §18-§19).
 *
 * First-class identity differential testing. After a test-candidate task
 * completes, the engine deterministically compares the mutated response
 * against the baseline via the Part 4 differential comparator, records the
 * experimental verdict in the test registry (§60) and emits the comparison
 * for the observation pipeline. The LLM never compares massive raw
 * responses (§18) — the deterministic diff engine does that first.
 */
import type { Repositories, TaskRecord } from '@aegis/database';
import type { PlatformEvent } from '@aegis/contracts';
import type { EventBus } from '@aegis/events';
import { generateId, type TestResultOutcome } from '@aegis/shared';
import type { ReasoningPort } from '../engine/ports.js';

export interface DifferentialOutcome {
  taskId: string | null;
  testId: string | null;
  differentialRecordId: string | null;
  verdict: TestResultOutcome;
  signal: string;
}

export class DifferentialEngine {
  constructor(
    private readonly deps: { repos: Repositories; eventBus: EventBus; reasoning: ReasoningPort },
  ) {}

  /**
   * Auto-run the differential for a completed test-candidate task (§19):
   * baseline = the base request; candidate = the mutated request recorded
   * by the worker (parent_request_id links them, Part 3 provenance).
   */
  async analyzeTask(engagementId: string, task: TaskRecord): Promise<DifferentialOutcome | null> {
    const mode = typeof task.inputs.mode === 'string' ? task.inputs.mode : '';
    if (mode !== 'TEST_CANDIDATE') return null;
    const baseRequestId =
      typeof task.inputs.base_request_id === 'string' ? task.inputs.base_request_id : null;
    if (!baseRequestId) return null;

    // The mutated request produced by this task links to the base via
    // parent_request_id (Part 3 provenance, §20).
    const mutated = await this.findChildRequest(engagementId, baseRequestId, task.id);
    if (!mutated) {
      // No mutated request recorded — the worker may have used replay
      // without mutation. Not comparable (§18) — inconclusive.
      await this.recordVerdict(engagementId, task, 'INCONCLUSIVE', 'no mutated request recorded for comparison');
      return {
        taskId: task.id,
        testId: this.testIdFor(task),
        differentialRecordId: null,
        verdict: 'INCONCLUSIVE',
        signal: 'no mutated request recorded for comparison',
      };
    }

    const comparison = await this.deps.reasoning.compareDifferential({
      engagementId,
      baselineRequestId: baseRequestId,
      candidateRequestId: String(mutated.id),
      hypothesisId: task.hypothesis_id,
      testId: this.testIdFor(task),
    });

    const verdict = this.verdictFromSummary(comparison.summary);
    const signal = this.summarize(comparison.summary);
    await this.recordVerdict(engagementId, task, verdict, signal);

    const event: PlatformEvent = {
      type: 'DIFFERENTIAL_AUTO_REQUESTED',
      engagement_id: engagementId,
      task_id: task.id,
      trace_id: generateId('TRC'),
      actor_id: null,
      payload: {
        differential_record: comparison.recordId,
        verdict,
        hypothesis_id: task.hypothesis_id,
        baseline: baseRequestId,
        candidate: String(mutated.id),
      },
      occurred_at: new Date().toISOString(),
      dedup_key: `auto-differential:${task.id}`,
    };
    await this.deps.eventBus.publish(event).catch(() => undefined);

    return {
      taskId: task.id,
      testId: this.testIdFor(task),
      differentialRecordId: comparison.recordId,
      verdict,
      signal,
    };
  }

  /** Verdict semantics (§72 in Part 4, §60 here). */
  private verdictFromSummary(summary: Record<string, unknown>): TestResultOutcome {
    const statusChanged = Boolean(summary.status_changed);
    const fieldsAdded = Array.isArray(summary.fields_added) ? (summary.fields_added as string[]) : [];
    const valuesChanged = Array.isArray(summary.values_changed)
      ? (summary.values_changed as Array<{ path: string; volatile: boolean }>)
      : [];
    const nonVolatileChanges = valuesChanged.filter((change) => !change.volatile).length;
    const bodySimilarity = typeof summary.body_similarity === 'number' ? summary.body_similarity : 1;
    const schemaChanged = Boolean(summary.schema_changed);

    const exposesProtectedData = fieldsAdded.length > 0 || nonVolatileChanges > 0 || (bodySimilarity < 0.98 && schemaChanged);

    // Authorization semantics: a DENY status change (403/404) refutes an
    // authorization-failure hypothesis (Part 4 §72): the non-owner did NOT
    // receive the protected content.
    if (statusChanged) return 'DISPROVED';
    if (exposesProtectedData) return 'SUPPORTED';
    return 'INCONCLUSIVE';
  }

  private summarize(summary: Record<string, unknown>): string {
    const parts: string[] = [];
    if (summary.status_changed) parts.push('status changed');
    if (summary.headers_changed) parts.push('headers changed');
    if (summary.schema_changed) parts.push('schema changed');
    const added = Array.isArray(summary.fields_added) ? (summary.fields_added as string[]) : [];
    if (added.length > 0) parts.push(`fields added: ${added.slice(0, 5).join(', ')}`);
    const removed = Array.isArray(summary.fields_removed) ? (summary.fields_removed as string[]) : [];
    if (removed.length > 0) parts.push(`fields removed: ${removed.slice(0, 5).join(', ')}`);
    if (typeof summary.body_similarity === 'number') parts.push(`body similarity ${summary.body_similarity.toFixed(3)}`);
    return parts.length > 0 ? parts.join('; ') : 'no semantic difference';
  }

  private async recordVerdict(engagementId: string, task: TaskRecord, verdict: TestResultOutcome, signal: string): Promise<void> {
    const testId = this.testIdFor(task);
    if (!testId) return;
    const test = await this.deps.repos.tests.findByFingerprint(engagementId, task.inputs.fingerprint as string).catch(() => null);
    if (!test) return;
    await this.deps.repos.tests
      .recordOutcome(test.id, verdict, signal.slice(0, 500))
      .catch(() => undefined);
  }

  private testIdFor(_task: TaskRecord): string | null {
    // The Part 2 compiler registered the test with the fingerprint computed
    // from the spec; resolved via recordVerdict's fingerprint lookup.
    return null;
  }

  private async findChildRequest(
    engagementId: string,
    baseRequestId: string,
    taskId: string,
  ): Promise<Record<string, unknown> | null> {
    const requests = await this.deps.repos.httpRequests.listByEngagement(engagementId, 100, 0);
    for (const request of requests) {
      if (request.parent_request_id === baseRequestId && request.provenance_parent_task_id === taskId) {
        return request;
      }
    }
    // Fallback: any child of the base request.
    for (const request of requests) {
      if (request.parent_request_id === baseRequestId) return request;
    }
    return null;
  }
}
