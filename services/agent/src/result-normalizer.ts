/**
 * Result normalizer (spec Part 2 §16, §42, §55-§57).
 *
 * Worker results are never applied raw. The pipeline:
 *   worker result -> normalization -> observation extraction (dedup)
 *   -> evidence linkage -> hypothesis updates (CONFIRM only via
 *   verification) -> test registry update -> leader-ready summaries.
 *
 * The orchestrator interprets the result; workers never mutate the database
 * directly (§16).
 */
import type { TaskRecord, ObservationRecord, HypothesisRecord } from '@aegis/database';
import type { WorkerResult } from '@aegis/worker-runtime';
import type { HypothesisEngine } from './hypothesis-engine.js';
import { generateId } from '@aegis/shared';
import type { Repositories } from '@aegis/database';
import type { EventBus } from '@aegis/events';

export interface NormalizedResult {
  observations: ObservationRecord[];
  hypothesesUpdated: string[];
  hypothesesCreated: string[];
  findingsPromoted: string[];
  deadEnds: string[];
  verificationRequested: boolean;
  /** Leader-facing compact summary (structured facts, not transcripts). */
  summary: Record<string, unknown>;
  rejectedUpdates: Array<{ hypothesis_id?: string; change: string; reason: string }>;
}

export interface ResultNormalizerDeps {
  repos: Repositories;
  eventBus: EventBus;
  hypothesisEngine: HypothesisEngine;
}

export class ResultNormalizer {
  constructor(private readonly deps: ResultNormalizerDeps) {}

  async normalize(
    task: TaskRecord,
    result: WorkerResult,
    input: { runId: string },
  ): Promise<NormalizedResult> {
    const normalized: NormalizedResult = {
      observations: [],
      hypothesesUpdated: [],
      hypothesesCreated: [],
      findingsPromoted: [],
      deadEnds: [],
      verificationRequested: false,
      summary: {},
      rejectedUpdates: [],
    };

    // 1. Observation extraction with deduplication (§42).
    const existing = await this.deps.repos.observations.listByTask(task.id);
    const seenDescriptions = new Set(existing.map((o) => `${o.type}::${o.description}`));
    for (const observation of result.observations) {
      const key = `${observation.type}::${observation.description}`;
      if (seenDescriptions.has(key)) continue;
      seenDescriptions.add(key);

      const created = await this.deps.repos.observations.create({
        engagementId: task.engagement_id,
        taskId: task.id,
        hypothesisId: task.hypothesis_id,
        type: observation.type,
        description: observation.description,
        confidence: observation.confidence,
        evidenceIds: observation.evidence_refs ?? [],
        metadata: observation.metadata ?? {},
      });
      normalized.observations.push(created);
      await this.deps.eventBus.publish({
        type: 'OBSERVATION_CREATED',
        engagement_id: task.engagement_id,
        task_id: task.id,
        trace_id: generateId('TRC'),
        actor_id: null,
        payload: {
          observation_id: created.id,
          type: created.type,
          confidence: created.confidence,
          hypothesis_id: task.hypothesis_id,
        },
        occurred_at: new Date().toISOString(),
        dedup_key: `observation:${created.id}`,
      });
    }

    // 2. Evidence linkage (§24): worker-cited evidence attaches to hypotheses.
    if (task.hypothesis_id && result.evidence_ids.length > 0) {
      await this.deps.hypothesisEngine.linkEvidence(
        task.hypothesis_id,
        result.evidence_ids.map((refId) => ({ refType: 'EVIDENCE', refId })),
      );
    }

    // 3. Hypothesis updates — interpreted, not applied blindly (§16).
    const isVerificationTask = task.type === 'VERIFICATION';
    const hypothesis = task.hypothesis_id
      ? await this.deps.repos.hypotheses.findById(task.hypothesis_id)
      : null;

    for (const update of result.hypothesis_updates) {
      // Worker-proposed new hypothesis (CTF clue interpretation, §48).
      if (update.change === 'CREATE') {
        try {
          const created = await this.deps.hypothesisEngine.createHypothesis({
            engagementId: task.engagement_id,
            type: (update.type as never) ?? 'UNKNOWN',
            statement: update.statement ?? 'Worker-proposed hypothesis (missing statement)',
            confidence: update.confidence ?? 0.4,
            source: 'worker',
            parentHypothesisId: task.hypothesis_id,
          });
          normalized.hypothesesCreated.push(created.id);
        } catch (error) {
          normalized.rejectedUpdates.push({
            change: 'CREATE',
            reason: error instanceof Error ? error.message : 'Branch budget exceeded',
          });
        }
        continue;
      }

      const targetId = update.hypothesis_id ?? task.hypothesis_id;
      if (!targetId) {
        normalized.rejectedUpdates.push({
          change: update.change,
          reason: 'No hypothesis referenced by task or update',
        });
        continue;
      }
      let target = hypothesis && hypothesis.id === targetId ? hypothesis : null;
      if (!target) {
        target = await this.deps.repos.hypotheses.findById(targetId);
      }
      if (!target || target.engagement_id !== task.engagement_id) {
        normalized.rejectedUpdates.push({
          hypothesis_id: targetId,
          change: update.change,
          reason: 'Hypothesis not found in this engagement',
        });
        continue;
      }

      try {
        const updated = await this.deps.hypothesisEngine.applyChange(target, update.change as never, {
          confidence: update.confidence,
          // CONFIRM is gated to verification tasks (§55-§56).
          viaVerification: isVerificationTask,
          verificationRef: task.id,
        });
        if (update.change === 'CONFIRM' && !isVerificationTask) {
          // unreachable — engine throws first; kept for type safety
          normalized.rejectedUpdates.push({
            hypothesis_id: targetId,
            change: update.change,
            reason: 'CONFIRM requires a verification task',
          });
          continue;
        }
        if (update.change === 'ABANDON') {
          normalized.deadEnds.push(targetId);
        } else if (update.change === 'CONFIRM') {
          normalized.findingsPromoted.push(targetId);
        } else {
          normalized.hypothesesUpdated.push(targetId);
        }
        void updated;
      } catch (error) {
        normalized.rejectedUpdates.push({
          hypothesis_id: targetId,
          change: update.change,
          reason: error instanceof Error ? error.message : 'Update rejected by hypothesis engine',
        });
      }
    }

    // 4. Verification linkage: observations produced by a verification task
    // link back to the hypothesis as evidence events.
    if (isVerificationTask && hypothesis && normalized.observations.length > 0) {
      for (const observation of normalized.observations) {
        await this.deps.hypothesisEngine.linkEvidence(hypothesis.id, [
          { refType: 'OBSERVATION', refId: observation.id },
        ]);
      }
    }

    // 5. Test registry outcome (§28).
    const testRow = await this.findTestForTask(task);
    if (testRow) {
      await this.deps.repos.tests.updateResult(
        testRow.id,
        result.status === 'COMPLETED' ? 'COMPLETED' : result.status === 'PARTIAL' ? 'COMPLETED' : 'FAILED',
        `${result.status}: ${result.observations.length} observations, ${result.hypothesis_updates.length} hypothesis updates`,
      );
    }

    // 6. Recommended verification becomes a machine-visible event (§56).
    if (
      result.recommended_next_action?.type === 'VERIFY' &&
      (task.hypothesis_id || normalized.hypothesesCreated.length > 0)
    ) {
      normalized.verificationRequested = true;
      await this.deps.eventBus.publish({
        type: 'VERIFICATION_REQUESTED',
        engagement_id: task.engagement_id,
        task_id: task.id,
        trace_id: generateId('TRC'),
        actor_id: null,
        payload: {
          run_id: input.runId,
          hypothesis_id: task.hypothesis_id ?? normalized.hypothesesCreated[0] ?? null,
          reason: result.recommended_next_action.reason,
        },
        occurred_at: new Date().toISOString(),
      });
    }

    // 7. Leader-facing compact summary (§42: no raw transcripts).
    normalized.summary = {
      task_id: task.id,
      type: task.type,
      worker_status: result.status,
      observation_count: normalized.observations.length,
      observation_types: normalized.observations.map((o) => o.type),
      top_confidences: normalized.observations
        .map((o) => o.confidence)
        .sort((a, b) => b - a)
        .slice(0, 3),
      hypotheses_updated: normalized.hypothesesUpdated,
      hypotheses_created: normalized.hypothesesCreated,
      findings_promoted: normalized.findingsPromoted,
      dead_ends: normalized.deadEnds,
      ...(result.needs ? { worker_needs: result.needs } : {}),
      ...(result.error ? { error: result.error } : {}),
      ...(normalized.rejectedUpdates.length > 0
        ? { rejected_updates: normalized.rejectedUpdates }
        : {}),
    };

    return normalized;
  }

  private async findTestForTask(task: TaskRecord): Promise<{ id: string } | null> {
    const tests = await this.deps.repos.tests.listByEngagement(task.engagement_id, 500);
    return tests.find((t) => t.task_id === task.id) ?? null;
  }
}

/** Maps worker statuses to task statuses (§17 -> §18). */
export function taskStatusForWorkerStatus(
  workerStatus: WorkerResult['status'],
): 'COMPLETED' | 'PARTIAL' | 'FAILED' {
  switch (workerStatus) {
    case 'COMPLETED':
      return 'COMPLETED';
    case 'PARTIAL':
      return 'PARTIAL';
    default:
      // BLOCKED / FAILED / NEEDS_* all fail the task; the retry policy in the
      // scheduler decides whether a retry is warranted (§43).
      return 'FAILED';
  }
}

/** Failure codes recorded on the task row per worker status. */
export function failureCodeForWorkerStatus(workerStatus: WorkerResult['status']): string {
  switch (workerStatus) {
    case 'BLOCKED':
      return 'WORKER_BLOCKED';
    case 'NEEDS_CONTEXT':
      return 'WORKER_NEEDS_CONTEXT';
    case 'NEEDS_TOOL':
      return 'WORKER_NEEDS_TOOL';
    case 'NEEDS_IDENTITY':
      return 'WORKER_NEEDS_IDENTITY';
    case 'PARTIAL':
      return 'WORKER_PARTIAL';
    default:
      return 'WORKER_FAILED';
  }
}

export type { HypothesisRecord };
