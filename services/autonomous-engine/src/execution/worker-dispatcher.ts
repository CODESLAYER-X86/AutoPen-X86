/**
 * Worker dispatcher (spec Part 6 §38, §76).
 *
 * Compiles the next batch of work into the task queue and lets the Part 2
 * scheduler dispatch it — the engine NEVER executes tools itself and NEVER
 * bypasses the scheduler's quota/policy/duplicate gates (§47: a model — or
 * an engine — cannot bypass any validation layer).
 */
import type { Repositories, TaskRecord } from '@aegis/database';
import type { PlatformEvent } from '@aegis/contracts';
import type { EventBus } from '@aegis/events';
import type { TestCandidate, LeaderDecision, LeaderTaskSpec } from '@aegis/contracts';
import { generateId } from '@aegis/shared';
import { TaskCompiler } from '@aegis/agent';

export interface WorkerDispatcherDeps {
  repos: Repositories;
  compiler: TaskCompiler;
  eventBus: EventBus;
}

export class WorkerDispatcher {
  constructor(private readonly deps: WorkerDispatcherDeps) {}

  /** Enqueue a deterministic recon plan as worker tasks (§9). */
  async enqueueReconTasks(
    engagementId: string,
    runId: string,
    specs: LeaderTaskSpec[],
    stage: string,
  ): Promise<TaskRecord[]> {
    if (specs.length === 0) return [];
    const decision: LeaderDecision = {
      decision: 'CREATE_PARALLEL_TASKS',
      reasoning_summary: `Deterministic recon pipeline stage ${stage} (§9): ${specs.length} bounded tasks.`,
      tasks: specs,
    };
    const compiled = await this.deps.compiler.compile(decision, { engagementId, runId, decisionId: null });
    const event: PlatformEvent = {
      type: 'RECON_TASK_PLANNED',
      engagement_id: engagementId,
      trace_id: generateId('TRC'),
      actor_id: null,
      payload: { stage, tasks: compiled.length, run_id: runId },
      occurred_at: new Date().toISOString(),
      dedup_key: `recon-planned:${engagementId}:${stage}:${runId}`,
    };
    await this.deps.eventBus.publish(event).catch(() => undefined);
    return compiled.map((c) => c.task);
  }

  /** Enqueue compiled test candidates (§38 adaptive generation). */
  async enqueueTestCandidates(
    engagementId: string,
    runId: string,
    candidates: TestCandidate[],
    specFor: (candidate: TestCandidate) => LeaderTaskSpec,
  ): Promise<TaskRecord[]> {
    if (candidates.length === 0) return [];
    const decision: LeaderDecision = {
      decision: 'CREATE_PARALLEL_TASKS',
      reasoning_summary: `Adaptive test-candidate batch (§38): ${candidates.length} structured tests compiled from the reasoning engine's plan.`,
      tasks: candidates.map(specFor),
    };
    const compiled = await this.deps.compiler.compile(decision, { engagementId, runId, decisionId: null });
    const event: PlatformEvent = {
      type: 'TEST_CANDIDATES_COMPILED',
      engagement_id: engagementId,
      trace_id: generateId('TRC'),
      actor_id: null,
      payload: { count: compiled.length, fingerprints: candidates.map((c) => c.fingerprint).slice(0, 8), run_id: runId },
      occurred_at: new Date().toISOString(),
      dedup_key: `candidates-compiled:${engagementId}:${runId}:${Date.now()}`,
    };
    await this.deps.eventBus.publish(event).catch(() => undefined);
    return compiled.map((c) => c.task);
  }

  /** Enqueue a single verification task (§26). */
  async enqueueVerification(
    engagementId: string,
    runId: string,
    hypothesisId: string,
    aspect: string | null,
  ): Promise<TaskRecord | null> {
    const decision: LeaderDecision = {
      decision: 'REQUEST_VERIFICATION',
      hypothesis_id: hypothesisId,
      ...(aspect ? { aspect } : {}),
      reasoning_summary: 'Deterministic verification request for a SUPPORTED hypothesis (§26, §38).',
    };
    const compiled = await this.deps.compiler.compile(decision, { engagementId, runId, decisionId: null });
    return compiled[0]?.task ?? null;
  }
}
