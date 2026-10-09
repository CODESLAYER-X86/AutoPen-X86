/**
 * Task compiler (spec Part 2 §13-§15, §35-§36, §41).
 *
 * Transforms a validated strategic decision into the SMALLEST useful worker
 * context. The compiler performs retrieval (hypothesis, endpoint facts,
 * relevant evidence, identity summary) — it never stringifies the database.
 * Structured facts are preferred over prose (§15).
 *
 * When a task would exceed the worker context budget, it is SPLIT (§41)
 * instead of growing the packet indefinitely; results are aggregated by the
 * normalizer.
 */
import type {
  HypothesisRecord,
  ObservationRecord,
  Repositories,
  TaskRecord,
} from '@aegis/database';
import type { EventBus } from '@aegis/events';
import type {
  LeaderDecision,
  LeaderTaskSpec,
} from '@aegis/contracts';
import { generateId, type TaskType, type WorkerType } from '@aegis/shared';
import type { ToolRegistry } from '@aegis/tools';
import { computePriority, type PriorityWeights } from './priority.js';
import { computeTestFingerprint } from './fingerprints.js';
import { defaultWorkerForTaskType, toolAllowedForWorker } from './decision-validator.js';
import type { WorkerTaskPacket } from '@aegis/worker-runtime';
import { estimateTokens } from './quota.js';

export interface TaskCompilerOptions {
  /** Soft cap on a single worker packet (§12 compact prompts). */
  workerContextTokenBudget: number;
  /** Default per-task constraints (§36) — workers cannot raise these. */
  defaultConstraints: {
    max_tool_calls: number;
    max_duration_seconds: number;
    max_network_requests: number;
  };
  priorityWeights?: PriorityWeights;
}

export const DEFAULT_COMPILER_OPTIONS: TaskCompilerOptions = {
  workerContextTokenBudget: 8_000,
  defaultConstraints: {
    max_tool_calls: 10,
    max_duration_seconds: 120,
    max_network_requests: 20,
  },
};

export interface CompiledTask {
  task: TaskRecord;
  packet: WorkerTaskPacket;
  /** Test registry id when a fingerprint was registered for this task. */
  testId: string | null;
}

export interface TaskCompilerDeps {
  repos: Repositories;
  tools: ToolRegistry;
  eventBus: EventBus;
  options?: Partial<TaskCompilerOptions>;
}

export class TaskCompiler {
  private readonly opts: TaskCompilerOptions;

  constructor(private readonly deps: TaskCompilerDeps) {
    this.opts = { ...DEFAULT_COMPILER_OPTIONS, ...deps.options };
  }

  get options(): TaskCompilerOptions {
    return { ...this.opts };
  }

  /**
   * Compiles one validated decision into persisted tasks + worker packets.
   * CREATE_PARALLEL_TASKS compiles N independent tasks (§32).
   */
  async compile(
    decision: LeaderDecision,
    input: {
      engagementId: string;
      runId: string;
      /** Part 6: deterministic engine compilations pass null (no leader
       * decision record); tasks.decision_id is nullable by design. */
      decisionId: string | null;
    },
  ): Promise<CompiledTask[]> {
    switch (decision.decision) {
      case 'CREATE_TASK':
        return [await this.compileOne(decision.task, input, 0)];
      case 'CREATE_PARALLEL_TASKS': {
        const compiled: CompiledTask[] = [];
        for (let i = 0; i < decision.tasks.length; i += 1) {
          compiled.push(await this.compileOne(decision.tasks[i]!, input, i));
        }
        return compiled;
      }
      case 'REQUEST_KNOWLEDGE':
        return [
          await this.compileOne(
            {
              objective: `Summarize locally recorded knowledge relevant to: ${decision.query}`,
              task_type: 'KNOWLEDGE_SUMMARY',
              depends_on: [],
              inputs: { query: decision.query, note: 'external knowledge retrieval lands in Part 5; reason from local observations only' },
            },
            input,
            0,
          ),
        ];
      case 'REQUEST_RECON':
        return [
          await this.compileOne(
            {
              objective: `Discover the attack surface: ${decision.focus}`,
              task_type: 'RECON',
              depends_on: [],
              inputs: { focus: decision.focus },
              ...(decision.task ?? {}),
            },
            input,
            0,
          ),
        ];
      case 'REQUEST_VERIFICATION':
        return [
          await this.compileOne(
            {
              objective: `Skeptically verify hypothesis: ${decision.hypothesis_id}${decision.aspect ? ` (aspect: ${decision.aspect})` : ''}`,
              task_type: 'VERIFICATION',
              depends_on: [],
              hypothesis_id: decision.hypothesis_id,
              inputs: { verification: true, ...(decision.aspect ? { aspect: decision.aspect } : {}) },
              constraints: { max_tool_calls: 6, max_duration_seconds: 90 },
            },
            input,
            0,
          ),
        ];
      default:
        // UPDATE_HYPOTHESIS / WAIT / STOP / PAUSE compile to no tasks.
        return [];
    }
  }

  private async compileOne(
    spec: LeaderTaskSpec,
    input: { engagementId: string; runId: string; decisionId: string | null },
    index: number,
  ): Promise<CompiledTask> {

    const { repos } = this.deps;
    const workerType = spec.worker_type ?? defaultWorkerForTaskType(spec.task_type);
    const allowedTools =
      spec.allowed_tools && spec.allowed_tools.length > 0
        ? spec.allowed_tools
        : this.defaultToolPalette(workerType);

    // Retrieval (§14): hypothesis, identity, endpoint facts, recent evidence.
    const hypothesis = spec.hypothesis_id
      ? await repos.hypotheses.findByIdAndEngagement(spec.hypothesis_id, input.engagementId)
      : null;
    const identity = spec.identity_id
      ? await repos.identities.listByEngagement(input.engagementId).then((list) => list.find((i) => i.id === spec.identity_id) ?? null)
      : null;
    const observations = await repos.observations.listByEngagement(input.engagementId, 20);
    const relevantObservations = selectRelevantObservations(observations, spec);

    const constraints = {
      ...this.opts.defaultConstraints,
      ...(spec.constraints ?? {}),
    };

    const priority = computePriority({
      hypothesisConfidence: hypothesis?.confidence ?? 0.5,
      potentialImpact: spec.potential_impact ?? 0.5,
      expectedInformationGain: spec.expected_information_gain ?? 0.5,
      testCost: estimateTestCost(constraints),
      scopeRelevance: 1, // scope validated upstream (decision validator layer 4)
      novelty: 1, // duplicates rejected upstream (layer 7)
      dependencyReadiness: (spec.depends_on ?? []).length === 0 ? 1 : 0,
      previousFailurePenalty: 0,
    }, this.opts.priorityWeights);

    // Idempotency key (§65): decision id + task index. Engine-compiled
    // batches (Part 6, decisionId null) get a UNIQUE random prefix — the DB
    // decision_id stays null (FK-safe) while different batches (recon vs
    // candidates vs replans) never collide; true duplicate TESTS are gated
    // by the fingerprint registry (§40).
    const idempotencyKey = input.decisionId
      ? `${input.decisionId}:${index}`
      : `engine-${generateId('TRC')}:${index}`;

    const task = await repos.tasks.create({
      engagementId: input.engagementId,
      runId: input.runId,
      decisionId: input.decisionId,
      hypothesisId: hypothesis?.id ?? null,
      type: spec.task_type,
      objective: spec.objective,
      workerType,
      priority,
      expectedInformationGain: spec.expected_information_gain ?? null,
      dependsOn: spec.depends_on ?? [],
      allowedTools,
      constraints,
      inputs: spec.inputs ?? {},
      maxAttempts: 3,
      idempotencyKey,
    });

    // Test registry (§28): register the fingerprint BEFORE scheduling so the
    // duplicate gate blocks equivalent future tasks.
    const fingerprint = computeTestFingerprint({
      endpoint: spec.target_hint ?? stringInput(spec.inputs, 'endpoint') ?? stringInput(spec.inputs, 'path') ?? 'engagement',
      method: stringInput(spec.inputs, 'method') ?? 'GET',
      identity: spec.identity_id ?? null,
      mutationType: spec.task_type,
      relevantParameter: stringInput(spec.inputs, 'parameter'),
      mutation: spec.inputs ?? undefined,
    });
    const registered = await repos.tests.register({
      engagementId: input.engagementId,
      taskId: task.id,
      hypothesisId: hypothesis?.id ?? null,
      testType: spec.task_type,
      target: spec.target_hint ?? stringInput(spec.inputs, 'endpoint') ?? 'engagement',
      identity: spec.identity_id ?? null,
      mutationSummary: summarizeInputs(spec.inputs),
      fingerprint,
    });

    // Splitting (§41): when the packet exceeds the worker budget, partition
    // the untrusted observations across follow-up tasks.
    const packet = this.buildPacket(task, hypothesis, identity, relevantObservations, spec);
    if (this.estimatePacket(packet) > this.opts.workerContextTokenBudget) {
      await this.splitTask(task, input, relevantObservations);
    }

    await this.deps.eventBus.publish({
      type: 'TASK_CREATED',
      engagement_id: input.engagementId,
      task_id: task.id,
      trace_id: generateId('TRC'),
      actor_id: null,
      payload: {
        run_id: input.runId,
        decision_id: input.decisionId,
        type: task.type,
        worker_type: task.worker_type,
        priority: task.priority,
        depends_on: task.depends_on,
        hypothesis_id: task.hypothesis_id,
        allowed_tools: task.allowed_tools,
      },
      occurred_at: new Date().toISOString(),
      dedup_key: `task-created:${task.id}`,
    });

    return { task, packet, testId: registered.duplicate ? registered.record.id : registered.record.id };
  }

  /**
   * Context splitting (§41): rather than growing one packet, the excess
   * observations are queued as a follow-up GENERAL_ANALYSIS task that the
   * scheduler runs after this one. The normalizer aggregates both.
   */
  private async splitTask(
    task: TaskRecord,
    input: { engagementId: string; runId: string; decisionId: string | null },
    observations: ObservationRecord[],
  ): Promise<void> {
    const { repos } = this.deps;
    const carry = observations.slice(10);
    if (carry.length === 0) return;

    const followUp = await repos.tasks.create({
      engagementId: input.engagementId,
      runId: input.runId,
      decisionId: null,
      hypothesisId: task.hypothesis_id,
      type: 'GENERAL_ANALYSIS',
      objective: `${task.objective} (continuation: remaining ${carry.length} observations)`,
      workerType: 'ANALYSIS_WORKER',
      priority: Math.max(0.05, task.priority - 0.2),
      dependsOn: [task.id],
      allowedTools: [],
      constraints: this.opts.defaultConstraints,
      inputs: { continuation_of: task.id, observation_ids: carry.map((o) => o.id) },
      idempotencyKey: `${input.decisionId ?? 'engine'}:split:${task.id}`,
    });
    await this.deps.eventBus.publish({
      type: 'TASK_CREATED',
      engagement_id: input.engagementId,
      task_id: followUp.id,
      trace_id: generateId('TRC'),
      actor_id: null,
      payload: { run_id: input.runId, split_of: task.id, observations: carry.length },
      occurred_at: new Date().toISOString(),
      dedup_key: `task-created:${followUp.id}`,
    });
  }

  private buildPacket(
    task: TaskRecord,
    hypothesis: HypothesisRecord | null,
    identity: { id: string; name: string; role: string; type: string } | null,
    observations: ObservationRecord[],
    spec: LeaderTaskSpec,
  ): WorkerTaskPacket {
    // TRUSTED context (§60): structured application facts.
    const context: Record<string, unknown> = {
      task_type: task.type,
      inputs: task.inputs,
      identity: identity ? { id: identity.id, name: identity.name, role: identity.role, type: identity.type } : null,
      // Structured endpoint facts (§15), not prose.
      endpoint: endpointFacts(spec),
    };

    // UNTRUSTED context (§61): target-derived observation text.
    const untrusted: Record<string, unknown> = {
      prior_observations: observations.slice(0, 10).map((o) => ({
        type: o.type,
        description: o.description,
        confidence: o.confidence,
      })),
    };

    return {
      task_id: task.id,
      engagement_id: task.engagement_id,
      run_id: task.run_id ?? '',
      type: task.type,
      worker_type: task.worker_type,
      objective: task.objective,
      hypothesis: hypothesis
        ? { id: hypothesis.id, statement: hypothesis.statement, confidence: hypothesis.confidence }
        : null,
      identity_id: spec.identity_id ?? null,
      allowed_tools: task.allowed_tools,
      constraints: {
        max_tool_calls: (task.constraints.max_tool_calls as number) ?? this.opts.defaultConstraints.max_tool_calls,
        max_duration_seconds: (task.constraints.max_duration_seconds as number) ?? this.opts.defaultConstraints.max_duration_seconds,
        ...(typeof task.constraints.max_network_requests === 'number'
          ? { max_network_requests: task.constraints.max_network_requests }
          : {}),
      },
      context,
      untrusted_context: untrusted,
    };
  }

  estimatePacket(packet: WorkerTaskPacket): number {
    return (
      estimateTokens(packet.objective) +
      estimateTokens(JSON.stringify(packet.context)) +
      estimateTokens(JSON.stringify(packet.untrusted_context)) +
      estimateTokens(packet.allowed_tools.join(',')) +
      400
    );
  }

  /** Default per-worker tool palette (§35): registry tools usable by the type. */
  private defaultToolPalette(workerType: WorkerType): string[] {
    return this.deps.tools
      .list()
      .filter((t) => toolAllowedForWorker(t.name, workerType))
      .map((t) => t.name);
  }

  /**
   * Rebuilds a worker packet from a PERSISTED task record (used by retries,
   * recovery and rescheduling — never the model's memory, §19).
   */
  async packetForTask(task: TaskRecord): Promise<WorkerTaskPacket> {
    const { repos } = this.deps;
    const hypothesis = task.hypothesis_id
      ? await repos.hypotheses.findByIdAndEngagement(task.hypothesis_id, task.engagement_id)
      : null;
    const observations = await repos.observations.listByEngagement(task.engagement_id, 20);
    const spec: LeaderTaskSpec = {
      objective: task.objective,
      task_type: task.type,
      depends_on: task.depends_on,
      inputs: task.inputs,
      ...(task.expected_information_gain !== null
        ? { expected_information_gain: task.expected_information_gain }
        : {}),
    };
    const identity = null; // identity facts are attached from task.inputs by the loop
    return this.buildPacket(task, hypothesis, identity, observations, spec);
  }
}

// ---------------------------------------------------------------------------
// Retrieval helpers (§14: the compiler performs retrieval, not dump)
// ---------------------------------------------------------------------------

function selectRelevantObservations(
  observations: ObservationRecord[],
  spec: LeaderTaskSpec,
): ObservationRecord[] {
  const keywords = extractKeywords(spec);
  if (keywords.length === 0) return observations.slice(0, 10);
  const scored = observations.map((obs) => ({
    obs,
    score: keywords.reduce(
      (sum, keyword) => (obs.description.toLowerCase().includes(keyword) ? sum + 1 : sum),
      0,
    ),
  }));
  const relevant = scored
    .filter((s) => s.score > 0)
    .sort((a, b) => b.score - a.score)
    .map((s) => s.obs);
  return (relevant.length > 0 ? relevant : observations).slice(0, 10);
}

function extractKeywords(spec: LeaderTaskSpec): string[] {
  const inputs = spec.inputs ?? {};
  const words: string[] = [];
  for (const value of Object.values(inputs)) {
    if (typeof value === 'string' && value.length > 3) words.push(value.toLowerCase());
  }
  if (spec.target_hint) words.push(spec.target_hint.toLowerCase());
  return words.slice(0, 8);
}

function endpointFacts(spec: LeaderTaskSpec): Record<string, unknown> {
  const inputs = spec.inputs ?? {};
  const facts: Record<string, unknown> = {};
  if (typeof inputs.endpoint === 'string') facts.endpoint = inputs.endpoint;
  if (typeof inputs.method === 'string') facts.method = inputs.method;
  if (typeof inputs.parameter === 'string') facts.parameter = inputs.parameter;
  if (Array.isArray(inputs.observed_ids)) facts.observed_ids = inputs.observed_ids;
  if (typeof inputs.query === 'string') facts.query = inputs.query;
  if (spec.target_hint) facts.target_hint = spec.target_hint;
  return facts;
}

function stringInput(
  inputs: Record<string, unknown> | undefined,
  key: string,
): string | undefined {
  const value = inputs?.[key];
  return typeof value === 'string' ? value : undefined;
}

function summarizeInputs(inputs: Record<string, unknown> | undefined): string {
  if (!inputs) return '';
  return Object.keys(inputs).slice(0, 8).join(',');
}

function estimateTestCost(constraints: Record<string, unknown>): number {
  const requests = typeof constraints.max_network_requests === 'number'
    ? constraints.max_network_requests
    : 20;
  return Math.min(1, requests / 40);
}

export type { TaskType };
