/**
 * Adaptive task planner (spec Part 6 §38, §20, §46).
 *
 * Compiles Part 4 deterministic TEST CANDIDATES into worker tasks through
 * the SAME validated compiler path as leader decisions (§47): the planner
 * builds a synthetic CREATE_PARALLEL_TASKS decision and hands it to the
 * Part 2 TaskCompiler. Tasks are generated INCREMENTALLY in small batches —
 * never thousands of pre-generated tasks (§38) — bounded by the candidate
 * batch limit, preconditions and resource budget.
 *
 * The LLM never constructs an unrestricted network operation (§1): the
 * candidate carries a structured mutation plan resolved by the deterministic
 * mutation engine (§20).
 */
import type { Repositories, TaskRecord } from '@aegis/database';
import type { TestCandidate, LeaderDecision, LeaderTaskSpec, PlatformEvent } from '@aegis/contracts';
import type { EventBus } from '@aegis/events';
import { generateId } from '@aegis/shared';
import { TaskCompiler, type CompiledTask } from '@aegis/agent';
import type { TaskType } from '@aegis/shared';

/** Part 4 test types -> Part 2 task types. */
const TEST_TYPE_MAP: Record<string, TaskType> = {
  IDENTITY_COMPARISON: 'AUTHORIZATION_ANALYSIS',
  ANONYMOUS_ACCESS: 'AUTHORIZATION_ANALYSIS',
  STRUCTURED_MUTATION: 'INPUT_VALIDATION_ANALYSIS',
  SESSION_VALIDATION: 'SESSION_ANALYSIS',
  WORKFLOW_ORDER: 'AUTHENTICATION_ANALYSIS',
  PARAMETER_PROBE: 'INPUT_VALIDATION_ANALYSIS',
};

function mapTestType(testType: string): TaskType {
  return TEST_TYPE_MAP[testType] ?? 'GENERAL_ANALYSIS';
}

export interface TaskPlannerOptions {
  /** Maximum candidates compiled per cycle (§38 adaptive batches). */
  batchLimit: number;
}

export interface TaskPlannerDeps {
  repos: Repositories;
  compiler: TaskCompiler;
  eventBus: EventBus;
  options?: Partial<TaskPlannerOptions>;
}

export interface PlannedBatch {
  tasks: TaskRecord[];
  skipped: Array<{ fingerprint: string; reason: string }>;
}

export class TaskPlanner {
  private readonly opts: TaskPlannerOptions;

  constructor(private readonly deps: TaskPlannerDeps) {
    this.opts = { batchLimit: deps.options?.batchLimit ?? 6 };
  }

  /**
   * Compile a batch of test candidates (§38). Candidates failing
   * preconditions are skipped with explicit reasons — never silently
   * dropped (auditability).
   */
  async compileCandidates(
    engagementId: string,
    runId: string,
    candidates: TestCandidate[],
  ): Promise<PlannedBatch> {
    const skipped: Array<{ fingerprint: string; reason: string }> = [];
    const eligible: TestCandidate[] = [];

    for (const candidate of candidates) {
      if (eligible.length >= this.opts.batchLimit) {
        skipped.push({ fingerprint: candidate.fingerprint, reason: 'batch limit reached (§38 incremental generation)' });
        continue;
      }
      if (!candidate.preconditions.scope_ok) {
        skipped.push({ fingerprint: candidate.fingerprint, reason: 'scope not ok' });
        continue;
      }
      if (!candidate.preconditions.duplicate_absent) {
        skipped.push({ fingerprint: candidate.fingerprint, reason: 'duplicate test already registered' });
        continue;
      }
      if (!candidate.preconditions.identity_available && candidate.candidate_identity) {
        skipped.push({ fingerprint: candidate.fingerprint, reason: 'identity session unavailable (§37 IDENTITY_AVAILABLE)' });
        continue;
      }
      if (!candidate.preconditions.baseline_available && candidate.base_request_id) {
        skipped.push({ fingerprint: candidate.fingerprint, reason: 'baseline request unavailable' });
        continue;
      }
      eligible.push(candidate);
    }

    if (eligible.length === 0) return { tasks: [], skipped };

    const specs: LeaderTaskSpec[] = eligible.map((candidate) => this.specFor(candidate));
    const decision: LeaderDecision = {
      decision: 'CREATE_PARALLEL_TASKS',
      reasoning_summary: `Deterministic test-candidate batch (${eligible.length} candidates) compiled by the autonomous engine from the reasoning engine's planned tests (§38, §20).`,
      tasks: specs,
    };

    const compiled: CompiledTask[] = await this.deps.compiler.compile(decision, {
      engagementId,
      runId,
      // Null decisionId: the compiler generates unique engine-batch
      // idempotency keys (§65) and keeps tasks.decision_id null (FK-safe).
      decisionId: null,
    });
    if (compiled.length > 0) {
      const event: PlatformEvent = {
        type: 'TEST_CANDIDATES_COMPILED',
        engagement_id: engagementId,
        trace_id: generateId('TRC'),
        actor_id: null,
        payload: {
          count: compiled.length,
          fingerprints: eligible.map((candidate) => candidate.fingerprint).slice(0, 8),
          run_id: runId,
        },
        occurred_at: new Date().toISOString(),
        dedup_key: `candidates-compiled:${engagementId}:${runId}:${compiled[0]!.task.id}`,
      };
      await this.deps.eventBus.publish(event).catch(() => undefined);
    }
    return { tasks: compiled.map((c) => c.task), skipped };
  }

  /** Candidate -> worker task spec (§20 mutation plan integration). */
  private specFor(candidate: TestCandidate): LeaderTaskSpec {
    const objective = this.objectiveFor(candidate);
    const isMutation = candidate.mutations.length > 0 && candidate.base_request_id;
    return {
      objective,
      task_type: mapTestType(candidate.test_type),
      worker_type: isMutation ? 'HTTP_WORKER' : undefined,
      hypothesis_id: candidate.hypothesis_id ?? undefined,
      identity_id: candidate.candidate_identity ?? undefined,
      depends_on: [],
      priority: candidate.priority,
      expected_information_gain: candidate.expected_information_gain,
      potential_impact: 0.6,
      inputs: {
        mode: 'TEST_CANDIDATE',
        test_candidate: true,
        base_request_id: candidate.base_request_id,
        baseline_identity: candidate.baseline_identity,
        candidate_identity: candidate.candidate_identity,
        mutation_category: candidate.mutation_category,
        mutations: candidate.mutations,
        expected_signal: this.expectedSignalFor(candidate),
        fingerprint: candidate.fingerprint,
        rationale: candidate.rationale,
        endpoint_id: candidate.endpoint_id,
        // Workers MUST use the structured mutation path (http.mutate), never
        // hand-built requests (§20).
        instruction:
          'Execute this planned test exactly: replay the base request with the provided structured mutations via the http.mutate tool, then compare the outcome against the expected signal. Do not invent alternative requests.',
      },
      allowed_tools: isMutation
        ? ['http.mutate', 'http.replay', 'diff.response', 'reasoning.query']
        : ['http.request', 'http.replay', 'diff.response', 'reasoning.query'],
      constraints: { max_tool_calls: 8, max_network_requests: 8, max_duration_seconds: 120 },
      target_hint: candidate.endpoint_id ?? undefined,
    };
  }

  private objectiveFor(candidate: TestCandidate): string {
    const identityPart = candidate.candidate_identity
      ? ` as identity ${candidate.candidate_identity}`
      : ' anonymously';
    if (candidate.test_type === 'IDENTITY_COMPARISON') {
      return `Identity differential test: replay the base request${identityPart} with the planned object-identifier mutation (${candidate.mutation_category ?? 'IDENTIFIER'}) and determine whether the response exposes another identity's protected data.`;
    }
    if (candidate.test_type === 'ANONYMOUS_ACCESS') {
      return `Anonymous access test: request the protected endpoint without authentication and record whether protected content is returned.`;
    }
    if (candidate.test_type === 'STRUCTURED_MUTATION') {
      return `Structured mutation test: apply the planned mutations (${candidate.mutation_category ?? 'PARAMETER'}) to the base request and compare the response semantics against the baseline.`;
    }
    return `Execute planned security test (${candidate.test_type}) with the provided structured mutation plan and record the observed signal.`;
  }

  private expectedSignalFor(candidate: TestCandidate): string {
    if (candidate.test_type === 'IDENTITY_COMPARISON') {
      return 'SUPPORTED if the mutated request returns another identity object data; DISPROVED if the server rejects the foreign object (403/404) or returns only own data.';
    }
    if (candidate.test_type === 'ANONYMOUS_ACCESS') {
      return 'SUPPORTED if protected content is returned without authentication; DISPROVED if the server requires authentication.';
    }
    return 'SUPPORTED if the mutation changes the response semantics relative to the baseline in the predicted direction; otherwise DISPROVED.';
  }
}
