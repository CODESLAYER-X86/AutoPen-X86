/**
 * Decision validator (spec Part 2 §10).
 *
 * Every leader decision passes the full deterministic pipeline:
 *
 *   schema validation      (done by validateLeaderDecision before this layer)
 *     -> semantic validation   (referenced entities exist; tools exist)
 *     -> engagement validation (engagement + run are active)
 *     -> scope validation      (URLs/hints in task inputs must be in scope)
 *     -> permission validation (AgentPolicy)
 *     -> resource validation   (budgets + quota + token budgets)
 *     -> duplicate-test validation (fingerprint registry, §28-§29)
 *
 * Invalid decisions are REJECTED with a machine-readable code; the loop
 * converts rejections into LEADER_DECISION_REJECTED events so the leader can
 * correct course (and anti-loop protection can count them).
 */
import type {
  EngagementBudgetRecord,
  EngagementRecord,
  EngagementUsageRecord,
  HypothesisRecord,
  ScopeRecord,
  TaskRecord,
} from '@aegis/database';
import type { LeaderDecision, LeaderTaskSpec } from '@aegis/contracts';
import { ScopeChecker } from '@aegis/security';
import type { ToolRegistry } from '@aegis/tools';
import type { WorkerType } from '@aegis/shared';
import { AgentPolicy } from './policy.js';
import type { QuotaManager, TokenBudgeter } from './quota.js';
import { computeTestFingerprint } from './fingerprints.js';
import { estimateTokens } from './quota.js';

/** Which tool name prefixes each worker type may use (§34-§35). */
export const WORKER_TOOL_PREFIXES: Record<WorkerType, string[]> = {
  HTTP_WORKER: ['http.', 'diff.', 'parser.', 'extract.', 'crypto.'],
  BROWSER_WORKER: ['browser.', 'parser.', 'extract.'],
  SOURCE_WORKER: ['source.', 'parser.', 'extract.', 'diff.'],
  ANALYSIS_WORKER: ['parser.', 'diff.', 'extract.', 'crypto.', 'knowledge.'],
};

export interface DecisionValidationInput {
  decision: LeaderDecision;
  engagement: EngagementRecord;
  scope: ScopeRecord | null;
  usage: EngagementUsageRecord;
  budget: EngagementBudgetRecord;
  quota: QuotaManager;
  tokenBudgets: TokenBudgeter;
}

export type DecisionValidationResult =
  | { ok: true; decision: LeaderDecision }
  | { ok: false; rejection: DecisionRejection };

export interface DecisionRejection {
  code: string;
  layer: 'SEMANTIC' | 'ENGAGEMENT' | 'SCOPE' | 'PERMISSION' | 'RESOURCE' | 'DUPLICATE';
  reason: string;
  details?: unknown;
}

export interface DecisionValidatorDeps {
  tools: ToolRegistry;
  /** Resolve existing tasks (dependency validation). */
  findTask: (engagementId: string, taskId: string) => Promise<TaskRecord | null>;
  findHypothesis: (engagementId: string, hypothesisId: string) => Promise<HypothesisRecord | null>;
  findIdentity: (engagementId: string, identityId: string) => Promise<{ id: string } | null>;
  fingerprintExists: (engagementId: string, fingerprint: string) => Promise<boolean>;
  /** Active run status ('RUNNING' etc.) — null when no active run. */
  runStatus: string | null;
}

export class DecisionValidator {
  constructor(private readonly deps: DecisionValidatorDeps) {}

  async validate(input: DecisionValidationInput): Promise<DecisionValidationResult> {
    const { decision, engagement } = input;

    // --- Engagement validation (layer 3) ---
    if (engagement.status !== 'RUNNING') {
      return reject('ENGAGEMENT_NOT_RUNNING', 'ENGAGEMENT', `Engagement status is ${engagement.status}`);
    }
    if (this.deps.runStatus && this.deps.runStatus !== 'RUNNING' && this.deps.runStatus !== 'WAITING') {
      return reject(
        'AGENT_RUN_NOT_ACTIVE',
        'ENGAGEMENT',
        `Agent run status is ${this.deps.runStatus}; decisions require an active run`,
      );
    }

    // --- Semantic + scope + permission + resource + duplicate per decision ---
    switch (decision.decision) {
      case 'CREATE_TASK':
        return this.validateTaskSpec(input, decision.task, 0);
      case 'CREATE_PARALLEL_TASKS':
        return this.validateParallelTasks(input, decision.tasks);
      case 'UPDATE_HYPOTHESIS':
        return this.validateHypothesisUpdate(input, decision.hypothesis_id ?? null);
      case 'REQUEST_KNOWLEDGE':
        return this.validateResource(input, 'knowledge', 2_000);
      case 'REQUEST_RECON': {
        const base: LeaderTaskSpec = {
          objective: `Recon: ${decision.focus}`,
          task_type: 'RECON',
          depends_on: [],
          ...(decision.task ?? {}),
        };
        return this.validateTaskSpec(input, base, 0);
      }
      case 'REQUEST_VERIFICATION':
        return this.validateVerification(input, decision.hypothesis_id);
      case 'WAIT':
      case 'STOP':
      case 'PAUSE':
        return { ok: true, decision };
      default:
        return reject('UNKNOWN_DECISION', 'SEMANTIC', 'Unreachable decision type');
    }
  }

  private async validateParallelTasks(
    input: DecisionValidationInput,
    tasks: LeaderTaskSpec[],
  ): Promise<DecisionValidationResult> {
    // §32: parallel tasks must not depend on each other (independence).
    const ids = new Set<string>();
    for (const spec of tasks) {
      for (const dep of spec.depends_on ?? []) {
        if (ids.has(dep)) {
          return reject(
            'PARALLEL_TASKS_NOT_INDEPENDENT',
            'SEMANTIC',
            `Parallel task depends on sibling task ${dep}; use CREATE_TASK for ordered work`,
          );
        }
      }
      ids.add(spec.objective);
    }

    // Resource estimate covers all tasks (§38 worker budget).
    const totalEstimate = tasks.length * this.estimateTaskTokens(tasks[0] ?? { objective: '', task_type: 'RECON', depends_on: [] });
    const resource = this.validateResource(input, 'worker', totalEstimate);
    if (!resource.ok) return resource;

    for (const spec of tasks) {
      const result = await this.validateTaskSpec(input, spec, 0, { skipResource: true });
      if (!result.ok) return result;
    }
    return { ok: true, decision: input.decision };
  }

  private async validateTaskSpec(
    input: DecisionValidationInput,
    spec: LeaderTaskSpec,
    _index: number,
    options: { skipResource?: boolean } = {},
  ): Promise<DecisionValidationResult> {
    const { engagement, scope, usage, budget } = input;

    // --- Semantic: allowed tools exist in the registry (kills hallucinations)
    const allowedTools = spec.allowed_tools ?? [];
    for (const toolName of allowedTools) {
      if (!this.deps.tools.has(toolName)) {
        return reject(
          'TOOL_NOT_FOUND',
          'SEMANTIC',
          `Decision references unknown tool '${toolName}'`,
          { tool: toolName },
        );
      }
    }

    // --- Semantic: worker-type/tool consistency (§34-§35)
    const workerType = spec.worker_type ?? defaultWorkerForTaskType(spec.task_type);
    for (const toolName of allowedTools) {
      if (!toolAllowedForWorker(toolName, workerType)) {
        return reject(
          'TOOL_NOT_PERMITTED_FOR_WORKER',
          'SEMANTIC',
          `Tool '${toolName}' is not usable by ${workerType}`,
          { tool: toolName, worker_type: workerType },
        );
      }
    }

    // --- Semantic: dependencies exist and belong to the engagement (§19)
    for (const depId of spec.depends_on ?? []) {
      const dep = await this.deps.findTask(engagement.id, depId);
      if (!dep) {
        return reject(
          'DEPENDENCY_NOT_FOUND',
          'SEMANTIC',
          `Task depends on unknown task '${depId}'`,
          { task_id: depId },
        );
      }
    }

    // --- Semantic: hypothesis reference
    if (spec.hypothesis_id) {
      const hypothesis = await this.deps.findHypothesis(engagement.id, spec.hypothesis_id);
      if (!hypothesis) {
        return reject(
          'HYPOTHESIS_NOT_FOUND',
          'SEMANTIC',
          `Decision references unknown hypothesis '${spec.hypothesis_id}'`,
          { hypothesis_id: spec.hypothesis_id },
        );
      }
      if (hypothesis.status === 'CONFIRMED' || hypothesis.status === 'DISPROVED' || hypothesis.status === 'ABANDONED') {
        return reject(
          'HYPOTHESIS_TERMINAL',
          'SEMANTIC',
          `Hypothesis '${spec.hypothesis_id}' is ${hypothesis.status}; testing it again is dead-end work`,
          { hypothesis_id: spec.hypothesis_id, status: hypothesis.status },
        );
      }
    }

    // --- Semantic: identity reference
    if (spec.identity_id) {
      const identity = await this.deps.findIdentity(engagement.id, spec.identity_id);
      if (!identity) {
        return reject(
          'IDENTITY_NOT_FOUND',
          'SEMANTIC',
          `Decision references unknown identity '${spec.identity_id}'`,
          { identity_id: spec.identity_id },
        );
      }
    }

    // --- Scope validation (layer 4): URLs in task inputs / target hint
    if (!scope) {
      // No scope: any task that would touch the network is rejected.
      if (allowedTools.some((t) => this.toolNeedsNetwork(t))) {
        return reject(
          'SCOPE_NOT_CONFIGURED',
          'SCOPE',
          'Engagement has no scope; network-touching tasks cannot be created',
        );
      }
    } else {
      const scopeChecker = new ScopeChecker(AgentPolicy.scopeRules(scope)!);
      const urls = extractCandidateUrls(spec);
      for (const url of urls) {
        const result = scopeChecker.checkUrl(url);
        if (!result.allowed) {
          return reject('SCOPE_VIOLATION', 'SCOPE', `Task input URL outside scope: ${result.reason}`, {
            url,
            code: result.code,
          });
        }
      }
    }

    // --- Permission validation (layer 5)
    const policy = new AgentPolicy();
    const policyDecision = policy.evaluateTask(
      { engagement, scope, usage, budget },
      { type: spec.task_type, worker_type: workerType, allowed_tools: allowedTools },
    );
    if (policyDecision.outcome === 'DENY') {
      return reject('POLICY_DENIED', 'PERMISSION', policyDecision.reason, {
        rule: policyDecision.rule,
      });
    }

    // --- Resource validation (layer 6)
    if (!options.skipResource) {
      const resource = this.validateResource(input, 'worker', this.estimateTaskTokens(spec));
      if (!resource.ok) return resource;
    }

    // --- Duplicate-test validation (layer 7)
    const fingerprint = computeTestFingerprint({
      endpoint: taskEndpoint(spec),
      method: taskMethod(spec),
      identity: spec.identity_id ?? null,
      mutationType: spec.task_type,
      relevantParameter: taskParameter(spec),
      mutation: sanitizeMutation(spec.inputs),
    });
    if (await this.deps.fingerprintExists(engagement.id, fingerprint)) {
      return reject(
        'TEST_DUPLICATE',
        'DUPLICATE',
        'An equivalent test is already registered; the scheduler refuses duplicate work (spec §28-§29)',
        { fingerprint },
      );
    }

    return { ok: true, decision: input.decision };
  }

  private async validateHypothesisUpdate(
    input: DecisionValidationInput,
    hypothesisId: string | null,
  ): Promise<DecisionValidationResult> {
    const decision = input.decision;
    if (decision.decision !== 'UPDATE_HYPOTHESIS') {
      return reject('INTERNAL_MISMATCH', 'SEMANTIC', 'Decision mismatch');
    }
    if (decision.change === 'CREATE') {
      if (!decision.hypothesis) {
        return reject('HYPOTHESIS_SPEC_MISSING', 'SEMANTIC', 'CREATE requires a hypothesis spec');
      }
      if (decision.hypothesis.parent_hypothesis_id) {
        const parent = await this.deps.findHypothesis(
          input.engagement.id,
          decision.hypothesis.parent_hypothesis_id,
        );
        if (!parent) {
          return reject('PARENT_HYPOTHESIS_NOT_FOUND', 'SEMANTIC', 'Parent hypothesis does not exist');
        }
      }
      return this.validateResource(input, 'leader', 500);
    }

    if (!hypothesisId) {
      return reject('HYPOTHESIS_ID_MISSING', 'SEMANTIC', 'Non-CREATE updates require hypothesis_id');
    }
    const hypothesis = await this.deps.findHypothesis(input.engagement.id, hypothesisId);
    if (!hypothesis) {
      return reject('HYPOTHESIS_NOT_FOUND', 'SEMANTIC', `Unknown hypothesis '${hypothesisId}'`);
    }
    return { ok: true, decision };
  }

  private async validateVerification(
    input: DecisionValidationInput,
    hypothesisId: string,
  ): Promise<DecisionValidationResult> {
    const hypothesis = await this.deps.findHypothesis(input.engagement.id, hypothesisId);
    if (!hypothesis) {
      return reject('HYPOTHESIS_NOT_FOUND', 'SEMANTIC', `Unknown hypothesis '${hypothesisId}'`);
    }
    if (hypothesis.status === 'ABANDONED') {
      return reject('HYPOTHESIS_ABANDONED', 'SEMANTIC', 'Cannot verify an abandoned hypothesis');
    }
    // §55: verification belongs after SUPPORTED; allow TESTING for mid-flight
    // skeptical checks, and CONFIRMED-adjacent SUPPORTED/DISPROVED flows.
    if (hypothesis.status === 'DISPROVED' || hypothesis.status === 'CONFIRMED') {
      return reject(
        'HYPOTHESIS_ALREADY_RESOLVED',
        'SEMANTIC',
        `Hypothesis is already ${hypothesis.status}`,
      );
    }
    // Verification uses its own budget bucket (§38).
    const resource = this.validateResource(input, 'verification', 3_000);
    if (!resource.ok) return resource;
    return { ok: true, decision: input.decision };
  }

  private validateResource(
    input: DecisionValidationInput,
    purpose: 'leader' | 'worker' | 'knowledge' | 'summarization' | 'verification',
    estimatedTokens: number,
  ): DecisionValidationResult {
    const policy = new AgentPolicy();
    const budgetDenial = policy.checkBudget({
      engagement: input.engagement,
      scope: input.scope,
      usage: input.usage,
      budget: input.budget,
    });
    if (budgetDenial) {
      return reject('RESOURCE_BUDGET_EXHAUSTED', 'RESOURCE', budgetDenial.reason, {
        rule: budgetDenial.rule,
      });
    }

    const spend = input.tokenBudgets.canSpend(purpose, estimatedTokens, Math.ceil(estimatedTokens * 0.5));
    if (!spend.allowed) {
      return reject('TOKEN_BUDGET_EXHAUSTED', 'RESOURCE', spend.reason ?? 'Token budget exhausted');
    }

    const dispatch = input.quota.canDispatch(estimatedTokens, Math.ceil(estimatedTokens * 0.5));
    if (!dispatch.allowed) {
      return reject('QUOTA_DELAY_REQUIRED', 'RESOURCE', dispatch.reason, {
        retry_after_ms: dispatch.retryAfterMs,
      });
    }

    return { ok: true, decision: input.decision };
  }

  private estimateTaskTokens(spec: LeaderTaskSpec): number {
    // Rough worker-packet estimate: objective + inputs + tool docs margin.
    return estimateTokens(spec.objective) + estimateTokens(JSON.stringify(spec.inputs ?? {})) + 800;
  }

  private toolNeedsNetwork(toolName: string): boolean {
    const tool = this.deps.tools.get(toolName);
    return tool ? tool.capabilities.includes('NETWORK') : true; // unknown = assume network
  }
}

function reject(
  code: string,
  layer: DecisionRejection['layer'],
  reason: string,
  details?: unknown,
): DecisionValidationResult {
  return { ok: false, rejection: { code, layer, reason, details } };
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

export function defaultWorkerForTaskType(taskType: string): WorkerType {
  switch (taskType) {
    case 'RECON':
    case 'HTTP_ANALYSIS':
    case 'AUTHORIZATION_ANALYSIS':
    case 'AUTHENTICATION_ANALYSIS':
    case 'SESSION_ANALYSIS':
    case 'INPUT_VALIDATION_ANALYSIS':
      return 'HTTP_WORKER';
    case 'BROWSER_INVESTIGATION':
      return 'BROWSER_WORKER';
    case 'SOURCE_ANALYSIS':
      return 'SOURCE_WORKER';
    default:
      return 'ANALYSIS_WORKER';
  }
}

export function toolAllowedForWorker(toolName: string, workerType: WorkerType): boolean {
  const prefixes = WORKER_TOOL_PREFIXES[workerType];
  return prefixes.some((prefix) => toolName.startsWith(prefix));
}

function taskEndpoint(spec: LeaderTaskSpec): string {
  const inputs = spec.inputs ?? {};
  const hint = spec.target_hint ?? '';
  const endpoint =
    (typeof inputs.endpoint === 'string' && inputs.endpoint) ||
    (typeof inputs.path === 'string' && inputs.path) ||
    hint ||
    'engagement';
  return endpoint;
}

function taskMethod(spec: LeaderTaskSpec): string {
  const inputs = spec.inputs ?? {};
  return typeof inputs.method === 'string' ? inputs.method : 'GET';
}

function taskParameter(spec: LeaderTaskSpec): string | undefined {
  const inputs = spec.inputs ?? {};
  return typeof inputs.parameter === 'string' ? inputs.parameter : undefined;
}

function sanitizeMutation(inputs: Record<string, unknown> | undefined): Record<string, unknown> | undefined {
  if (!inputs) return undefined;
  const { url, token, password, secret, ...rest } = inputs as Record<string, unknown>;
  void url;
  void token;
  void password;
  void secret;
  return rest;
}

/** URLs that appear in task specs — subject to scope validation. */
function extractCandidateUrls(spec: LeaderTaskSpec): string[] {
  const urls: string[] = [];
  const candidates = [
    spec.target_hint,
    (spec.inputs as Record<string, unknown> | undefined)?.url,
    (spec.inputs as Record<string, unknown> | undefined)?.endpoint,
  ];
  for (const candidate of candidates) {
    if (typeof candidate === 'string' && /^https?:\/\//i.test(candidate)) {
      urls.push(candidate);
    }
  }
  return urls;
}
