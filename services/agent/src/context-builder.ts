/**
 * Strategic context builder (spec Part 2 §6-§8, §47).
 *
 * Builds the leader's CONTEXT PROJECTION — never the whole database.
 * Trusted, application-derived state and untrusted target-derived content
 * are assembled into two SEPARATE structures so the prompt builder can wrap
 * the untrusted side in explicit delimiters (§61).
 *
 * Context reduction follows the §7 priority order:
 *   1 scope, 2 objective, 3 confirmed facts, 4 active hypotheses,
 *   5 recent observations, 6 unresolved anomalies, 7 relevant evidence,
 *   8 recent tests, 9 dead ends, 10 historical background.
 * Scope is NEVER truncated to save tokens.
 */

import type { Repositories, TaskRecord } from '@aegis/database';
import type { ToolRegistry } from '@aegis/tools';
import type { SecurityContextProvider, SecurityProjection, KnowledgeContextProvider } from '@aegis/contracts';
import type { QuotaSnapshot, TokenBudgeter } from './quota.js';
import { estimateTokens } from './quota.js';

export interface StrategicContextInput {
  engagementId: string;
  /** Soft cap for the serialized context (trusted + untrusted). */
  maxContextTokens: number;
}

export interface StrategicContext {
  /** Trusted projection (application state). Rendered as TRUSTED CONTEXT. */
  trusted: {
    engagement: Record<string, unknown>;
    objective: Record<string, unknown>;
    scope: Record<string, unknown>;
    assets: Array<Record<string, unknown>>;
    identities: Array<Record<string, unknown>>;
    attack_surface: Record<string, unknown>;
    workflow_state: Record<string, unknown>;
    /** Part 5 §87: trusted knowledge metadata (sources/trust/relevance). */
    knowledge: Record<string, unknown> | null;
    observations: Array<Record<string, unknown>>;
    hypotheses: Array<Record<string, unknown>>;
    recent_tests: Array<Record<string, unknown>>;
    dead_ends: Array<Record<string, unknown>>;
    findings: Array<Record<string, unknown>>;
    available_tools: Array<Record<string, unknown>>;
    resource_state: Record<string, unknown>;
    pending_tasks: Array<Record<string, unknown>>;
  };
  /**
   * Untrusted projection (target-derived). Everything the target controls:
   * observation descriptions, evidence summaries, CTF challenge text and
   * clues. Rendered inside explicit untrusted delimiters.
   */
  untrusted: {
    observation_details: Array<Record<string, unknown>>;
    evidence_summaries: Array<Record<string, unknown>>;
    ctf: Record<string, unknown> | null;
    /** Part 4 §115/§116: signal/test text derived from untrusted target data. */
    security_projection: Record<string, unknown> | null;
    /** Part 5 §50/§115: retrieved external knowledge excerpts — rendered
     * inside UNTRUSTED_EXTERNAL_KNOWLEDGE delimiters by the prompt layer. */
    knowledge_excerpts: Record<string, unknown> | null;
  };
}

export interface ContextBuilderDeps {
  repos: Repositories;
  tools: ToolRegistry;
  /** Part 4 §120: compact security projection provider (optional seam). */
  security?: SecurityContextProvider;
  /** Part 5 §120: compact knowledge packet provider (optional seam). */
  knowledge?: KnowledgeContextProvider;
}

export const DEFAULT_MAX_CONTEXT_TOKENS = 24_000;

/** §7 priority order — indices reduce LAST to FIRST when shrinking. */
const REDUCTION_ORDER = [
  'historical_background',
  'knowledge_excerpts',
  'security_projection',
  'recent_tests',
  'dead_ends',
  'findings_detail',
  'evidence_summaries',
  'unresolved_anomalies',
  'older_observations',
  'pending_tasks_detail',
] as const;

export class ContextBuilder {
  constructor(private readonly deps: ContextBuilderDeps) {}

  async build(input: StrategicContextInput): Promise<StrategicContext> {
    const { repos } = this.deps;
    const engagementId = input.engagementId;

    const [engagement, scope, targets, assets, identities, observations, hypotheses, tests, deadEnds, findings, strategies, pendingTasks] =
      await Promise.all([
        repos.engagements.findById(engagementId),
        repos.scope.findByEngagement(engagementId),
        repos.targets.listByEngagement(engagementId),
        repos.assets.listByEngagement(engagementId),
        repos.identities.listByEngagement(engagementId),
        repos.observations.listByEngagement(engagementId, 40),
        repos.hypotheses.listByEngagement(engagementId, {
          statuses: ['PROPOSED', 'ACTIVE', 'TESTING', 'SUPPORTED'],
        }),
        repos.tests.listByEngagement(engagementId, 15),
        repos.deadEnds.listByEngagement(engagementId, 10),
        repos.findings.listByEngagement(engagementId, { statuses: ['CONFIRMED', 'PROPOSED'] }),
        repos.strategies.latestByEngagement(engagementId),
        repos.tasks.listByEngagement(engagementId, {
          statuses: ['CREATED', 'QUEUED', 'READY', 'RUNNING', 'WAITING', 'RECOVERY_PENDING'],
        }),
      ]);

    if (!engagement) {
      throw Object.assign(new Error(`Engagement ${engagementId} not found`), { code: 'ENGAGEMENT_NOT_FOUND' });
    }

    // Part 4 §120: deterministic security projection. Failures degrade to
    // the Part 2-only projection (the leader still works, §112 isolation).
    const securityProjection = this.deps.security
      ? await this.deps.security.buildSecurityProjection(engagementId).catch(() => null)
      : null;
    const projection = securityProjection ? splitProjection(securityProjection) : null;

    // Part 5 §87/§120: compact knowledge packet. Retrieved knowledge is
    // advisory; excerpts are UNTRUSTED external content (§41/§50) rendered
    // inside explicit delimiters. Failures degrade to the knowledge-free
    // projection (§112 isolation).
    const knowledgeContext = this.deps.knowledge
      ? await this.deps.knowledge
          .buildKnowledgeContext(engagementId)
          .catch(() => null)
      : null;

    // --- Trusted projection: structured facts over prose (§15) ---
    const trusted: StrategicContext['trusted'] = {
      engagement: {
        id: engagement.id,
        name: engagement.name,
        mode: engagement.mode,
        status: engagement.status,
      },
      objective: {
        description: engagement.description,
        mode: engagement.mode,
        completed_hypotheses: (await repos.hypotheses.countByStatus(engagementId)).CONFIRMED,
      },
      scope: scope
        ? {
            allowed_hosts: scope.allowed_hosts,
            allowed_domains: scope.allowed_domains,
            allowed_ports: scope.allowed_ports,
            allowed_schemes: scope.allowed_schemes,
            excluded_hosts: scope.excluded_hosts,
            excluded_paths: scope.excluded_paths,
            destructive_actions_allowed: scope.destructive_actions_allowed,
          }
        : { note: 'NO SCOPE CONFIGURED — all network testing is blocked' },
      assets: assets.slice(0, 30).map((a) => ({ id: a.id, type: a.type, value: a.value, label: a.label })),
      identities: identities.slice(0, 20).map((i) => ({
        // Secrets NEVER enter the context: only non-secret identity facts.
        id: i.id,
        name: i.name,
        role: i.role,
        type: i.type,
      })),
      attack_surface: {
        target_count: targets.length,
        targets: targets.slice(0, 20).map((t) => ({ id: t.id, type: t.type, value: t.value })),
        discovered_endpoints: summarizeEndpoints(observations),
        // Part 4 §120: counts + ids only (trusted); string-bearing detail is
        // routed to the untrusted projection below (§115/§116).
        ...(projection ? { security_projection: projection.trusted_summary } : {}),
      },
      workflow_state: {
        strategy: strategies
          ? { version: strategies.version, focus: strategies.focus, summary: strategies.summary }
          : null,
      },
      // Part 5 §87: trusted knowledge metadata (source names, trust levels,
      // relevance — never page content).
      knowledge: knowledgeContext?.trusted_summary ?? null,
      // Observation INDEX (trusted metadata only; descriptions are untrusted).
      observations: observations.map((o) => ({
        id: o.id,
        type: o.type,
        confidence: o.confidence,
        task_id: o.task_id,
        created_at: o.created_at,
      })),
      hypotheses: hypotheses.map((h) => ({
        id: h.id,
        type: h.type,
        statement: h.statement,
        status: h.status,
        confidence: h.confidence,
        priority: h.priority,
        parent_hypothesis_id: h.parent_hypothesis_id,
      })),
      recent_tests: tests.map((t) => ({
        id: t.id,
        test_type: t.test_type,
        target: t.target,
        status: t.status,
        mutation_summary: t.mutation_summary,
      })),
      dead_ends: deadEnds.map((d) => ({
        id: d.id,
        hypothesis_id: d.hypothesis_id,
        description: d.description,
        reason: d.reason,
      })),
      findings: findings.map((f) => ({
        id: f.id,
        title: f.title,
        severity: f.severity,
        status: f.status,
      })),
      available_tools: this.deps.tools.list().map((t) => ({
        name: t.name,
        description: t.description,
        risk_level: t.risk_level,
        capabilities: t.capabilities,
        implemented: t.implemented,
        ...(t.planned_part ? { planned_part: t.planned_part } : {}),
      })),
      resource_state: {},
      pending_tasks: pendingTasks.map(projectPendingTask),
    };

    // --- Untrusted projection (target-controlled content) ---
    const ctfClues = observations
      .filter((o) => o.type === 'CTF_CLUE')
      .map((o) => ({ id: o.id, clue: o.description, source: o.metadata?.source ?? 'human' }));

    const untrusted: StrategicContext['untrusted'] = {
      observation_details: observations
        .filter((o) => o.type !== 'CTF_CLUE')
        .slice(0, 25)
        .map((o) => ({ id: o.id, type: o.type, description: o.description, confidence: o.confidence })),
      evidence_summaries: [],
      ctf:
        engagement.mode === 'CTF'
          ? {
              // §47: the challenge description is DATA, never trusted instructions.
              challenge_description: engagement.description,
              clues: ctfClues,
              known_flag_format: firstStringFromObservations(observations, 'flag_format'),
              challenge_metadata: {},
              provided_files: [],
              known_constraints: [],
            }
          : null,
      security_projection: projection ? projection.untrusted_detail : null,
      // Part 5 §50/§41: excerpts wrapped in EXTERNAL_KNOWLEDGE delimiters
      // by the prompt layer — external text is data, never instructions.
      knowledge_excerpts: knowledgeContext?.untrusted_detail ?? null,
    };

    return this.reduceToBudget({ trusted, untrusted }, input.maxContextTokens);
  }

  /**
   * Priority-ordered context reduction (§7). Scope and objective are never
   * touched; the reducer works from "historical background" inward.
   */
  reduceToBudget(context: StrategicContext, maxTokens: number): StrategicContext {
    let current = context;
    let tokens = this.estimateContext(current);

    // Only observations beyond the most recent 10 are "older" (drop first).
    const applyReducer = (reduce: (c: StrategicContext) => StrategicContext): void => {
      if (tokens <= maxTokens) return;
      current = reduce(current);
      tokens = this.estimateContext(current);
    };

    for (const step of REDUCTION_ORDER) {
      if (tokens <= maxTokens) break;
      switch (step) {
        case 'historical_background':
          applyReducer((c) => ({
            ...c,
            trusted: {
              ...c.trusted,
              findings: c.trusted.findings.slice(0, 5),
              dead_ends: c.trusted.dead_ends.slice(0, 5),
              recent_tests: c.trusted.recent_tests.slice(0, 8),
            },
          }));
          break;
        case 'knowledge_excerpts':
          // Part 5 detail is supplementary: shrink excerpts first, then drop
          // the section entirely before touching Part 2 core fields.
          applyReducer((c) => ({
            ...c,
            untrusted: {
              ...c.untrusted,
              knowledge_excerpts: c.untrusted.knowledge_excerpts
                ? shrinkSecurityDetail(c.untrusted.knowledge_excerpts)
                : null,
            },
          }));
          break;
        case 'security_projection':
          // Part 4 §120 detail is supplementary: shrink untrusted detail
          // first, then drop it entirely before touching Part 2 core fields.
          applyReducer((c) => ({
            ...c,
            untrusted: {
              ...c.untrusted,
              security_projection: c.untrusted.security_projection
                ? shrinkSecurityDetail(c.untrusted.security_projection)
                : null,
            },
          }));
          break;
        case 'recent_tests':
          applyReducer((c) => ({
            ...c,
            trusted: { ...c.trusted, recent_tests: c.trusted.recent_tests.slice(0, 5) },
          }));
          break;
        case 'dead_ends':
          applyReducer((c) => ({
            ...c,
            trusted: { ...c.trusted, dead_ends: c.trusted.dead_ends.slice(0, 3) },
          }));
          break;
        case 'findings_detail':
          applyReducer((c) => ({
            ...c,
            trusted: { ...c.trusted, findings: c.trusted.findings.map(stripToIds) },
          }));
          break;
        case 'evidence_summaries':
          applyReducer((c) => ({
            ...c,
            untrusted: { ...c.untrusted, evidence_summaries: c.untrusted.evidence_summaries.slice(0, 5) },
          }));
          break;
        case 'unresolved_anomalies':
          applyReducer((c) => ({
            ...c,
            untrusted: {
              ...c.untrusted,
              observation_details: c.untrusted.observation_details.filter((o) => (o.confidence as number) >= 0.3),
            },
          }));
          break;
        case 'older_observations':
          applyReducer((c) => ({
            ...c,
            untrusted: {
              ...c.untrusted,
              observation_details: c.untrusted.observation_details.slice(0, 10),
            },
          }));
          break;
        case 'pending_tasks_detail':
          applyReducer((c) => ({
            ...c,
            trusted: { ...c.trusted, pending_tasks: c.trusted.pending_tasks.map(stripToIds) },
          }));
          break;
      }
    }

    return current;
  }

  estimateContext(context: StrategicContext): number {
    return estimateTokens(JSON.stringify(context.trusted)) + estimateTokens(
      JSON.stringify(context.untrusted),
    );
  }

  /** Attaches live quota/budget state (trusted; application-derived). */
  attachResourceState(
    context: StrategicContext,
    resourceState: {
      quota: QuotaSnapshot;
      tokenBudgets: ReturnType<TokenBudgeter['usage']>;
      usage: Record<string, unknown>;
    },
  ): StrategicContext {
    return {
      ...context,
      trusted: {
        ...context.trusted,
        resource_state: {
          quota: {
            rpm: resourceState.quota.requestsPerMinute,
            rpm_limit: resourceState.quota.limits.requestsPerMinute,
            input_tpm: resourceState.quota.inputTokensPerMinute,
            input_tpm_limit: resourceState.quota.limits.inputTokensPerMinute,
            requests_today: resourceState.quota.requestsPerDay,
            requests_per_day_limit: resourceState.quota.limits.requestsPerDay,
          },
          token_budgets: resourceState.tokenBudgets,
          engagement_usage: resourceState.usage,
        },
      },
    };
  }
}

function projectPendingTask(task: TaskRecord): Record<string, unknown> {
  return {
    id: task.id,
    type: task.type,
    status: task.status,
    priority: task.priority,
    objective: task.objective,
    worker_type: task.worker_type,
    hypothesis_id: task.hypothesis_id,
    depends_on: task.depends_on,
    attempts: task.attempts,
  };
}

/** Extracts endpoint-ish facts from observations for the attack surface. */
function summarizeEndpoints(
  observations: Array<{ type: string; description: string; metadata: Record<string, unknown> }>,
): Array<Record<string, unknown>> {
  const endpoints: Array<Record<string, unknown>> = [];
  const seen = new Set<string>();
  for (const obs of observations) {
    const meta = obs.metadata ?? {};
    const endpoint = firstString(meta.endpoint, meta.path, meta.url);
    const method = typeof meta.method === 'string' ? meta.method : null;
    if (!endpoint) continue;
    const key = `${method ?? ''} ${endpoint}`;
    if (seen.has(key)) continue;
    seen.add(key);
    endpoints.push({
      // Structured fact, not prose (§15).
      method,
      path: endpoint,
      ...(typeof meta.auth_required === 'boolean' ? { auth_required: meta.auth_required } : {}),
      ...(Array.isArray(meta.observed_ids) ? { observed_ids: meta.observed_ids } : {}),
    });
  }
  return endpoints.slice(0, 30);
}

function firstString(...values: unknown[]): string | null {
  for (const value of values) {
    if (typeof value === 'string' && value.length > 0) return value;
  }
  return null;
}

/** Halve the Part 4 untrusted detail, then null it (supplementary context). */
function shrinkSecurityDetail(detail: Record<string, unknown>): Record<string, unknown> | null {
  const shrunk: Record<string, unknown> = {};
  let remaining = 0;
  for (const [key, value] of Object.entries(detail)) {
    if (Array.isArray(value)) {
      if (value.length === 0) continue;
      shrunk[key] = value.slice(0, Math.max(1, Math.floor(value.length / 2)));
      remaining += (shrunk[key] as unknown[]).length;
    } else {
      shrunk[key] = value;
      remaining += 1;
    }
  }
  return remaining > 0 ? shrunk : null;
}

/**
 * Split a Part 4 security projection (§120) along the trust boundary.
 *
 * TRUSTED: counts, ids, statuses, priorities, confidences — application
 * bookkeeping the target cannot control.
 * UNTRUSTED: signal summaries, canonical paths, mutation values and
 * rationales — strings derived from target-controlled data (§115/§116).
 */
function splitProjection(
  projection: SecurityProjection,
): { trusted_summary: Record<string, unknown>; untrusted_detail: Record<string, unknown> } {
  return {
    trusted_summary: {
      endpoint_count: projection.attack_surface.endpoint_count,
      resource_family_count: projection.attack_surface.resource_family_count,
      identity_count: projection.attack_surface.identity_count,
      workflow_count: projection.attack_surface.workflow_count,
      parameter_count: projection.attack_surface.parameter_count,
      object_count: projection.attack_surface.object_count,
      top_endpoints: projection.attack_surface.top_endpoints.map((endpoint) => ({
        id: endpoint.id,
        method_summary: endpoint.method_summary,
        status: endpoint.status,
        priority: endpoint.priority,
      })),
      active_hypotheses: projection.active_hypotheses.map((hypothesis) => ({
        id: hypothesis.id,
        confidence: hypothesis.confidence,
      })),
      recommended_tests: projection.recommended_tests.map((test) => ({
        hypothesis_id: test.hypothesis_id,
        test_type: test.test_type,
        endpoint_id: test.endpoint_id,
        baseline_identity: test.baseline_identity,
        candidate_identity: test.candidate_identity,
        mutation_category: test.mutation_category,
        expected_information_gain: test.expected_information_gain,
        estimated_cost: test.estimated_cost,
        priority: test.priority,
        fingerprint: test.fingerprint,
        preconditions: test.preconditions,
      })),
    },
    untrusted_detail: {
      interesting: projection.interesting,
      top_endpoint_paths: projection.attack_surface.top_endpoints.map((endpoint) => ({
        id: endpoint.id,
        canonical_path: endpoint.canonical_path,
      })),
      hypothesis_statements: projection.active_hypotheses,
      recommended_test_mutations: projection.recommended_tests.map((test) => ({
        fingerprint: test.fingerprint,
        base_request_id: test.base_request_id,
        mutations: test.mutations,
        rationale: test.rationale,
      })),
    },
  };
}

function firstStringFromObservations(
  observations: Array<{ metadata: Record<string, unknown> }>,
  key: string,
): string | null {
  for (const obs of observations) {
    const value = obs.metadata?.[key];
    if (typeof value === 'string' && value.length > 0) return value;
  }
  return null;
}

function stripToIds(item: Record<string, unknown>): Record<string, unknown> {
  return { id: item.id };
}
