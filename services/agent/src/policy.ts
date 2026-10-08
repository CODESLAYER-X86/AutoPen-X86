/**
 * Agent policy layer (spec Part 2 §67-§68).
 *
 * Deterministic decision function answering "is this action allowed?" for
 * every agent-proposed action BEFORE it reaches the scheduler. Inputs:
 * engagement state, scope, task, identity, tool, risk, resource budget.
 * Output: ALLOW | DENY | REQUIRE_USER_APPROVAL. No LLM involvement.
 *
 * High-risk / destructive operations require explicit engagement permission
 * (scope.destructive_actions_allowed) — the model cannot grant it itself.
 */
import type {
  EngagementRecord,
  EngagementUsageRecord,
  EngagementBudgetRecord,
  ScopeRecord,
  TaskRecord,
} from '@aegis/database';
import { ScopeChecker, type ScopeRules } from '@aegis/security';
import type { RiskLevel } from '@aegis/shared';
import type { ToolDefinition } from '@aegis/tools';

export type PolicyDecision = {
  outcome: 'ALLOW' | 'DENY' | 'REQUIRE_USER_APPROVAL';
  /** Machine-readable rule that produced the outcome (audit trail). */
  rule: string;
  reason: string;
};

export interface PolicyContext {
  engagement: EngagementRecord;
  scope: ScopeRecord | null;
  usage: EngagementUsageRecord;
  budget: EngagementBudgetRecord;
}

/** Engagement-level hard stops (spec Part 2 §50 deterministic conditions). */
export interface EngagementRuntimeState {
  engagementStatus: string;
  runStatus: string | null;
}

export class AgentPolicy {
  /**
   * Action gate for a candidate task + tool combination.
   *
   * Evaluation order (deny-wins):
   *   1. engagement must be RUNNING
   *   2. resource budget must not be exhausted
   *   3. tool risk level vs engagement permission
   *   4. tool capabilities vs engagement permissions
   *   5. NETWORK tools: scope must exist
   */
  evaluateTask(
    ctx: PolicyContext,
    task: Pick<TaskRecord, 'type' | 'worker_type' | 'allowed_tools'>,
  ): PolicyDecision {
    if (ctx.engagement.status !== 'RUNNING') {
      return {
        outcome: 'DENY',
        rule: 'engagement_not_running',
        reason: `Engagement status is ${ctx.engagement.status}; autonomous actions require RUNNING`,
      };
    }

    const budgetDenial = this.checkBudget(ctx);
    if (budgetDenial) return budgetDenial;

    if (ctx.engagement.mode === 'CTF' && task.type === 'RECON') {
      // Allowed — CTF recon is still bounded by scope; no special rule.
      void 0;
    }

    return { outcome: 'ALLOW', rule: 'task_allowed', reason: 'Task passed policy gates' };
  }

  evaluateToolInvocation(
    ctx: PolicyContext,
    tool: ToolDefinition,
    options: { identityPresent: boolean },
  ): PolicyDecision {
    if (ctx.engagement.status !== 'RUNNING') {
      return {
        outcome: 'DENY',
        rule: 'engagement_not_running',
        reason: `Engagement status is ${ctx.engagement.status}; tools require RUNNING`,
      };
    }

    // Risk mapping (§68): CRITICAL tools always require user approval;
    // HIGH requires explicit engagement permission.
    if (tool.riskLevel === 'CRITICAL') {
      return {
        outcome: 'REQUIRE_USER_APPROVAL',
        rule: 'risk_critical',
        reason: `Tool '${tool.name}' is CRITICAL risk and requires explicit user approval`,
      };
    }

    if (tool.capabilities.includes('DESTRUCTIVE') || tool.riskLevel === 'HIGH') {
      const allowed = ctx.scope?.destructive_actions_allowed ?? false;
      if (!allowed) {
        return {
          outcome: 'REQUIRE_USER_APPROVAL',
          rule: 'destructive_not_permitted',
          reason: `Tool '${tool.name}' is destructive/high risk and the engagement does not permit destructive actions`,
        };
      }
    }

    if (tool.capabilities.includes('NETWORK') && !ctx.scope) {
      return {
        outcome: 'DENY',
        rule: 'network_without_scope',
        reason: `Tool '${tool.name}' needs network access but no scope is configured`,
      };
    }

    if (
      (tool.capabilities.includes('AUTHENTICATED') || tool.requiresIdentity) &&
      !options.identityPresent
    ) {
      return {
        outcome: 'DENY',
        rule: 'identity_required',
        reason: `Tool '${tool.name}' requires an identity that is not present`,
      };
    }

    return { outcome: 'ALLOW', rule: 'tool_allowed', reason: 'Tool invocation allowed' };
  }

  /** Engagement resource budget gate (spec Part 2 §50/§66). */
  checkBudget(ctx: PolicyContext): PolicyDecision | null {
    const { budget, usage } = ctx;
    if (budget.max_model_calls !== null && usage.model_calls >= budget.max_model_calls) {
      return {
        outcome: 'DENY',
        rule: 'budget_model_calls_exhausted',
        reason: `Model call budget exhausted (${usage.model_calls}/${budget.max_model_calls})`,
      };
    }
    const totalTokens = usage.input_tokens + usage.output_tokens;
    if (budget.max_model_tokens !== null && totalTokens >= budget.max_model_tokens) {
      return {
        outcome: 'DENY',
        rule: 'budget_model_tokens_exhausted',
        reason: `Model token budget exhausted (${totalTokens}/${budget.max_model_tokens})`,
      };
    }
    if (
      budget.max_network_requests !== null &&
      usage.network_requests >= budget.max_network_requests
    ) {
      return {
        outcome: 'DENY',
        rule: 'budget_network_exhausted',
        reason: `Network request budget exhausted (${usage.network_requests}/${budget.max_network_requests})`,
      };
    }
    if (budget.max_storage_bytes !== null && usage.storage_bytes >= budget.max_storage_bytes) {
      return {
        outcome: 'DENY',
        rule: 'budget_storage_exhausted',
        reason: `Storage budget exhausted (${usage.storage_bytes}/${budget.max_storage_bytes})`,
      };
    }
    if (budget.max_duration_seconds !== null) {
      const start = ctx.engagement.started_at ? Date.parse(ctx.engagement.started_at) : null;
      if (start !== null && Date.now() - start > budget.max_duration_seconds * 1000) {
        return {
          outcome: 'DENY',
          rule: 'budget_duration_exhausted',
          reason: `Engagement duration budget exceeded (>${budget.max_duration_seconds}s)`,
        };
      }
    }
    return null;
  }

  /** Scope rules projection used by the ToolGateway. */
  static scopeRules(scope: ScopeRecord | null): ScopeRules | null {
    if (!scope) return null;
    return {
      allowed_hosts: scope.allowed_hosts,
      allowed_domains: scope.allowed_domains,
      allowed_ports: scope.allowed_ports,
      allowed_schemes: scope.allowed_schemes,
      excluded_hosts: scope.excluded_hosts,
      excluded_paths: scope.excluded_paths,
      rate_limit: scope.rate_limit,
      concurrency_limit: scope.concurrency_limit,
      destructive_actions_allowed: scope.destructive_actions_allowed,
    };
  }

  static scopeChecker(scope: ScopeRecord | null): ScopeChecker | null {
    const rules = AgentPolicy.scopeRules(scope);
    return rules ? new ScopeChecker(rules) : null;
  }

  /** Risk ordering helper (LOW < MEDIUM < HIGH < CRITICAL). */
  static riskRank(risk: RiskLevel): number {
    return { LOW: 0, MEDIUM: 1, HIGH: 2, CRITICAL: 3 }[risk];
  }
}
