import { describe, expect, it } from 'vitest';
import { AgentPolicy, AgentPolicy as Policy } from '@aegis/agent';
import { z } from 'zod';
import type {
  EngagementRecord,
  EngagementUsageRecord,
  EngagementBudgetRecord,
  ScopeRecord,
} from '@aegis/database';

function engagement(overrides: Partial<EngagementRecord> = {}): EngagementRecord {
  return {
    id: 'ENG_TEST',
    project_id: 'PRJ_TEST',
    name: 'e',
    mode: 'PENTEST',
    status: 'RUNNING',
    description: '',
    started_at: new Date().toISOString(),
    completed_at: null,
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString(),
    ...overrides,
  };
}

function usage(overrides: Partial<EngagementUsageRecord> = {}): EngagementUsageRecord {
  return {
    engagement_id: 'ENG_TEST',
    network_requests: 0,
    concurrent_requests: 0,
    browser_contexts: 0,
    model_calls: 0,
    input_tokens: 0,
    output_tokens: 0,
    storage_bytes: 0,
    tool_calls: 0,
    updated_at: new Date().toISOString(),
    ...overrides,
  };
}

function budget(overrides: Partial<EngagementBudgetRecord> = {}): EngagementBudgetRecord {
  return {
    id: 'BGT_TEST',
    engagement_id: 'ENG_TEST',
    max_duration_seconds: null,
    max_network_requests: null,
    max_concurrent_requests: null,
    max_browser_contexts: null,
    max_model_calls: null,
    max_model_tokens: null,
    max_storage_bytes: null,
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString(),
    ...overrides,
  };
}

function scope(overrides: Partial<ScopeRecord> = {}): ScopeRecord {
  return {
    id: 'SCP_TEST',
    engagement_id: 'ENG_TEST',
    allowed_hosts: ['app.internal'],
    allowed_domains: [],
    allowed_ports: [8080],
    allowed_schemes: ['http'],
    excluded_hosts: [],
    excluded_paths: [],
    rate_limit: null,
    concurrency_limit: null,
    destructive_actions_allowed: false,
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString(),
    ...overrides,
  };
}

const tool = (overrides: {
  riskLevel?: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  capabilities?: string[];
}) =>
  ({
    name: 'test.tool',
    version: '1.0.0',
    description: 'test tool',
    inputSchema: z.object({}),
    outputSchema: z.object({}),
    riskLevel: overrides.riskLevel ?? 'LOW',
    capabilities: (overrides.capabilities ?? ['READ_ONLY']) as never,
    requiresScope: false,
    implemented: true,
    execute: async () => ({}),
  }) as never;

describe('agent policy (spec Part 2 §67-§68)', () => {
  const policy = new AgentPolicy();

  it('DENIES tasks when the engagement is not RUNNING', () => {
    const decision = policy.evaluateTask(
      { engagement: engagement({ status: 'PAUSED' }), scope: scope(), usage: usage(), budget: budget() },
      { type: 'RECON', worker_type: 'HTTP_WORKER', allowed_tools: [] },
    );
    expect(decision.outcome).toBe('DENY');
    expect(decision.rule).toBe('engagement_not_running');
  });

  it('DENIES tasks when resource budgets are exhausted (§50/§66)', () => {
    const cases: Array<[Partial<EngagementBudgetRecord>, Partial<EngagementUsageRecord>, string]> = [
      [{ max_model_calls: 10 }, { model_calls: 10 }, 'budget_model_calls_exhausted'],
      [{ max_model_tokens: 100 }, { input_tokens: 60, output_tokens: 40 }, 'budget_model_tokens_exhausted'],
      [{ max_network_requests: 5 }, { network_requests: 5 }, 'budget_network_exhausted'],
      [{ max_storage_bytes: 1000 }, { storage_bytes: 1000 }, 'budget_storage_exhausted'],
    ];
    for (const [budgetPatch, usagePatch, rule] of cases) {
      const decision = policy.evaluateTask(
        { engagement: engagement(), scope: scope(), usage: usage(usagePatch), budget: budget(budgetPatch) },
        { type: 'RECON', worker_type: 'HTTP_WORKER', allowed_tools: [] },
      );
      expect(decision.outcome).toBe('DENY');
      expect(decision.rule).toBe(rule);
    }
  });

  it('DENIES network tools when no scope is configured', () => {
    const decision = policy.evaluateToolInvocation(
      { engagement: engagement(), scope: null, usage: usage(), budget: budget() },
      tool({ capabilities: ['NETWORK', 'READ_ONLY'] }),
      { identityPresent: false },
    );
    expect(decision.outcome).toBe('DENY');
    expect(decision.rule).toBe('network_without_scope');
  });

  it('REQUIRES USER APPROVAL for CRITICAL risk tools (§68)', () => {
    const decision = policy.evaluateToolInvocation(
      { engagement: engagement(), scope: scope(), usage: usage(), budget: budget() },
      tool({ riskLevel: 'CRITICAL' }),
      { identityPresent: false },
    );
    expect(decision.outcome).toBe('REQUIRE_USER_APPROVAL');
    expect(decision.rule).toBe('risk_critical');
  });

  it('REQUIRES USER APPROVAL for destructive tools without engagement permission', () => {
    const decision = policy.evaluateToolInvocation(
      { engagement: engagement(), scope: scope(), usage: usage(), budget: budget() },
      tool({ riskLevel: 'HIGH', capabilities: ['DESTRUCTIVE'] }),
      { identityPresent: false },
    );
    expect(decision.outcome).toBe('REQUIRE_USER_APPROVAL');
    expect(decision.rule).toBe('destructive_not_permitted');
  });

  it('allows destructive tools when the engagement explicitly permits them', () => {
    const decision = policy.evaluateToolInvocation(
      {
        engagement: engagement(),
        scope: scope({ destructive_actions_allowed: true }),
        usage: usage(),
        budget: budget(),
      },
      tool({ riskLevel: 'HIGH', capabilities: ['DESTRUCTIVE'] }),
      { identityPresent: false },
    );
    expect(decision.outcome).toBe('ALLOW');
  });

  it('DENIES authenticated tools when no identity is bound', () => {
    const decision = policy.evaluateToolInvocation(
      { engagement: engagement(), scope: scope(), usage: usage(), budget: budget() },
      tool({ capabilities: ['AUTHENTICATED'] }),
      { identityPresent: false },
    );
    expect(decision.outcome).toBe('DENY');
    expect(decision.rule).toBe('identity_required');
  });

  it('ALLOWs normal in-policy operations', () => {
    const decision = policy.evaluateToolInvocation(
      { engagement: engagement(), scope: scope(), usage: usage(), budget: budget() },
      tool({}),
      { identityPresent: false },
    );
    expect(decision.outcome).toBe('ALLOW');
  });

  it('projects scope rules for the gateway deterministically', () => {
    const rules = AgentPolicy.scopeRules(scope());
    expect(rules?.allowed_hosts).toEqual(['app.internal']);
    expect(rules?.destructive_actions_allowed).toBe(false);
    expect(AgentPolicy.scopeRules(null)).toBeNull();
    expect(Policy.riskRank('CRITICAL')).toBeGreaterThan(Policy.riskRank('LOW'));
  });
});
