/** Engagement scope resolution for tool-gateway execution contexts. */
import { AgentPolicy } from '@aegis/agent';
import type { ScopeRules } from '@aegis/security';
import type { AppContext } from '../context.js';
import { ScopeViolationError } from '@aegis/shared';

export async function scopeRulesForEngagement(
  ctx: AppContext,
  engagementId: string,
): Promise<ScopeRules | null> {
  const record = await ctx.repos.scope.findByEngagement(engagementId);
  return AgentPolicy.scopeRules(record);
}

export async function requireScopeForEngagement(
  ctx: AppContext,
  engagementId: string,
): Promise<ScopeRules> {
  const rules = await scopeRulesForEngagement(ctx, engagementId);
  if (!rules) {
    throw new ScopeViolationError(
      'Engagement has no scope configured; interaction-layer operations are refused',
      'SCOPE_NOT_CONFIGURED',
    );
  }
  return rules;
}
