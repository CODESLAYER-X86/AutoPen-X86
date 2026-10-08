/**
 * Leader runtime (spec Part 2 §4-§9, §31).
 *
 * One strategic decision cycle:
 *   build context projection -> render trust-separated prompt -> strategic
 *   model call (bounded retries, §44) -> deterministic JSON extraction ->
 *   schema validation (fails closed) -> decision validator (§10 layers).
 *
 * The leader NEVER executes tools or network operations itself (§1). Its
 * output is a structured decision, persisted with an input-state hash so
 * autonomous behaviour is reproducible (§31).
 */
import { createHash } from 'node:crypto';
import type { Logger } from '@aegis/logging';
import type { ModelProvider, GenerateResult } from '@aegis/model-runtime';
import type { AgentDecisionRecord, Repositories } from '@aegis/database';
import type { EventBus } from '@aegis/events';
import { generateId, isPlatformError } from '@aegis/shared';
import {
  type LeaderDecision,
  validateLeaderDecision,
} from '@aegis/contracts';
import { buildLeaderPrompt } from './prompts.js';
import type { ContextBuilder } from './context-builder.js';
import type { DecisionValidator, DecisionValidationInput, DecisionValidationResult } from './decision-validator.js';
import { withRetries } from './retry.js';
import { estimateTokens, type QuotaManager, type TokenBudgeter } from './quota.js';

/** Flattened JSON Schema hint sent to providers that support structured output. */
export const LEADER_DECISION_JSON_SCHEMA = {
  type: 'object',
  required: ['decision', 'reasoning_summary'],
  properties: {
    decision: {
      type: 'string',
      enum: [
        'CREATE_TASK',
        'CREATE_PARALLEL_TASKS',
        'UPDATE_HYPOTHESIS',
        'REQUEST_KNOWLEDGE',
        'REQUEST_RECON',
        'REQUEST_VERIFICATION',
        'WAIT',
        'STOP',
        'PAUSE',
      ],
    },
    reasoning_summary: { type: 'string', maxLength: 2000 },
    task: {
      type: 'object',
      properties: {
        objective: { type: 'string', maxLength: 2000 },
        task_type: {
          type: 'string',
          enum: [
            'RECON',
            'HTTP_ANALYSIS',
            'BROWSER_INVESTIGATION',
            'SOURCE_ANALYSIS',
            'AUTHORIZATION_ANALYSIS',
            'AUTHENTICATION_ANALYSIS',
            'SESSION_ANALYSIS',
            'INPUT_VALIDATION_ANALYSIS',
            'CTF_CLUE_ANALYSIS',
            'VERIFICATION',
            'KNOWLEDGE_SUMMARY',
            'GENERAL_ANALYSIS',
          ],
        },
        worker_type: {
          type: 'string',
          enum: ['HTTP_WORKER', 'BROWSER_WORKER', 'SOURCE_WORKER', 'ANALYSIS_WORKER'],
        },
        hypothesis_id: { type: 'string' },
        priority: { type: 'number' },
        expected_information_gain: { type: 'number' },
        potential_impact: { type: 'number' },
        identity_id: { type: 'string' },
        target_hint: { type: 'string', maxLength: 500 },
        depends_on: { type: 'array', items: { type: 'string' } },
        allowed_tools: { type: 'array', items: { type: 'string' } },
        inputs: { type: 'object' },
        constraints: { type: 'object' },
      },
    },
    tasks: { type: 'array', items: { type: 'object' } },
    hypothesis_id: { type: 'string' },
    change: { type: 'string' },
    confidence: { type: 'number' },
    hypothesis: { type: 'object' },
    query: { type: 'string', maxLength: 1000 },
    focus: { type: 'string', maxLength: 1000 },
    aspect: { type: 'string', maxLength: 500 },
    duration_hint_seconds: { type: 'integer' },
    objective_satisfied: { type: 'boolean' },
    summary: { type: 'string', maxLength: 4000 },
  },
} as const;

export interface LeaderRuntimeDeps {
  provider: ModelProvider;
  repos: Repositories;
  eventBus: EventBus;
  logger: Logger;
  contextBuilder: ContextBuilder;
  decisionValidator: DecisionValidator;
  quota: QuotaManager;
  tokenBudgets: TokenBudgeter;
  options?: {
    maxOutputTokens?: number;
    maxContextTokens?: number;
    retryAttempts?: number;
  };
}

export type LeaderCycleOutcome =
  | {
      ok: true;
      decision: LeaderDecision;
      decisionRecord: AgentDecisionRecord;
      usage: { inputTokens: number; outputTokens: number; durationMs: number };
    }
  | {
      ok: false;
      stage: 'MODEL' | 'SCHEMA' | 'VALIDATION';
      code: string;
      reason: string;
      details?: unknown;
      decisionRecord: AgentDecisionRecord | null;
      usage: { inputTokens: number; outputTokens: number; durationMs: number };
    };

export class LeaderRuntime {
  private readonly opts: Required<NonNullable<LeaderRuntimeDeps['options']>>;

  constructor(private readonly deps: LeaderRuntimeDeps) {
    this.opts = {
      maxOutputTokens: deps.options?.maxOutputTokens ?? 2_048,
      maxContextTokens: deps.options?.maxContextTokens ?? 24_000,
      retryAttempts: deps.options?.retryAttempts ?? 3,
    };
  }

  async decide(input: {
    engagementId: string;
    runId: string;
    cycle: number;
    runStatus: string;
  }): Promise<LeaderCycleOutcome> {
    const { repos } = this.deps;
    const startedAt = Date.now();
    const emptyUsage = { inputTokens: 0, outputTokens: 0, durationMs: 0 };

    // 1. Context projection (§6-§8) + live resource state.
    let context = await this.deps.contextBuilder.build({
      engagementId: input.engagementId,
      maxContextTokens: this.opts.maxContextTokens,
    });
    const usage = await repos.budgets.getUsage(input.engagementId);
    context = this.deps.contextBuilder.attachResourceState(context, {
      quota: this.deps.quota.snapshot(),
      tokenBudgets: this.deps.tokenBudgets.usage(),
      usage: usage as unknown as Record<string, unknown>,
    });

    const pendingTasks = context.trusted.pending_tasks.length;
    const inputStateHash = hashContext(context);

    // 2. Prompt with trust separation (§60-§62).
    const prompt = buildLeaderPrompt(
      context.trusted as unknown as Record<string, unknown>,
      context.untrusted as unknown as Record<string, unknown>,
      { cycle: input.cycle, pendingTasks },
    );

    await repos.agentMessages.create({
      engagementId: input.engagementId,
      runId: input.runId,
      taskId: null,
      channel: 'LEADER',
      direction: 'OUTBOUND',
      role: 'user',
      content: prompt.user,
      untrustedBytes: prompt.untrustedBytes,
      metadata: { cycle: input.cycle, system_chars: prompt.system.length },
    });

    // 3. Model call with bounded retries (§44).
    let result: GenerateResult;
    try {
      result = await withRetries(
        () =>
          this.deps.provider.generate({
            system: prompt.system,
            messages: [{ role: 'user', content: prompt.user }],
            responseJsonSchema: LEADER_DECISION_JSON_SCHEMA as unknown as Record<string, unknown>,
            maxOutputTokens: this.opts.maxOutputTokens,
            temperature: 0.2,
          }),
        { maxAttempts: this.opts.retryAttempts },
      );
    } catch (error) {
      const code = isPlatformError(error) ? error.code : 'MODEL_REQUEST_FAILED';
      const reason = isPlatformError(error) ? error.message : 'Model request failed';
      this.deps.logger.warn('leader.model_failed', {
        engagement_id: input.engagementId,
        run_id: input.runId,
        cycle: input.cycle,
        code,
      });
      await this.recordFailedModelCall(input, code, Date.now() - startedAt);
      return {
        ok: false,
        stage: 'MODEL',
        code,
        reason,
        decisionRecord: null,
        usage: emptyUsage,
      };
    }

    const callUsage = {
      inputTokens: result.usage?.inputTokens ?? estimateTokens(prompt.user),
      outputTokens: result.usage?.outputTokens ?? estimateTokens(result.content),
      durationMs: Date.now() - startedAt,
    };

    await repos.agentMessages.create({
      engagementId: input.engagementId,
      runId: input.runId,
      taskId: null,
      channel: 'LEADER',
      direction: 'INBOUND',
      role: 'assistant',
      content: result.content,
      metadata: { cycle: input.cycle, provider: result.provider, model: result.model },
      inputTokens: callUsage.inputTokens,
      outputTokens: callUsage.outputTokens,
    });
    await repos.modelCalls.create({
      engagementId: input.engagementId,
      runId: input.runId,
      taskId: null,
      decisionId: null,
      role: 'strategic',
      purpose: 'leader',
      provider: result.provider,
      model: result.model,
      inputTokens: callUsage.inputTokens,
      outputTokens: callUsage.outputTokens,
      durationMs: callUsage.durationMs,
    });
    this.deps.quota.recordUsage(callUsage.inputTokens, callUsage.outputTokens);
    this.deps.tokenBudgets.record('leader', callUsage.inputTokens, callUsage.outputTokens);
    await repos.budgets.incrementUsage(input.engagementId, {
      modelCalls: 1,
      inputTokens: callUsage.inputTokens,
      outputTokens: callUsage.outputTokens,
    });

    // 4. Deterministic JSON extraction (models sometimes wrap in fences).
    const rawDecision = extractJson(result.content);
    if (rawDecision === null) {
      return this.rejectDecision(input, {
        cycle: input.cycle,
        inputStateHash,
        rawContent: result.content,
        code: 'LEADER_DECISION_NOT_JSON',
        reason: 'Leader model output is not parseable JSON',
        details: { content_prefix: result.content.slice(0, 300) },
        usage: callUsage,
        stage: 'SCHEMA',
      });
    }

    // 5. Schema validation — fails closed (§9/§10 layer 1).
    let decision: LeaderDecision;
    try {
      decision = validateLeaderDecision(rawDecision);
    } catch (error) {
      return this.rejectDecision(input, {
        cycle: input.cycle,
        inputStateHash,
        rawContent: result.content,
        code: isPlatformError(error) ? error.code : 'LEADER_DECISION_INVALID',
        reason: isPlatformError(error) ? error.message : 'Schema validation failed',
        details: isPlatformError(error) ? error.details : undefined,
        usage: callUsage,
        stage: 'SCHEMA',
      });
    }

    // 6. Persist the decision record BEFORE semantic validation (audit first).
    const decisionRecord = await repos.agentDecisions.create({
      runId: input.runId,
      engagementId: input.engagementId,
      cycle: input.cycle,
      inputStateHash,
      decisionType: decision.decision,
      reasoningSummary: decision.reasoning_summary,
      payload: decision as unknown as Record<string, unknown>,
      inputTokens: callUsage.inputTokens,
      outputTokens: callUsage.outputTokens,
      durationMs: callUsage.durationMs,
    });

    // 7. Decision validation layers 2-7 (§10).
    const [engagement, scope, budget] = await Promise.all([
      repos.engagements.findById(input.engagementId),
      repos.scope.findByEngagement(input.engagementId),
      repos.budgets.getOrDefault(input.engagementId, {}),
    ]);
    if (!engagement || !budget) {
      return {
        ok: false,
        stage: 'VALIDATION',
        code: 'ENGAGEMENT_NOT_FOUND',
        reason: 'Engagement disappeared during decision cycle',
        decisionRecord,
        usage: callUsage,
      };
    }

    const validationInput: DecisionValidationInput = {
      decision,
      engagement,
      scope,
      usage: await repos.budgets.getUsage(input.engagementId),
      budget,
      quota: this.deps.quota,
      tokenBudgets: this.deps.tokenBudgets,
    };
    const validation: DecisionValidationResult = await this.deps.decisionValidator.validate(
      validationInput,
    );

    if (!validation.ok) {
      const updated = await repos.agentDecisions.markRejected(
        decisionRecord.id,
        validation.rejection.code,
        validation.rejection as unknown as Record<string, unknown>,
      );
      await this.deps.eventBus.publish({
        type: 'LEADER_DECISION_REJECTED',
        engagement_id: input.engagementId,
        task_id: null,
        trace_id: generateId('TRC'),
        actor_id: null,
        payload: {
          run_id: input.runId,
          cycle: input.cycle,
          decision: decision.decision,
          code: validation.rejection.code,
          layer: validation.rejection.layer,
          reason: validation.rejection.reason,
        },
        occurred_at: new Date().toISOString(),
      });
      // Duplicate-test rejections get their own event (spec §59) so the
      // audit trail explicitly shows refused duplicate work.
      if (validation.rejection.code === 'TEST_DUPLICATE') {
        await this.deps.eventBus.publish({
          type: 'TEST_DUPLICATE',
          engagement_id: input.engagementId,
          task_id: null,
          trace_id: generateId('TRC'),
          actor_id: null,
          payload: {
            run_id: input.runId,
            cycle: input.cycle,
            ...(validation.rejection.details as { fingerprint?: string }),
          },
          occurred_at: new Date().toISOString(),
        });
      }
      return {
        ok: false,
        stage: 'VALIDATION',
        code: validation.rejection.code,
        reason: validation.rejection.reason,
        details: validation.rejection.details,
        decisionRecord: updated ?? decisionRecord,
        usage: callUsage,
      };
    }

    await repos.agentDecisions.markValid(decisionRecord.id);
    await this.deps.eventBus.publish({
      type: 'LEADER_DECISION_RECORDED',
      engagement_id: input.engagementId,
      task_id: null,
      trace_id: generateId('TRC'),
      actor_id: null,
      payload: {
        run_id: input.runId,
        cycle: input.cycle,
        decision: decision.decision,
      },
      occurred_at: new Date().toISOString(),
      dedup_key: `leader-decision:${decisionRecord.id}`,
    });

    return { ok: true, decision, decisionRecord, usage: callUsage };
  }

  private async rejectDecision(
    input: { engagementId: string; runId: string; cycle: number },
    args: {
      cycle: number;
      inputStateHash: string;
      rawContent: string;
      code: string;
      reason: string;
      details?: unknown;
      usage: { inputTokens: number; outputTokens: number; durationMs: number };
      stage: 'MODEL' | 'SCHEMA' | 'VALIDATION';
    },
  ): Promise<LeaderCycleOutcome> {
    const record = await this.deps.repos.agentDecisions.create({
      runId: input.runId,
      engagementId: input.engagementId,
      cycle: args.cycle,
      inputStateHash: args.inputStateHash,
      decisionType: 'WAIT', // placeholder; marked REJECTED below
      reasoningSummary: args.reason.slice(0, 2000),
      payload: { raw_content_prefix: args.rawContent.slice(0, 500) },
      inputTokens: args.usage.inputTokens,
      outputTokens: args.usage.outputTokens,
      durationMs: args.usage.durationMs,
    });
    const rejected = await this.deps.repos.agentDecisions.markRejected(
      record.id,
      args.code,
      { reason: args.reason, ...(args.details ? { details: args.details } : {}) },
    );
    await this.deps.eventBus.publish({
      type: 'LEADER_DECISION_REJECTED',
      engagement_id: input.engagementId,
      task_id: null,
      trace_id: generateId('TRC'),
      actor_id: null,
      payload: {
        run_id: input.runId,
        cycle: args.cycle,
        code: args.code,
        reason: args.reason,
      },
      occurred_at: new Date().toISOString(),
    });
    return {
      ok: false,
      stage: args.stage as 'MODEL' | 'SCHEMA' | 'VALIDATION',
      code: args.code,
      reason: args.reason,
      details: args.details,
      decisionRecord: rejected,
      usage: args.usage,
    };
  }

  private async recordFailedModelCall(
    input: { engagementId: string; runId: string },
    code: string,
    durationMs: number,
  ): Promise<void> {
    await this.deps.repos.modelCalls
      .create({
        engagementId: input.engagementId,
        runId: input.runId,
        taskId: null,
        decisionId: null,
        role: 'strategic',
        purpose: 'leader',
        provider: this.deps.provider.id,
        model: this.deps.provider.model,
        status: 'FAILED',
        errorCode: code,
        durationMs,
      })
      .catch(() => undefined);
  }
}

/** Deterministic extraction of the first JSON object in model output. */
export function extractJson(content: string): unknown {
  const trimmed = content.trim();
  // Strip markdown fences when present.
  const fenceMatch = /^```(?:json)?\s*([\s\S]*?)\s*```$/.exec(trimmed);
  const candidate = fenceMatch ? fenceMatch[1]! : trimmed;
  const start = candidate.indexOf('{');
  const end = candidate.lastIndexOf('}');
  if (start === -1 || end === -1 || end <= start) return null;
  try {
    return JSON.parse(candidate.slice(start, end + 1));
  } catch {
    return null;
  }
}

function hashContext(context: unknown): string {
  return createHash('sha256').update(JSON.stringify(context), 'utf8').digest('hex');
}
