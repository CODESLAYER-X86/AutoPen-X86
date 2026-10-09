/**
 * Part 4 tool factories — security reasoning tools for workers (spec §80,
 * §118, §72).
 *
 * These tools expose the DETERMINISTIC reasoning engine to tactical workers:
 *  - reasoning.query        — focused attack-surface projection (§80)
 *  - differential.compare   — semantic response comparison of two recorded
 *                             requests (§25, §118)
 *  - verification.evaluate  — skeptical verification of a hypothesis (§72)
 *
 * All three operate on RECORDED engagement data only — no network capability,
 * no mutation. Engagement ownership is enforced structurally: the gateway's
 * execution context engagement id is authoritative; any engagement_id in the
 * input must match it or the tool refuses (cross-engagement reads blocked).
 */
import { z } from 'zod';
import { AuthorizationError, generateId, isPlatformError, type RiskLevel, type ToolCapability } from '@aegis/shared';
import type { ToolDefinition, ToolExecutionContext } from '@aegis/tools';
import {
  ReasoningQueryInputSchema,
  DifferentialCompareInputSchema,
  VerificationEvaluateInputSchema,
} from '@aegis/contracts';

export const PART4_TOOL_CONFIGURATION_VERSION = 'part4-0.4.0';

/** Structural seam: satisfied by SecurityReasoningEngine (services/reasoning). */
export interface ReasoningToolDeps {
  reasoning: {
    query(input: {
      engagementId: string;
      endpointId?: string | null;
      hypothesisId?: string | null;
      signalType?: string | null;
    }): Promise<unknown>;
    compareDifferential(input: {
      engagementId: string;
      baselineRequestId: string;
      candidateRequestId: string;
      hypothesisId?: string | null;
      testId?: string | null;
    }): Promise<{ recordId: string; summary: unknown }>;
    evaluateWithBridge(input: {
      engagementId: string;
      hypothesisId: string;
    }): Promise<unknown>;
  };
  repos: {
    toolExecutions: {
      insert(input: {
        id: string;
        engagementId: string;
        taskId: string | null;
        identityId: string | null;
        toolName: string;
        toolVersion: string;
        configurationVersion: string;
        correlationId: string;
        status: 'SUCCEEDED' | 'FAILED';
        inputRedacted: unknown;
        outputSummary: Record<string, unknown>;
        error: unknown;
        durationMs: number;
        deadlineMs: number;
      }): Promise<unknown>;
    };
  };
  eventBus: {
    publish(event: import('@aegis/contracts').PlatformEvent): Promise<void>;
  };
}

/** The authoritative engagement for tool execution (never trust input). */
function requireEngagement(toolName: string, input: { engagement_id?: string }, ctx: ToolExecutionContext): string {
  if (!ctx.engagementId) {
    throw new AuthorizationError(
      `Tool '${toolName}' requires an engagement context`,
      'TOOL_ENGAGEMENT_REQUIRED',
    );
  }
  if (typeof input.engagement_id === 'string' && input.engagement_id !== ctx.engagementId) {
    // Cross-engagement access attempt (scope bypass, spec §132).
    throw new AuthorizationError(
      `Tool '${toolName}' was invoked for a different engagement than its execution context`,
      'TOOL_ENGAGEMENT_MISMATCH',
    );
  }
  return ctx.engagementId;
}

async function withExecutionLog(
  deps: ReasoningToolDeps,
  toolName: string,
  toolVersion: string,
  ctx: ToolExecutionContext,
  input: unknown,
  fn: () => Promise<{ output: unknown; summary: Record<string, unknown> }>,
): Promise<unknown> {
  const startedAt = Date.now();
  const correlationId = generateId('TEX');
  let status: 'SUCCEEDED' | 'FAILED' = 'SUCCEEDED';
  let summary: Record<string, unknown> = {};
  try {
    const outcome = await fn();
    summary = outcome.summary;
    return outcome.output;
  } catch (err) {
    status = 'FAILED';
    throw err;
  } finally {
    const durationMs = Date.now() - startedAt;
    try {
      await deps.repos.toolExecutions.insert({
        id: generateId('TEX'),
        engagementId: ctx.engagementId ?? 'unknown',
        taskId: null,
        identityId: ctx.identityId ?? null,
        toolName,
        toolVersion,
        configurationVersion: PART4_TOOL_CONFIGURATION_VERSION,
        correlationId,
        status,
        inputRedacted: input,
        outputSummary: summary,
        error: null,
        durationMs,
        deadlineMs: 15_000,
      });
      await deps.eventBus.publish({
        type: 'TOOL_EXECUTION_RECORDED',
        engagement_id: ctx.engagementId ?? 'unknown',
        task_id: null,
        trace_id: generateId('TRC'),
        actor_id: null,
        payload: { tool: toolName, version: toolVersion, status, duration_ms: durationMs, correlation_id: correlationId },
        occurred_at: new Date().toISOString(),
        dedup_key: `tool-exec:${correlationId}`,
      });
    } catch {
      // Logging must never break the tool pipeline (§112 isolation).
    }
  }
}

function tool(
  name: string,
  description: string,
  inputSchema: z.ZodTypeAny,
  outputSchema: z.ZodTypeAny,
  riskLevel: RiskLevel,
  capabilities: ToolCapability[],
  execute: (input: never, ctx: ToolExecutionContext) => Promise<unknown>,
): ToolDefinition {
  return {
    name,
    version: '1.0.0',
    description,
    inputSchema,
    outputSchema,
    riskLevel,
    capabilities,
    implemented: true,
    // Read-only analysis over recorded data: no scope/network semantics.
    requiresScope: false,
    execute,
  };
}

export function createPart4Tools(deps: ReasoningToolDeps): ToolDefinition[] {
  // §80: focused attack-surface query — bounded, structured projection for
  // workers. Everything returned is derived state, labeled untrusted upstream.
  const reasoningQuery = tool(
    'reasoning.query',
    'Queries the deterministic security reasoning engine for a focused attack-surface view: endpoints, parameters, authorization matrix cells, signals, object candidates and recent differentials for this engagement (optionally focused on one endpoint/hypothesis/signal type).',
    ReasoningQueryInputSchema,
    z.object({
      reasoning_output: z.unknown(),
    }),
    'LOW',
    ['READ_ONLY'],
    async (rawInput: never, ctx: ToolExecutionContext) => {
      const input = ReasoningQueryInputSchema.parse(rawInput);
      const engagementId = requireEngagement('reasoning.query', input, ctx);
      return withExecutionLog(deps, 'reasoning.query', '1.0.0', ctx, input, async () => {
        const output = await deps.reasoning.query({
          engagementId,
          endpointId: input.endpoint_id,
          hypothesisId: input.hypothesis_id,
          signalType: input.signal_type,
        });
        return { output: { reasoning_output: output }, summary: { focused_on: input.endpoint_id ?? 'all' } };
      });
    },
  );

  // §25/§118: differential comparison of two RECORDED exchanges.
  const differentialCompare = tool(
    'differential.compare',
    'Semantically compares two recorded request/response exchanges (status, headers, JSON schema, values, similarity, volatile fields) and persists the differential result. Records must belong to this engagement. Differences are signals, never conclusions.',
    DifferentialCompareInputSchema,
    z.object({
      differential_id: z.string(),
      summary: z.record(z.string(), z.unknown()),
    }),
    'LOW',
    ['READ_ONLY'],
    async (rawInput: never, ctx: ToolExecutionContext) => {
      const input = DifferentialCompareInputSchema.parse(rawInput);
      const engagementId = requireEngagement('differential.compare', input, ctx);
      return withExecutionLog(deps, 'differential.compare', '1.0.0', ctx, input, async () => {
        const result = await deps.reasoning.compareDifferential({
          engagementId,
          baselineRequestId: input.baseline_request_id,
          candidateRequestId: input.candidate_request_id,
          hypothesisId: input.hypothesis_id,
          testId: input.test_id,
        });
        const summary = result.summary as {
          status_changed: boolean;
          schema_changed: boolean;
          body_similarity: number;
        };
        return {
          output: { differential_id: result.recordId, summary },
          summary: {
            status_changed: summary.status_changed,
            schema_changed: summary.schema_changed,
            body_similarity: summary.body_similarity,
          },
        };
      });
    },
  );

  // §72: skeptical verification of a hypothesis against recorded evidence.
  const verificationEvaluate = tool(
    'verification.evaluate',
    'Runs the skeptical verification engine over a hypothesis: evaluates alternative explanations (public resource, caching, shared access, non-reproduction) against the authorization matrix and differential records, persists the verification with its checklist, and returns the verdict.',
    VerificationEvaluateInputSchema,
    z.object({
      verification: z.unknown(),
      outcome: z.unknown(),
    }),
    'LOW',
    ['READ_ONLY'],
    async (rawInput: never, ctx: ToolExecutionContext) => {
      const input = VerificationEvaluateInputSchema.parse(rawInput);
      const engagementId = requireEngagement('verification.evaluate', input, ctx);
      return withExecutionLog(deps, 'verification.evaluate', '1.0.0', ctx, input, async () => {
        const output = (await deps.reasoning.evaluateWithBridge({
          engagementId,
          hypothesisId: input.hypothesis_id,
        })) as Record<string, unknown>;
        const outcome = (output['outcome'] ?? {}) as Record<string, unknown>;
        return {
          output,
          summary: { status: outcome['status'], kind: outcome['kind'] },
        };
      });
    },
  );

  void isPlatformError; // reserved for richer error summary in later parts
  return [reasoningQuery, differentialCompare, verificationEvaluate];
}
