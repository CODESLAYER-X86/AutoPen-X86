/**
 * Tactical worker runtime (spec Part 2 §11-§17, §36, §43-§44, §60-§62).
 *
 * Bounded execution loop for ONE compact task packet:
 *   render trust-separated prompt -> tactical model -> validated turn
 *   -> (TOOL_CALL: policy-gated gateway execution, result fed back as DATA)
 *   -> (FINAL: schema-validated structured result)
 *
 * Runtime-enforced limits (§36): max tool calls, max duration, max turns.
 * Workers cannot raise their own limits. All failures are structured; a
 * failing worker never crashes the engagement (§43).
 */
import type { ModelProvider, ModelMessage } from '@aegis/model-runtime';
import { generateId, isPlatformError } from '@aegis/shared';
import { validateWorkerTurn, validateWorkerOutput, type WorkerTurn } from '@aegis/contracts';
import type { Repositories } from '@aegis/database';
import type { EventBus } from '@aegis/events';
import { withRetries } from './retry.js';
import {
  buildWorkerPrompt,
  buildToolResultMessage,
  buildBudgetExceededMessage,
  buildInvalidTurnMessage,
} from './prompts.js';
import type {
  WorkerExecutionContext,
  WorkerResult,
  WorkerRuntime,
  WorkerTaskPacket,
  WorkerUsage,
} from './types.js';

export interface WorkerRuntimeDeps {
  provider: ModelProvider;
  repos: Repositories;
  eventBus: EventBus;
  /** Optional tool metadata registry for prompt-time descriptions. */
  toolRegistry?: {
    get(name: string): { description: string; implemented: boolean } | null;
  };
  options?: {
    maxTurns?: number;
    maxInvalidTurns?: number;
    retryAttempts?: number;
    maxOutputTokens?: number;
  };
}

const DEFAULTS = {
  maxTurns: 24,
  maxInvalidTurns: 2,
  retryAttempts: 2,
  maxOutputTokens: 2_048,
};

/** JSON Schema hint for worker turns (flattened; zod remains the enforcer). */
const WORKER_TURN_JSON_SCHEMA = {
  type: 'object',
  required: ['type'],
  properties: {
    type: { type: 'string', enum: ['TOOL_CALL', 'FINAL'] },
    tool: { type: 'string' },
    input: { type: 'object' },
    reason: { type: 'string', maxLength: 1000 },
    result: { type: 'object' },
  },
} as const;

export class TacticalWorkerRuntime implements WorkerRuntime {
  private readonly opts: typeof DEFAULTS;
  private readonly toolRegistry: WorkerRuntimeDeps['toolRegistry'] | undefined;

  constructor(private readonly deps: WorkerRuntimeDeps) {
    this.opts = { ...DEFAULTS, ...deps.options };
    this.toolRegistry = deps.toolRegistry ?? undefined;
  }

  async runTask(packet: WorkerTaskPacket, ctx: WorkerExecutionContext): Promise<WorkerResult> {
    const startedAt = Date.now();
    const usage: WorkerUsage = {
      inputTokens: 0,
      outputTokens: 0,
      toolCalls: 0,
      networkRequests: 0,
      durationMs: 0,
    };

    const failureResult = (
      failure: { code: string; message: string; status: WorkerResult['status'] },
      attemptId: string,
    ): WorkerResult => ({
      task_id: packet.task_id,
      attempt_id: attemptId,
      status: failure.status,
      observations: [],
      evidence_ids: [],
      hypothesis_updates: [],
      usage: { ...usage, durationMs: Date.now() - startedAt },
      error: { code: failure.code, message: failure.message },
    });

    // 1. Attempt record (WorkerRun, spec §2) — attempt number from scheduler.
    const attempt = await this.deps.repos.taskAttempts.create({
      taskId: packet.task_id,
      engagementId: packet.engagement_id,
      attempt: ctx.attemptNumber,
      workerType: safeWorkerType(packet.worker_type),
      workerModel: this.deps.provider.model,
    });

    await this.deps.eventBus.publish({
      type: 'WORKER_STARTED',
      engagement_id: packet.engagement_id,
      task_id: packet.task_id,
      trace_id: generateId('TRC'),
      actor_id: null,
      payload: {
        attempt_id: attempt.id,
        worker_type: packet.worker_type,
        attempt: ctx.attemptNumber,
        type: packet.type,
      },
      occurred_at: new Date().toISOString(),
      dedup_key: `worker-started:${attempt.id}`,
    });

    // 2. Prompt with trust separation (§60-§62).
    const toolDescriptions = packet.allowed_tools
      .map((name) => {
        const tool = this.toolRegistry?.get(name);
        return tool
          ? `- ${name}: ${tool.description}${tool.implemented ? '' : ' [NOT IMPLEMENTED yet — calling it returns a structured error]'}`
          : `- ${name}`;
      })
      .join('\n');
    const prompt = buildWorkerPrompt(packet, toolDescriptions || '(no tools available for this task)');

    await this.deps.repos.agentMessages.create({
      engagementId: packet.engagement_id,
      runId: packet.run_id,
      taskId: packet.task_id,
      channel: 'WORKER',
      direction: 'OUTBOUND',
      role: 'user',
      content: prompt.user,
      untrustedBytes: prompt.untrustedBytes,
      metadata: { worker_type: packet.worker_type, system_chars: prompt.system.length },
    });

    // 3. Bounded conversation loop.
    const messages: ModelMessage[] = [{ role: 'user', content: prompt.user }];
    let invalidTurns = 0;
    let toolCalls = 0;

    for (let turn = 0; turn < this.opts.maxTurns; turn += 1) {
      const elapsed = Date.now() - startedAt;
      if (elapsed > packet.constraints.max_duration_seconds * 1000) {
        return this.finishAttempt(attempt.id, packet, ctx, usage, startedAt, failureResult(
          {
            code: 'WORKER_DURATION_EXCEEDED',
            message: `Worker exceeded its ${packet.constraints.max_duration_seconds}s duration limit`,
            status: 'PARTIAL',
          },
          attempt.id,
        ));
      }

      // Model call with bounded retries for transient errors (§44).
      let content: string;
      try {
        const result = await withRetries(
          () =>
            this.deps.provider.generate({
              system: prompt.system,
              messages: [...messages],
              responseJsonSchema: WORKER_TURN_JSON_SCHEMA as unknown as Record<string, unknown>,
              maxOutputTokens: this.opts.maxOutputTokens,
              temperature: 0.2,
            }),
          { maxAttempts: this.opts.retryAttempts },
        );
        content = result.content;
        const inTok = result.usage?.inputTokens ?? estimate(content.length);
        const outTok = result.usage?.outputTokens ?? estimate(content.length);
        usage.inputTokens += inTok;
        usage.outputTokens += outTok;

        await this.deps.repos.modelCalls.create({
          engagementId: packet.engagement_id,
          runId: packet.run_id,
          taskId: packet.task_id,
          decisionId: null,
          role: 'tactical',
          purpose: packet.type === 'VERIFICATION' ? 'verification' : 'worker',
          provider: result.provider,
          model: result.model,
          inputTokens: inTok,
          outputTokens: outTok,
        });
      } catch (error) {
        return this.finishAttempt(attempt.id, packet, ctx, usage, startedAt, failureResult(
          {
            code: isPlatformError(error) ? error.code : 'MODEL_REQUEST_FAILED',
            message: isPlatformError(error) ? error.message : 'Worker model call failed',
            status: 'FAILED',
          },
          attempt.id,
        ));
      }

      await this.deps.repos.agentMessages.create({
        engagementId: packet.engagement_id,
        runId: packet.run_id,
        taskId: packet.task_id,
        channel: 'WORKER',
        direction: 'INBOUND',
        role: 'assistant',
        content,
        metadata: { turn },
      });

      // Turn validation — fails closed; invalid turns get bounded feedback.
      const raw = extractJson(content);
      let turnDecision: WorkerTurn;
      try {
        if (raw === null) throw new Error('not json');
        turnDecision = validateWorkerTurn(raw);
      } catch (error) {
        invalidTurns += 1;
        const issues = issueList(error);
        if (invalidTurns > this.opts.maxInvalidTurns) {
          return this.finishAttempt(attempt.id, packet, ctx, usage, startedAt, failureResult(
            {
              code: 'WORKER_TURN_INVALID',
              message: `Worker produced ${invalidTurns} invalid turn objects; aborting`,
              status: 'FAILED',
            },
            attempt.id,
          ));
        }
        messages.push({ role: 'user', content: buildInvalidTurnMessage(issues) });
        continue;
      }

      // FINAL: validate the structured output and finish (§16).
      if (turnDecision.type === 'FINAL') {
        try {
          const output = validateWorkerOutput(turnDecision.result);
          return await this.finishAttempt(attempt.id, packet, ctx, usage, startedAt, {
            task_id: packet.task_id,
            attempt_id: attempt.id,
            status: output.status,
            observations: output.observations,
            evidence_ids: output.evidence_ids,
            hypothesis_updates: output.hypothesis_updates,
            ...(output.needs ? { needs: output.needs } : {}),
            ...(output.recommended_next_action
              ? { recommended_next_action: output.recommended_next_action }
              : {}),
            usage: { ...usage },
          });
        } catch (error) {
          return this.finishAttempt(attempt.id, packet, ctx, usage, startedAt, failureResult(
            {
              code: 'WORKER_OUTPUT_INVALID',
              message: isPlatformError(error) ? error.message : 'Worker FINAL output failed validation',
              status: 'FAILED',
            },
            attempt.id,
          ));
        }
      }

      // TOOL_CALL: the allow-list is authoritative, never the model (§35).
      if (toolCalls >= packet.constraints.max_tool_calls) {
        messages.push({
          role: 'user',
          content: buildBudgetExceededMessage(
            `tool call limit of ${packet.constraints.max_tool_calls} reached`,
          ),
        });
        continue;
      }

      if (!packet.allowed_tools.includes(turnDecision.tool)) {
        messages.push({
          role: 'user',
          content: buildToolResultMessage(
            turnDecision.tool,
            {
              code: 'TOOL_NOT_ALLOWED',
              message: `Tool '${turnDecision.tool}' is not in this task's allow-list`,
            },
            false,
          ),
        });
        continue;
      }

      // Gateway execution (policy/scope gated — the ONLY path to tools, §69).
      const toolResult = await ctx.toolGateway.execute(turnDecision.tool, turnDecision.input, {
        requestId: ctx.requestId,
        engagementId: ctx.engagementId,
        identityId: packet.identity_id ?? undefined,
        scope: ctx.scope ?? undefined,
        permissions: ctx.permissions,
      });
      toolCalls += 1;
      usage.toolCalls += 1;
      await this.deps.repos.budgets.incrementUsage(packet.engagement_id, { toolCalls: 1 });

      await this.deps.eventBus.publish({
        type: 'TOOL_INVOKED',
        engagement_id: packet.engagement_id,
        task_id: packet.task_id,
        trace_id: generateId('TRC'),
        actor_id: null,
        payload: {
          tool: turnDecision.tool,
          ok: toolResult.ok,
          duration_ms: toolResult.durationMs,
          worker: packet.worker_type,
        },
        occurred_at: new Date().toISOString(),
      });

      messages.push({
        role: 'user',
        content: buildToolResultMessage(
          turnDecision.tool,
          toolResult.ok ? toolResult.output : toolResult.error,
          toolResult.ok,
        ),
      });
    }

    // Turn budget exhausted without FINAL.
    return this.finishAttempt(attempt.id, packet, ctx, usage, startedAt, failureResult(
      {
        code: 'WORKER_TURN_BUDGET_EXCEEDED',
        message: `Worker exceeded ${this.opts.maxTurns} turns without finalizing`,
        status: 'FAILED',
      },
      attempt.id,
    ));
  }

  private async finishAttempt(
    attemptId: string,
    packet: WorkerTaskPacket,
    ctx: WorkerExecutionContext,
    usage: WorkerUsage,
    startedAt: number,
    result: WorkerResult,
  ): Promise<WorkerResult> {
    result.usage.durationMs = Date.now() - startedAt;
    await this.deps.repos.taskAttempts.finish(attemptId, {
      status: result.status,
      output: result as unknown as Record<string, unknown>,
      errorCode: result.error?.code ?? null,
      errorMessage: result.error?.message ?? null,
      toolCalls: usage.toolCalls,
      networkRequests: usage.networkRequests,
      inputTokens: usage.inputTokens,
      outputTokens: usage.outputTokens,
      durationMs: result.usage.durationMs,
    });
    await this.deps.repos.budgets.incrementUsage(packet.engagement_id, {
      inputTokens: usage.inputTokens,
      outputTokens: usage.outputTokens,
    });
    await this.deps.eventBus.publish({
      type: 'WORKER_COMPLETED',
      engagement_id: packet.engagement_id,
      task_id: packet.task_id,
      trace_id: generateId('TRC'),
      actor_id: null,
      payload: {
        attempt_id: attemptId,
        status: result.status,
        tool_calls: usage.toolCalls,
        input_tokens: usage.inputTokens,
        output_tokens: usage.outputTokens,
      },
      occurred_at: new Date().toISOString(),
      dedup_key: `worker-completed:${attemptId}`,
    });
    ctx.logger?.info('worker.completed', {
      engagement_id: packet.engagement_id,
      task_id: packet.task_id,
      status: result.status,
      tool_calls: usage.toolCalls,
    });
    return result;
  }
}

function issueList(error: unknown): Array<{ path: string; message: string }> {
  if (isPlatformError(error) && Array.isArray(error.details)) {
    return error.details as Array<{ path: string; message: string }>;
  }
  return [{ path: '$', message: 'Response was not a valid JSON turn object' }];
}

function extractJson(content: string): unknown {
  const trimmed = content.trim();
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

function estimate(chars: number): number {
  return Math.ceil(chars / 4);
}

function safeWorkerType(
  workerType: string,
): 'HTTP_WORKER' | 'BROWSER_WORKER' | 'SOURCE_WORKER' | 'ANALYSIS_WORKER' {
  const allowed = ['HTTP_WORKER', 'BROWSER_WORKER', 'SOURCE_WORKER', 'ANALYSIS_WORKER'] as const;
  return (allowed as readonly string[]).includes(workerType)
    ? (workerType as (typeof allowed)[number])
    : 'ANALYSIS_WORKER';
}
