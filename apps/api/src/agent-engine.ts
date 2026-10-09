/**
 * Agent engine registry (API composition layer, Part 2).
 *
 * One AgentLoopEngine per engagement, held in-process. Implements the
 * AgentLauncher interface consumed by the orchestrator, and exposes run
 * control + human overrides for the API routes.
 *
 * Restart semantics (spec Part 2 §63): engines are stateless across
 * restarts — all state lives in the database. `ensureEngine` re-attaches to
 * an existing active run and resumes the loop (crash recovery happens inside
 * `AgentLoopEngine.start`/`attach`).
 */
import type { AppConfig } from '@aegis/config';
import type { Logger } from '@aegis/logging';
import type { Repositories } from '@aegis/database';
import type { EventBus } from '@aegis/events';
import type { ModelRouter } from '@aegis/model-runtime';
import type { ToolGateway, ToolRegistry } from '@aegis/tools';
import type { SecurityContextProvider } from '@aegis/contracts';
import type { AgentLauncher } from '@aegis/orchestrator';
import {
  AgentLoopEngine,
  QuotaManager,
  TokenBudgeter,
  AgentMetricsCollector,
} from '@aegis/agent';
import { TacticalWorkerRuntime } from '@aegis/worker-runtime';
import type { EngagementRecord } from '@aegis/database';
import { ValidationError } from '@aegis/shared';

export interface AgentEngineRegistryDeps {
  config: AppConfig;
  logger: Logger;
  repos: Repositories;
  eventBus: EventBus;
  modelRouter: ModelRouter;
  toolRegistry: ToolRegistry;
  toolGateway: ToolGateway;
  /** Part 4 §120: deterministic security projection provider. */
  security?: SecurityContextProvider;
}

export class AgentEngineRegistry implements AgentLauncher {
  private readonly engines = new Map<string, AgentLoopEngine>();
  private readonly background = new Set<Promise<void>>();

  constructor(private readonly deps: AgentEngineRegistryDeps) {}

  /** AgentLauncher.start — called by the orchestrator on engagement start. */
  async start(engagement: EngagementRecord, actorId: string | null, reason?: string): Promise<{ runId: string }> {
    if (engagement.status !== 'RUNNING') {
      throw new ValidationError(
        `Cannot start an agent run while the engagement is ${engagement.status}`,
        'ENGAGEMENT_NOT_RUNNING',
      );
    }
    const existing = await this.deps.repos.agentRuns.findActiveByEngagement(engagement.id);
    if (existing && ['RUNNING', 'WAITING', 'INITIALIZING'].includes(existing.status)) {
      throw new ValidationError(
        'An active agent run already exists for this engagement',
        'AGENT_RUN_ALREADY_ACTIVE',
        { run_id: existing.id },
      );
    }

    const engine = this.buildEngine();
    const run = await engine.start(engagement, {
      leaderModel: this.deps.modelRouter.forRole('strategic').model,
      workerModel: this.deps.modelRouter.forRole('tactical').model,
      reason: reason ?? 'engagement started',
    });
    this.engines.set(engagement.id, engine);
    void actorId;
    this.spawnBackgroundLoop(engagement.id, engine);
    return { runId: run.id };
  }

  async pause(engagementId: string, _actorId: string | null, reason?: string): Promise<void> {
    const engine = this.engines.get(engagementId);
    const run = await this.deps.repos.agentRuns.findActiveByEngagement(engagementId);
    if (engine) engine.requestPause(reason ?? 'operator pause');
    if (run && (run.status === 'RUNNING' || run.status === 'WAITING')) {
      await this.deps.repos.agentRuns.updateStatus(run.id, 'PAUSED');
      await this.deps.eventBus.publish({
        type: 'AGENT_RUN_PAUSED',
        engagement_id: engagementId,
        task_id: null,
        trace_id: `TRC_PAUSE_${run.id}`,
        actor_id: _actorId,
        payload: { run_id: run.id, reason: reason ?? 'operator pause' },
        occurred_at: new Date().toISOString(),
      });
    }
  }

  async resume(engagementId: string, actorId: string | null): Promise<void> {
    const run = await this.deps.repos.agentRuns.findActiveByEngagement(engagementId);
    if (!run) return;
    if (run.status !== 'PAUSED') {
      throw new ValidationError(
        `Run ${run.id} is ${run.status}; only PAUSED runs can be resumed`,
        'AGENT_RUN_NOT_PAUSED',
      );
    }
    const engagement = await this.deps.repos.engagements.findById(engagementId);
    if (!engagement) return;
    await this.deps.repos.agentRuns.updateStatus(run.id, 'RUNNING');
    await this.deps.eventBus.publish({
      type: 'AGENT_RUN_RESUMED',
      engagement_id: engagementId,
      task_id: null,
      trace_id: `TRC_RESUME_${run.id}`,
      actor_id: actorId,
      payload: { run_id: run.id },
      occurred_at: new Date().toISOString(),
    });
    // Ensure an engine is running for this engagement (restart recovery, §63).
    if (!this.engines.has(engagementId)) {
      const engine = this.buildEngine();
      await engine.attach(engagement, (await this.deps.repos.agentRuns.findById(run.id))!);
      this.engines.set(engagementId, engine);
      this.spawnBackgroundLoop(engagementId, engine);
    } else {
      this.engines.get(engagementId)!.requestResume();
    }
  }

  async cancel(engagementId: string, actorId: string | null, reason?: string): Promise<void> {
    const engine = this.engines.get(engagementId);
    if (engine) engine.requestCancel(reason ?? 'operator cancellation');
    const run = await this.deps.repos.agentRuns.findActiveByEngagement(engagementId);
    if (run) {
      // Deterministic terminal transition (§50: orchestrator decides).
      await this.deps.repos.agentRuns.updateStatus(run.id, 'CANCELLED');
      await this.deps.eventBus.publish({
        type: 'AGENT_RUN_CANCELLED',
        engagement_id: engagementId,
        task_id: null,
        trace_id: `TRC_CANCEL_${run.id}`,
        actor_id: actorId,
        payload: { run_id: run.id, reason: reason ?? 'operator cancellation' },
        occurred_at: new Date().toISOString(),
      });
    }
    this.engines.delete(engagementId);
  }

  /** Direct run start for the API route (independent of engagement start). */
  async startRun(
    engagement: EngagementRecord,
    actorId: string | null,
    reason?: string,
  ): Promise<{ runId: string }> {
    return this.start(engagement, actorId, reason);
  }

  getEngine(engagementId: string): AgentLoopEngine | undefined {
    return this.engines.get(engagementId);
  }

  /** Human overrides (spec §46) — all audited by the route layer. */
  async applyHumanOverride(input: {
    engagementId: string;
    actorId: string;
    kind: 'ADD_CTF_CLUE' | 'PRIORITIZE_HYPOTHESIS' | 'CANCEL_TASK' | 'REQUEST_VERIFICATION' | 'PAUSE_RUN';
    payload: Record<string, unknown>;
  }): Promise<Record<string, unknown>> {
    const { repos } = this.deps;
    switch (input.kind) {
      case 'ADD_CTF_CLUE': {
        const observation = await repos.observations.create({
          engagementId: input.engagementId,
          taskId: null,
          hypothesisId: null,
          type: 'CTF_CLUE',
          description: String(input.payload.clue ?? ''),
          confidence: 1,
          metadata: { source: 'human', provided_by: input.actorId },
        });
        await this.deps.eventBus.publish({
          type: 'HUMAN_OVERRIDE',
          engagement_id: input.engagementId,
          task_id: null,
          trace_id: `TRC_OVERRIDE_${observation.id}`,
          actor_id: input.actorId,
          payload: { kind: input.kind, observation_id: observation.id },
          occurred_at: new Date().toISOString(),
        });
        return { observation_id: observation.id };
      }
      case 'PRIORITIZE_HYPOTHESIS': {
        const hypothesisId = String(input.payload.hypothesis_id ?? '');
        const priority = Number(input.payload.priority ?? 0.5);
        const hypothesis = await repos.hypotheses.findByIdAndEngagement(
          hypothesisId,
          input.engagementId,
        );
        if (!hypothesis) {
          throw new ValidationError('Hypothesis not found in this engagement', 'HYPOTHESIS_NOT_FOUND');
        }
        const updated = await repos.hypotheses.update(hypothesis.id, {
          priority: Math.min(1, Math.max(0, priority)),
        });
        await this.deps.eventBus.publish({
          type: 'HUMAN_OVERRIDE',
          engagement_id: input.engagementId,
          task_id: null,
          trace_id: `TRC_OVERRIDE_${hypothesis.id}`,
          actor_id: input.actorId,
          payload: { kind: input.kind, hypothesis_id: hypothesis.id, priority },
          occurred_at: new Date().toISOString(),
        });
        return { hypothesis_id: updated?.id ?? hypothesis.id, priority: updated?.priority ?? priority };
      }
      case 'CANCEL_TASK': {
        const taskId = String(input.payload.task_id ?? '');
        const task = await repos.tasks.findByIdAndEngagement(taskId, input.engagementId);
        if (!task) {
          throw new ValidationError('Task not found in this engagement', 'TASK_NOT_FOUND');
        }
        const engine = this.engines.get(input.engagementId);
        const scheduler = engine ? (engine as unknown as { scheduler?: never }) : undefined;
        void scheduler;
        // Cancel directly through the repository (deterministic transition).
        if (['COMPLETED', 'PARTIAL', 'FAILED', 'CANCELLED', 'EXPIRED'].includes(task.status)) {
          throw new ValidationError(
            `Task is already ${task.status}`,
            'TASK_TERMINAL',
          );
        }
        await repos.tasks.recordFailure(task.id, 'HUMAN_CANCELLED', String(input.payload.reason ?? 'operator cancelled'));
        await repos.tasks.updateStatus(task.id, 'CANCELLED');
        await this.deps.eventBus.publish({
          type: 'TASK_CANCELLED',
          engagement_id: input.engagementId,
          task_id: task.id,
          trace_id: `TRC_OVERRIDE_${task.id}`,
          actor_id: input.actorId,
          payload: { reason: String(input.payload.reason ?? 'operator cancelled') },
          occurred_at: new Date().toISOString(),
        });
        return { task_id: task.id, status: 'CANCELLED' };
      }
      case 'REQUEST_VERIFICATION': {
        const hypothesisId = String(input.payload.hypothesis_id ?? '');
        const hypothesis = await repos.hypotheses.findByIdAndEngagement(
          hypothesisId,
          input.engagementId,
        );
        if (!hypothesis) {
          throw new ValidationError('Hypothesis not found in this engagement', 'HYPOTHESIS_NOT_FOUND');
        }
        // Compile a verification task immediately (verification is
        // independently schedulable, §56) and let the engine pick it up.
        const engine = this.buildEngine();
        const run = await repos.agentRuns.findActiveByEngagement(input.engagementId);
        if (run) {
          await engine.compilerCompileVerification(
            input.engagementId,
            run.id,
            hypothesis.id,
            String(input.payload.reason ?? 'operator requested verification'),
          );
        }
        await this.deps.eventBus.publish({
          type: 'HUMAN_OVERRIDE',
          engagement_id: input.engagementId,
          task_id: null,
          trace_id: `TRC_OVERRIDE_${hypothesis.id}`,
          actor_id: input.actorId,
          payload: { kind: input.kind, hypothesis_id: hypothesis.id },
          occurred_at: new Date().toISOString(),
        });
        return { hypothesis_id: hypothesis.id, verification_task_requested: run !== null };
      }
      case 'PAUSE_RUN': {
        await this.pause(input.engagementId, input.actorId, String(input.payload.reason ?? 'operator pause'));
        return { paused: true };
      }
      default:
        throw new ValidationError(`Unknown override kind '${String(input.kind)}'`, 'OVERRIDE_UNKNOWN');
    }
  }

  /** Runs crash recovery for an engagement without starting a new run (§63-64). */
  async recover(engagementId: string): Promise<{ recovered: number; finalized: number; requeued: number; failed: number }> {
    const engine = this.buildEngine();
    const report = await engine.recoverNow(engagementId);
    return {
      recovered: report.recovered,
      finalized: report.finalizedFromOutput,
      requeued: report.requeued,
      failed: report.failed,
    };
  }

  metrics(engagementId: string): Promise<Record<string, unknown>> {
    const collector = new AgentMetricsCollector({ repos: this.deps.repos });
    return collector.collect(engagementId) as unknown as Promise<Record<string, unknown>>;
  }

  private buildEngine(): AgentLoopEngine {
    const { config, logger, repos, eventBus, modelRouter, toolRegistry, toolGateway } = this.deps;

    const workerRuntime = new TacticalWorkerRuntime({
      provider: modelRouter.forRole('tactical'),
      repos,
      eventBus,
      toolRegistry: {
        get: (name: string) => {
          const tool = toolRegistry.get(name);
          return tool ? { description: tool.description, implemented: tool.implemented } : null;
        },
      },
      options: {
        maxTurns: config.agent.worker.maxTurns,
        maxOutputTokens: config.agent.worker.maxOutputTokens,
      },
    });

    const quota = new QuotaManager(config.agent.quota);
    const tokenBudgets = new TokenBudgeter(config.agent.tokenBudgets);

    return new AgentLoopEngine({
      repos,
      eventBus,
      logger,
      models: {
        strategic: modelRouter.forRole('strategic'),
        tactical: modelRouter.forRole('tactical'),
      },
      tools: toolRegistry,
      toolGateway,
      workerRuntime,
      quota,
      tokenBudgets,
      security: this.deps.security,
      options: {
        maxCycles: config.agent.loop.maxCycles,
        maxIdleCycles: config.agent.loop.maxIdleCycles,
        idleBackoffMs: config.agent.loop.idleBackoffMs,
        maxWaitMs: config.agent.loop.maxWaitMs,
        defaultBudget: config.agent.engagementBudgetDefaults,
      },
    });
  }

  private spawnBackgroundLoop(engagementId: string, engine: AgentLoopEngine): void {
    const promise = engine
      .run()
      .catch((error: unknown) => {
        this.deps.logger.error('agent.loop_crashed', {
          engagement_id: engagementId,
          error: error instanceof Error ? error.message : String(error),
        });
      })
      .finally(() => {
        this.background.delete(promise);
        if (this.engines.get(engagementId) === engine) {
          this.engines.delete(engagementId);
        }
      });
    this.background.add(promise);
  }
}
