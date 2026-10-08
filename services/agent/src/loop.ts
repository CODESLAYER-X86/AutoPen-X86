/**
 * Autonomous decision loop (spec Part 2 §30-§31, §45, §49-§50).
 *
 * Implemented as an EXPLICIT event-driven state machine, never uncontrolled
 * recursion: `step()` performs exactly one deterministic tick; `run()`
 * iterates ticks with bounded cycles and idle backoff. Control flags
 * (pause / resume / cancel) are checked at every tick, so a human can stop
 * autonomous activity immediately (§45).
 *
 * One tick:
 *   1. control check (paused / cancelled)
 *   2. deterministic stop conditions (§50)
 *   3. dependency resolution (§33)
 *   4. dispatch ready tasks (bounded concurrency) and await them
 *   5. anti-loop evaluation (§51-§52)
 *   6. if no pending work: leader decision cycle (§4)
 *   7. apply decision through compiler / hypothesis engine
 *   8. record the decision-cycle outcome (§31)
 *
 * The orchestrator — not the leader — makes every final state transition
 * (§50). The leader commands; this engine decides what actually happens.
 */
import type {
  AgentRunRecord,
  EngagementRecord,
  EngagementUsageRecord,
  EngagementBudgetRecord,
  ScopeRecord,
  Repositories,
} from '@aegis/database';
import type { EventBus } from '@aegis/events';
import type { Logger } from '@aegis/logging';
import { generateId, type AgentRunStatus } from '@aegis/shared';
import { AgentRunStateMachine } from './state-machines.js';
import { AgentPolicy } from './policy.js';
import { TaskScheduler } from './scheduler.js';
import { TaskCompiler } from './task-compiler.js';
import { HypothesisEngine } from './hypothesis-engine.js';
import { ResultNormalizer } from './result-normalizer.js';
import { LeaderRuntime } from './leader.js';
import { AntiLoopDetector } from './anti-loop.js';
import { CrashRecovery } from './recovery.js';
import { QuotaManager, TokenBudgeter } from './quota.js';
import { ContextBuilder } from './context-builder.js';
import { DecisionValidator } from './decision-validator.js';
import { AgentMetricsCollector } from './metrics.js';
import type { ModelProvider } from '@aegis/model-runtime';
import type { ToolGateway, ToolRegistry } from '@aegis/tools';
import type { WorkerRuntime } from '@aegis/worker-runtime';

export interface LoopOptions {
  /** Hard bound on leader decision cycles per run (anti-runaway). */
  maxCycles: number;
  /** Maximum idle leader cycles before a deterministic stop. */
  maxIdleCycles: number;
  /** Backoff between ticks when there is nothing to do. */
  idleBackoffMs: number;
  /** Maximum sleep for a leader WAIT decision. */
  maxWaitMs: number;
  /** Scheduler retry backoff for transient task failures (§44). */
  retryDelayMs: number;
  /** Default engagement budget applied when none is configured. */
  defaultBudget: {
    maxDurationSeconds?: number | null;
    maxModelCalls?: number | null;
    maxModelTokens?: number | null;
    maxNetworkRequests?: number | null;
  };
}

export const DEFAULT_LOOP_OPTIONS: LoopOptions = {
  maxCycles: 40,
  maxIdleCycles: 3,
  idleBackoffMs: 150,
  maxWaitMs: 5_000,
  retryDelayMs: 800,
  defaultBudget: {},
};

export interface AgentEngineDeps {
  repos: Repositories;
  eventBus: EventBus;
  logger: Logger;
  models: { strategic: ModelProvider; tactical: ModelProvider };
  tools: ToolRegistry;
  toolGateway: ToolGateway;
  workerRuntime: WorkerRuntime;
  options?: Partial<LoopOptions>;
  quota?: QuotaManager;
  tokenBudgets?: TokenBudgeter;
}

export type StepOutcome =
  | { kind: 'running' }
  | { kind: 'waiting'; until: number }
  | { kind: 'paused' }
  | { kind: 'completed'; reason: string }
  | { kind: 'failed'; reason: string; code: string }
  | { kind: 'cancelled'; reason: string }
  | { kind: 'idle' };

/** Engagement lifecycle callbacks — provided by the orchestrator (§50). */
export interface EngagementController {
  complete(engagementId: string, actorId: string | null, reason: string): Promise<void>;
  fail(engagementId: string, actorId: string | null, reason: string): Promise<void>;
}

export class AgentLoopEngine {
  private readonly opts: LoopOptions;
  private readonly repos: Repositories;
  private readonly leader: LeaderRuntime;
  private readonly compiler: TaskCompiler;
  private readonly scheduler: TaskScheduler;
  private readonly hypothesisEngine: HypothesisEngine;
  private readonly normalizer: ResultNormalizer;
  private readonly antiLoop: AntiLoopDetector;
  private readonly recovery: CrashRecovery;
  private readonly quota: QuotaManager;
  private readonly tokenBudgets: TokenBudgeter;
  private readonly metrics: AgentMetricsCollector;

  private runState: AgentRunRecord | null = null;
  private engagement: EngagementRecord | null = null;
  private control: 'running' | 'pause-requested' | 'cancel-requested' = 'running';
  private waitUntil = 0;
  private cycleCount = 0;
  private idleCycles = 0;
  private lastFocus: string | null = null;
  private controller: EngagementController | null = null;
  private finished = false;

  constructor(private readonly deps: AgentEngineDeps) {
    this.opts = { ...DEFAULT_LOOP_OPTIONS, ...deps.options };
    this.repos = deps.repos;
    this.quota = deps.quota ?? new QuotaManager();
    this.tokenBudgets = deps.tokenBudgets ?? (new TokenBudgeter() as unknown as TokenBudgeter);

    const contextBuilder = new ContextBuilder({ repos: deps.repos, tools: deps.tools });
    const decisionValidator = new DecisionValidator({
      tools: deps.tools,
      findTask: (engagementId, taskId) => this.repos.tasks.findByIdAndEngagement(taskId, engagementId),
      findHypothesis: (engagementId, hypothesisId) =>
        this.repos.hypotheses.findByIdAndEngagement(hypothesisId, engagementId),
      findIdentity: async (engagementId, identityId) => {
        const list = await this.repos.identities.listByEngagement(engagementId);
        const found = list.find((i) => i.id === identityId);
        return found ? { id: found.id } : null;
      },
      fingerprintExists: async (engagementId, fingerprint) => {
        const row = await this.repos.tests.findByFingerprint(engagementId, fingerprint);
        return row !== null;
      },
      runStatus: null,
    });

    this.leader = new LeaderRuntime({
      provider: deps.models.strategic,
      repos: deps.repos,
      eventBus: deps.eventBus,
      logger: deps.logger,
      contextBuilder,
      decisionValidator,
      quota: this.quota,
      tokenBudgets: this.tokenBudgets,
    });

    this.compiler = new TaskCompiler({
      repos: deps.repos,
      tools: deps.tools,
      eventBus: deps.eventBus,
    });
    this.hypothesisEngine = new HypothesisEngine({
      hypotheses: deps.repos.hypotheses,
      deadEnds: deps.repos.deadEnds,
      findings: deps.repos.findings,
      eventBus: deps.eventBus,
    });
    this.normalizer = new ResultNormalizer({
      repos: deps.repos,
      eventBus: deps.eventBus,
      hypothesisEngine: this.hypothesisEngine,
    });
    this.scheduler = new TaskScheduler({
      repos: deps.repos,
      eventBus: deps.eventBus,
      workerRuntime: deps.workerRuntime,
      compiler: this.compiler,
      normalizer: this.normalizer,
      toolGateway: deps.toolGateway,
      quota: this.quota,
      tokenBudgets: this.tokenBudgets,
      options: { retryDelayMs: this.opts.retryDelayMs },
    });
    this.antiLoop = new AntiLoopDetector({ repos: deps.repos, eventBus: deps.eventBus });
    this.recovery = new CrashRecovery({
      repos: deps.repos,
      eventBus: deps.eventBus,
      normalizer: this.normalizer,
    });
    this.metrics = new AgentMetricsCollector({ repos: deps.repos });
  }

  /** Human engagement-level controls (§45). */
  setEngagementController(controller: EngagementController): void {
    this.controller = controller;
  }

  get runId(): string | null {
    return this.runState?.id ?? null;
  }

  get cycles(): number {
    return this.cycleCount;
  }

  // -------------------------------------------------------------------------
  // Lifecycle
  // -------------------------------------------------------------------------

  /**
   * Initializes a fresh run: CREATED -> INITIALIZING -> RUNNING with crash
   * recovery and the initial strategy snapshot (§30 INITIALIZE).
   */
  async start(
    engagement: EngagementRecord,
    input: { leaderModel: string; workerModel: string; reason: string | null },
  ): Promise<AgentRunRecord> {
    if (this.runState) throw new Error('Engine already bound to a run');

    const run = await this.repos.agentRuns.create({
      engagementId: engagement.id,
      leaderModel: input.leaderModel,
      workerModel: input.workerModel,
      reason: input.reason,
    });
    this.runState = run;
    this.engagement = engagement;
    await this.emitRunEvent('AGENT_RUN_CREATED', { reason: input.reason });

    await this.transitionRun('INITIALIZING');
    await this.emitRunEvent('AGENT_RUN_STARTED', {});

    // Initial strategy snapshot (§49) so the UI can explain direction.
    const strategy = await this.repos.strategies.createNext({
      engagementId: engagement.id,
      runId: run.id,
      summary: 'Initial strategy: map the attack surface and form competing hypotheses.',
      focus: 'initial-recon',
      reason: input.reason ?? 'run started',
    });
    this.lastFocus = strategy.focus;
    await this.repos.agentRuns.updateStrategyVersion(run.id, strategy.version);
    await this.deps.eventBus.publish({
      type: 'STRATEGY_CHANGED',
      engagement_id: engagement.id,
      task_id: null,
      trace_id: generateId('TRC'),
      actor_id: null,
      payload: { run_id: run.id, version: strategy.version, focus: strategy.focus },
      occurred_at: new Date().toISOString(),
    });

    // Crash recovery for any dangling state from a previous process (§63-64).
    await this.recovery.recoverEngagement(engagement.id, run.id);
    await this.quota.rebaseFromDatabase(engagement.id, this.repos.modelCalls);

    await this.transitionRun('RUNNING');
    this.control = 'running';
    this.finished = false;
    return run;
  }

  /** Binds the engine to an EXISTING run (resume after pause/restart). */
  async attach(engagement: EngagementRecord, run: AgentRunRecord): Promise<void> {
    this.engagement = engagement;
    this.runState = run;
    this.cycleCount = await this.repos.agentDecisions.nextCycle(run.id) - 1;
    await this.quota.rebaseFromDatabase(engagement.id, this.repos.modelCalls);
  }

  requestPause(reason: string): void {
    if (!this.finished) this.control = 'pause-requested';
    void reason;
  }

  requestCancel(reason: string): void {
    if (!this.finished) this.control = 'cancel-requested';
    void reason;
  }

  requestResume(): void {
    if (this.control === 'pause-requested') this.control = 'running';
  }

  /**
   * Composition-root helper: compile + queue a verification task for a
   * hypothesis without a leader cycle (human override path, §46/§56).
   */
  async compilerCompileVerification(
    engagementId: string,
    runId: string,
    hypothesisId: string,
    reason: string,
  ): Promise<{ taskId: string | null }> {
    const compiled = await this.compiler.compile(
      {
        decision: 'REQUEST_VERIFICATION',
        reasoning_summary: reason.slice(0, 2000),
        hypothesis_id: hypothesisId,
      },
      { engagementId, runId, decisionId: `${runId}:override:${hypothesisId}` },
    );
    await this.scheduler.resolveDependencies(engagementId);
    return { taskId: compiled[0]?.task.id ?? null };
  }

  /**
   * Composition-root helper: run crash recovery for an engagement without
   * binding a run (exposed for the API recovery endpoint, §63-§64).
   */
  async recoverNow(engagementId: string): Promise<import('./recovery.js').RecoveryReport> {
    return this.recovery.recoverEngagement(engagementId, null);
  }

  /**
   * The autonomous execution loop (§30). Bounded cycles; every tick checks
   * control flags and deterministic stop conditions. NOT recursion: one
   * while-loop, one tick per iteration.
   */
  async run(): Promise<void> {
    while (!this.finished) {
      const outcome = await this.step();
      if (outcome.kind === 'completed' || outcome.kind === 'failed' || outcome.kind === 'cancelled') {
        break;
      }
      if (outcome.kind === 'paused') {
        await this.waitForControlChange();
        continue;
      }
      if (outcome.kind === 'waiting') {
        await sleep(Math.min(Math.max(outcome.until - Date.now(), 50), this.opts.maxWaitMs));
        if (this.runState && (await this.repos.agentRuns.findById(this.runState.id))?.status === 'WAITING') {
          await this.transitionRun('RUNNING');
        }
        continue;
      }
      if (outcome.kind === 'idle') {
        await sleep(this.opts.idleBackoffMs);
      }
    }
  }

  /**
   * ONE deterministic tick (exposed for tests + step-driven simulation).
   * Everything the engine does happens here, in a fixed order.
   */
  async step(): Promise<StepOutcome> {
    if (!this.runState || !this.engagement) {
      return { kind: 'failed' as const, reason: 'Engine not bound to a run', code: 'ENGINE_NOT_BOUND' };
    }
    if (this.finished) return { kind: 'completed', reason: 'run already finished' };

    // 1. Control check (§45: the user can stop autonomous activity immediately).
    if (this.control === 'cancel-requested') {
      return this.finish('cancelled', 'operator requested cancellation');
    }
    if (this.control === 'pause-requested') {
      if (this.runState.status === 'RUNNING' || this.runState.status === 'WAITING') {
        await this.transitionRun('PAUSED');
        await this.emitRunEvent('AGENT_RUN_PAUSED', { reason: 'operator pause' });
      }
      return { kind: 'paused' };
    }

    // 2. Deterministic stop conditions (§50) — the orchestrator decides.
    const stop = await this.evaluateStopConditions();
    if (stop) return stop;

    // 3. Dependency resolution (§33).
    await this.scheduler.resolveDependencies(this.engagement.id);

    // 4. Dispatch ready tasks and await completion (bounded concurrency).
    const dispatch = await this.dispatchReadyTasks();
    if (dispatch.executed > 0) {
      await this.refreshRunMetrics();
      return { kind: 'running' };
    }

    // 5. Anti-loop evaluation (§51-§52) — may create follow-up work.
    const antiLoopReport = await this.antiLoop.evaluate(this.engagement.id, this.runState.id);
    await this.applyAntiLoopActions(antiLoopReport.actions);
    if (antiLoopReport.actions.some((a) => a.type === 'PAUSE_STRATEGY')) {
      // Forced evidence review (§52): schedule a distinguishing review task.
      await this.compiler.compile(
        {
          decision: 'CREATE_TASK',
          reasoning_summary: 'Oscillation detected; forcing an evidence review before further strategy changes',
          task: {
            objective: 'Evidence review: reconcile current observations and identify ONE distinguishing test',
            task_type: 'GENERAL_ANALYSIS',
            depends_on: [],
          },
        },
        { engagementId: this.engagement.id, runId: this.runState.id, decisionId: this.runState.id },
      );
      await this.scheduler.resolveDependencies(this.engagement.id);
      return { kind: 'running' };
    }

    // 6. Pending work? If yes, wait for it; if not, ask the leader.
    const pending = await this.pendingTaskCount();
    if (pending > 0) {
      return { kind: 'idle' };
    }

    if (this.waitUntil > Date.now()) {
      if (this.runState.status === 'RUNNING') {
        await this.transitionRun('WAITING');
        await this.emitRunEvent('AGENT_RUN_WAITING', { until: new Date(this.waitUntil).toISOString() });
      }
      return { kind: 'waiting', until: this.waitUntil };
    }

    if (this.cycleCount >= this.opts.maxCycles) {
      return this.finish('completed', `cycle budget exhausted (${this.opts.maxCycles} cycles)`);
    }

    // 7. Leader decision cycle.
    const outcome = await this.leader.decide({
      engagementId: this.engagement.id,
      runId: this.runState.id,
      cycle: this.cycleCount + 1,
      runStatus: this.runState.status,
    });

    this.cycleCount += 1;

    if (!outcome.ok) {
      // Quota pressure is NOT a failure: the run waits and retries later
      // (§40: delay rather than intentionally exceed the configured quota).
      if (outcome.code === 'QUOTA_DELAY_REQUIRED') {
        const details = outcome.details as { retry_after_ms?: number } | undefined;
        const delayMs = Math.min(details?.retry_after_ms ?? 1_000, this.opts.maxWaitMs);
        this.waitUntil = Date.now() + delayMs;
        await this.deps.eventBus.publish({
          type: 'QUOTA_DELAY',
          engagement_id: this.engagement.id,
          task_id: null,
          trace_id: generateId('TRC'),
          actor_id: null,
          payload: { run_id: this.runState.id, scope: 'leader', retry_after_ms: delayMs },
          occurred_at: new Date().toISOString(),
        });
        return { kind: 'waiting', until: this.waitUntil };
      }
      // Schema/validation failures are recorded; the loop tolerates a few
      // (anti-loop counts them) before failing deterministically.
      this.idleCycles += 1;
      if (this.idleCycles >= this.opts.maxIdleCycles) {
        return this.finish('failed', `leader decision quality degraded: ${outcome.code}`);
      }
      return { kind: 'idle' };
    }

    const applied = await this.applyDecision(outcome.decision);
    await this.repos.agentDecisions.recordOutcome(outcome.decisionRecord.id, applied.outcome);
    this.idleCycles = 0;

    await this.refreshRunMetrics();
    await this.emitRunEvent('AGENT_CYCLE_COMPLETED', {
      cycle: this.cycleCount,
      decision: outcome.decision.decision,
      ...applied.outcome,
    });

    return { kind: 'running' };
  }

  // -------------------------------------------------------------------------
  // Stop conditions (§50) — deterministic, orchestrator-owned
  // -------------------------------------------------------------------------

  private async evaluateStopConditions(): Promise<StepOutcome | null> {
    if (!this.runState || !this.engagement) return null;

    const [engagement, scope, budget, usage, run] = await Promise.all([
      this.repos.engagements.findById(this.engagement.id),
      this.repos.scope.findByEngagement(this.engagement.id),
      this.repos.budgets.getOrDefault(this.engagement.id, this.opts.defaultBudget),
      this.repos.budgets.getUsage(this.engagement.id),
      this.repos.agentRuns.findById(this.runState.id),
    ]);
    if (!engagement || !run) {
      return this.finish('failed', 'engagement or run disappeared', 'STATE_LOST');
    }
    this.engagement = engagement;
    this.runState = run;

    // Operator paused/cancelled through the API (DB is authoritative).
    if (run.status === 'CANCELLED') {
      this.finished = true;
      return { kind: 'cancelled', reason: 'run cancelled' };
    }
    if (run.status === 'PAUSED') {
      this.control = 'pause-requested';
      return { kind: 'paused' };
    }
    if (engagement.status === 'PAUSED') {
      this.control = 'pause-requested';
      await this.transitionRun('PAUSED');
      return { kind: 'paused' };
    }
    if (['COMPLETED', 'FAILED', 'CANCELLED'].includes(engagement.status)) {
      return this.finish('cancelled', `engagement is ${engagement.status}`);
    }

    // Scope invalid: all network testing is structurally impossible.
    if (scope === null) {
      return this.finish('failed', 'engagement has no scope; autonomous testing cannot proceed', 'SCOPE_NOT_CONFIGURED');
    }

    // Resource budget exhausted (§50/§66).
    const policy = new AgentPolicy();
    const denial = policy.checkBudget({ engagement, scope, usage, budget });
    if (denial) {
      return this.finish('completed', `resource budget exhausted: ${denial.reason}`);
    }

    // No actionable hypotheses remain AND no pending work (§50).
    const actionable = await this.repos.hypotheses.countActionable(engagement.id);
    const pending = await this.pendingTaskCount();
    if (this.cycleCount > 0 && actionable === 0 && pending === 0) {
      return this.finish('completed', 'no actionable hypotheses remain');
    }

    return null;
  }

  // -------------------------------------------------------------------------
  // Decision application — the orchestrator interprets the leader (§16)
  // -------------------------------------------------------------------------

  private async applyDecision(decision: import('@aegis/contracts').LeaderDecision): Promise<{
    outcome: Record<string, unknown>;
  }> {
    if (!this.runState || !this.engagement) return { outcome: {} };

    switch (decision.decision) {
      case 'CREATE_TASK':
      case 'CREATE_PARALLEL_TASKS':
      case 'REQUEST_KNOWLEDGE':
      case 'REQUEST_RECON':
      case 'REQUEST_VERIFICATION': {
        const compiled = await this.compiler.compile(decision, {
          engagementId: this.engagement.id,
          runId: this.runState.id,
          decisionId: await this.currentDecisionId(),
        });
        for (const c of compiled) {
          if (c.task.hypothesis_id) {
            const hypothesis = await this.repos.hypotheses.findById(c.task.hypothesis_id);
            if (hypothesis) {
              await this.hypothesisEngine.markTesting(hypothesis).catch(() => undefined);
            }
          }
        }
        await this.scheduler.resolveDependencies(this.engagement.id);
        if (decision.decision === 'REQUEST_VERIFICATION') {
          await this.deps.eventBus.publish({
            type: 'VERIFICATION_REQUESTED',
            engagement_id: this.engagement.id,
            task_id: null,
            trace_id: generateId('TRC'),
            actor_id: null,
            payload: { run_id: this.runState.id, hypothesis_id: decision.hypothesis_id, source: 'leader' },
            occurred_at: new Date().toISOString(),
          });
        }
        // Strategy memory (§49): record a new version when focus changes.
        await this.maybeRecordStrategyChange(compiled.map((c) => c.task.type).join('+'), decision.reasoning_summary);
        return {
          outcome: {
            tasks_created: compiled.length,
            task_ids: compiled.map((c) => c.task.id),
          },
        };
      }

      case 'UPDATE_HYPOTHESIS': {
        if (decision.change === 'CREATE' && decision.hypothesis) {
          const created = await this.hypothesisEngine.createHypothesis({
            engagementId: this.engagement.id,
            type: decision.hypothesis.type,
            statement: decision.hypothesis.statement,
            confidence: decision.hypothesis.confidence ?? 0.5,
            priority: decision.hypothesis.priority ?? 0.5,
            source: 'leader',
            parentHypothesisId: decision.hypothesis.parent_hypothesis_id ?? null,
          });
          await this.maybeRecordStrategyChange(
            `hypothesis:${created.type}`,
            decision.reasoning_summary,
          );
          return { outcome: { hypothesis_created: created.id } };
        }
        if (decision.hypothesis_id) {
          const hypothesis = await this.repos.hypotheses.findByIdAndEngagement(
            decision.hypothesis_id,
            this.engagement.id,
          );
          if (hypothesis) {
            const updated = await this.hypothesisEngine
              .applyChange(hypothesis, decision.change, { confidence: decision.confidence })
              .catch((error: unknown) => {
                this.deps.logger.warn('hypothesis.update_rejected', {
                  engagement_id: this.engagement!.id,
                  hypothesis_id: decision.hypothesis_id,
                  error: error instanceof Error ? error.message : String(error),
                });
                return null;
              });
            return {
              outcome: updated
                ? { hypothesis_updated: updated.id, status: updated.status, confidence: updated.confidence }
                : { hypothesis_update_rejected: decision.hypothesis_id },
            };
          }
        }
        return { outcome: { hypothesis_update_rejected: 'hypothesis not found' } };
      }

      case 'WAIT': {
        this.waitUntil = Date.now() + Math.min(
          (decision.duration_hint_seconds ?? 5) * 1000,
          this.opts.maxWaitMs,
        );
        return { outcome: { wait_until: new Date(this.waitUntil).toISOString() } };
      }

      case 'STOP': {
        // The leader recommends; the orchestrator decides (§50).
        if (decision.objective_satisfied) {
          await this.finish('completed', 'objective satisfied (leader STOP accepted)');
          return { outcome: { stopped: true, objective_satisfied: true } };
        }
        const actionable = await this.repos.hypotheses.countActionable(this.engagement.id);
        const pending = await this.pendingTaskCount();
        if (actionable === 0 && pending === 0) {
          await this.finish('completed', 'no actionable hypotheses remain (leader STOP accepted)');
          return { outcome: { stopped: true } };
        }
        // STOP without deterministic justification: pause for operator review.
        await this.transitionRun('PAUSED');
        await this.emitRunEvent('AGENT_RUN_PAUSED', {
          reason: 'leader requested STOP without objective satisfaction; operator review required',
        });
        return { outcome: { paused_for_review: true } };
      }

      case 'PAUSE': {
        await this.transitionRun('PAUSED');
        await this.emitRunEvent('AGENT_RUN_PAUSED', { reason: decision.reasoning_summary });
        this.control = 'pause-requested';
        return { outcome: { paused: true } };
      }

      default:
        return { outcome: {} };
    }
  }

  // -------------------------------------------------------------------------
  // Task dispatch
  // -------------------------------------------------------------------------

  private async dispatchReadyTasks(): Promise<{ executed: number }> {
    if (!this.runState || !this.engagement) return { executed: 0 };

    const pendingTasks = await this.repos.tasks.listByEngagement(this.engagement.id, {
      statuses: ['READY', 'QUEUED', 'WAITING'],
      limit: 500,
    });
    const inFlight = new Set<string>();
    const { selected, quotaDelayed } = this.scheduler.selectDispatchable(pendingTasks, inFlight);
    if (quotaDelayed > 0) {
      await this.scheduler.recordQuotaDelay(this.engagement.id, 1_000);
    }
    if (selected.length === 0) return { executed: 0 };

    const scope = await this.repos.scope.findByEngagement(this.engagement.id);
    const runId = this.runState.id;
    const engagementRef = this.engagement;
    const results = await Promise.allSettled(
      selected.map((task) => this.scheduler.executeTask(task, {
        runId,
        engagement: engagementRef,
        scope,
      })),
    );

    let executed = 0;
    for (const result of results) {
      if (result.status === 'fulfilled') executed += 1;
      else {
        // A crashing task execution never crashes the run (§43.6).
        this.deps.logger.error('task.execution_crashed', {
          engagement_id: this.engagement.id,
          error: result.reason instanceof Error ? result.reason.message : String(result.reason),
        });
      }
    }
    return { executed };
  }

  private async pendingTaskCount(): Promise<number> {
    if (!this.engagement) return 0;
    const counts = await this.repos.tasks.countByStatus(this.engagement.id);
    return (
      counts.CREATED +
      counts.QUEUED +
      counts.READY +
      counts.RUNNING +
      counts.WAITING +
      counts.RECOVERY_PENDING
    );
  }

  // -------------------------------------------------------------------------
  // Anti-loop actions (§51)
  // -------------------------------------------------------------------------

  private async applyAntiLoopActions(
    actions: Array<{ type: string; [key: string]: unknown }>,
  ): Promise<void> {
    if (!this.engagement) return;
    for (const action of actions) {
      if (action.type === 'MARK_DEAD_END' && typeof action.hypothesisId === 'string') {
        const hypothesis = await this.repos.hypotheses.findById(action.hypothesisId);
        if (hypothesis && hypothesis.status !== 'ABANDONED') {
          await this.hypothesisEngine.abandon(hypothesis, String(action.reason)).catch(() => undefined);
        }
      } else if (action.type === 'REDUCE_PRIORITY' && typeof action.target === 'string') {
        const tasks = await this.repos.tasks.listByEngagement(this.engagement.id, {
          statuses: ['CREATED', 'QUEUED', 'READY', 'WAITING'],
          limit: 500,
        });
        for (const task of tasks) {
          const matches =
            task.worker_type === action.target ||
            task.objective.includes(action.target) ||
            JSON.stringify(task.inputs).includes(action.target);
          if (matches) {
            await this.repos.tasks.updatePriority(task.id, task.priority * 0.5);
          }
        }
      } else if (action.type === 'PAUSE_STRATEGY' || action.type === 'REQUEST_ALTERNATIVE_HYPOTHESIS') {
        const strategy = await this.repos.strategies.createNext({
          engagementId: this.engagement.id,
          runId: this.runState?.id ?? null,
          summary: String(action.reason),
          focus: action.type === 'PAUSE_STRATEGY' ? 'evidence-review' : 'alternative-hypothesis',
          reason: 'anti-loop protection',
        });
        await this.deps.eventBus.publish({
          type: 'STRATEGY_CHANGED',
          engagement_id: this.engagement.id,
          task_id: null,
          trace_id: generateId('TRC'),
          actor_id: null,
          payload: {
            run_id: this.runState?.id,
            version: strategy.version,
            focus: strategy.focus,
            source: 'anti-loop',
          },
          occurred_at: new Date().toISOString(),
        });
      }
    }
  }

  // -------------------------------------------------------------------------
  // Strategy memory (§49)
  // -------------------------------------------------------------------------

  private async maybeRecordStrategyChange(focus: string, reason: string): Promise<void> {
    if (!this.engagement || !this.runState) return;
    if (focus === this.lastFocus) return;
    const strategy = await this.repos.strategies.createNext({
      engagementId: this.engagement.id,
      runId: this.runState.id,
      summary: reason.slice(0, 2000),
      focus,
      reason: 'leader direction change',
    });
    this.lastFocus = focus;
    await this.repos.agentRuns.updateStrategyVersion(this.runState.id, strategy.version);
    await this.deps.eventBus.publish({
      type: 'STRATEGY_CHANGED',
      engagement_id: this.engagement.id,
      task_id: null,
      trace_id: generateId('TRC'),
      actor_id: null,
      payload: { run_id: this.runState.id, version: strategy.version, focus },
      occurred_at: new Date().toISOString(),
    });
  }

  // -------------------------------------------------------------------------
  // Finalization (§50: orchestrator makes the final transition)
  // -------------------------------------------------------------------------

  private async finish(
    kind: 'completed' | 'failed' | 'cancelled',
    reason: string,
    code?: string,
  ): Promise<StepOutcome> {
    if (!this.runState || !this.engagement) {
      return { kind: 'failed', reason, code: code ?? 'ENGINE_NOT_BOUND' };
    }
    if (this.finished) {
      if (kind === 'completed') return { kind: 'completed' as const, reason };
      if (kind === 'failed') return { kind: 'failed' as const, reason, code: code ?? 'RUN_FAILED' };
      return { kind: 'cancelled' as const, reason };
    }
    this.finished = true;

    const status: AgentRunStatus = kind === 'completed' ? 'COMPLETED' : kind === 'failed' ? 'FAILED' : 'CANCELLED';
    if (AgentRunStateMachine.canTransition(this.runState.status, status)) {
      await this.transitionRun(status);
    }
    await this.emitRunEvent(
      kind === 'completed'
        ? 'AGENT_RUN_COMPLETED'
        : kind === 'failed'
          ? 'AGENT_RUN_FAILED'
          : 'AGENT_RUN_CANCELLED',
      { reason, ...(code ? { code } : {}) },
    );
    await this.refreshRunMetrics();

    // Engagement transition: objective satisfied -> COMPLETED; failures ->
    // engagement stays RUNNING for operator review unless scope-invalid.
    if (kind === 'completed' && reason.includes('objective satisfied') && this.controller) {
      await this.controller.complete(this.engagement.id, null, reason).catch(() => undefined);
    }
    if (kind === 'completed') return { kind: 'completed' as const, reason };
    if (kind === 'failed') return { kind: 'failed' as const, reason, code: code ?? 'RUN_FAILED' };
    return { kind: 'cancelled' as const, reason };
  }

  private async transitionRun(to: AgentRunStatus): Promise<void> {
    if (!this.runState) return;
    if (this.runState.status === to) return;
    AgentRunStateMachine.assertTransition(this.runState.status, to);
    const updated = await this.repos.agentRuns.updateStatus(this.runState.id, to);
    if (updated) this.runState = updated;
  }

  private async emitRunEvent(type: string, payload: Record<string, unknown>): Promise<void> {
    if (!this.runState || !this.engagement) return;
    await this.deps.eventBus.publish({
      type: type as never,
      engagement_id: this.engagement.id,
      task_id: null,
      trace_id: generateId('TRC'),
      actor_id: null,
      payload: { run_id: this.runState.id, ...payload },
      occurred_at: new Date().toISOString(),
    });
  }

  private async currentDecisionId(): Promise<string> {
    if (!this.runState) return 'run';
    const decisions = await this.repos.agentDecisions.listByRun(this.runState.id, 1);
    return decisions[0]?.id ?? `${this.runState.id}:0`;
  }

  private async refreshRunMetrics(): Promise<void> {
    if (!this.runState || !this.engagement) return;
    const metrics = await this.metrics.collect(this.engagement.id);
    await this.repos.agentRuns.updateMetrics(this.runState.id, {
      cycles: this.cycleCount,
      tasks: metrics.tasks,
      hypotheses: metrics.hypotheses,
      tokens: metrics.tokens,
      workers: metrics.workers,
      runs: metrics.runs,
      observations: metrics.observations,
      findings: metrics.findings,
      tool_calls: metrics.tool_calls,
      network_requests: metrics.network_requests,
    });
  }

  private async waitForControlChange(): Promise<void> {
    const deadline = Date.now() + 2_000;
    while (this.control === 'pause-requested' && Date.now() < deadline) {
      await sleep(100);
    }
    if (this.control === 'running' && this.runState) {
      const current = await this.repos.agentRuns.findById(this.runState.id);
      if (current && current.status === 'PAUSED') {
        await this.repos.agentRuns.updateStatus(this.runState.id, 'RUNNING');
        await this.emitRunEvent('AGENT_RUN_RESUMED', {});
        this.runState = (await this.repos.agentRuns.findById(this.runState.id)) ?? this.runState;
      }
    }
  }
}

const sleep = (ms: number): Promise<void> => new Promise((resolve) => setTimeout(resolve, ms));

/** Type re-exports for composition roots. */
export type { EngagementUsageRecord, EngagementBudgetRecord, ScopeRecord };
