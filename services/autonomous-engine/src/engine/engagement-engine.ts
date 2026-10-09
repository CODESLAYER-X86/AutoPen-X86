/**
 * Engagement engine — the AutonomousEngine facade (spec Part 6 §1, §7-§9,
 * §73, §88).
 *
 * Implements the persistent, restartable loop:
 *
 *   OBSERVE -> MODEL -> HYPOTHESIZE -> PRIORITIZE -> PLAN -> VALIDATE ->
 *   EXECUTE -> OBSERVE -> COMPARE -> VERIFY -> UPDATE -> REPLAN
 *
 * The engine is DOMAIN-AWARE but EXECUTION-AGNOSTIC (§90): security
 * reasoning determines WHAT should be investigated; the deterministic
 * browser/HTTP/tooling layers determine HOW an authorized investigation is
 * performed. The LLM never constructs an unrestricted network operation:
 * every task flows through the Part 2 compiler + scheduler + gateway, with
 * scope, policy, quota and duplicate gates enforced at every layer (§47).
 */
import type { EngagementRecord, Repositories, TaskRecord } from '@aegis/database';
import type { PlatformEvent, TestCandidate } from '@aegis/contracts';
import type { EventBus } from '@aegis/events';
import type { Logger } from '@aegis/logging';
import type { AppConfig } from '@aegis/config';
import type { ToolRegistry } from '@aegis/tools';
import {
  AUTONOMOUS_TERMINAL_PHASES,
  generateId,
  type AutonomousMode,
  type ReplanTrigger,
  type StopReason,
} from '@aegis/shared';
import { TaskCompiler, HypothesisEngine } from '@aegis/agent';
import { LifecycleManager } from './lifecycle-manager.js';
import { LoopController } from './loop-controller.js';
import type { EngagementCompletionPort, KnowledgePort, ReasoningPort } from './ports.js';
import type { LoopLauncher } from '../execution/execution-controller.js';
import { ReconPlanner } from '../reconnaissance/recon-planner.js';
import { AuthDiscovery } from '../reconnaissance/auth-discovery.js';
import { HypothesisBridge } from '../reasoning/hypothesis-engine.js';
import { BranchManager } from '../reasoning/branch-manager.js';
import { StrategyEngine } from '../reasoning/strategy-engine.js';
import { TaskPlanner } from '../planning/task-planner.js';
import { WorkerDispatcher } from '../execution/worker-dispatcher.js';
import { ExecutionController } from '../execution/execution-controller.js';
import { RetryManager } from '../execution/retry-manager.js';
import { RecoveryManager } from '../execution/recovery-manager.js';
import { ObservationAnalyzer } from '../analysis/observation-analyzer.js';
import { DataflowAnalyzer } from '../analysis/dataflow-analyzer.js';
import { StateAnalyzer } from '../analysis/state-analyzer.js';
import { EvidenceCorrelator } from '../analysis/evidence-correlator.js';
import { Verifier } from '../verification/verifier.js';
import { CtfEngine } from '../ctf/ctf-engine.js';
import { StopEvaluator } from '../stopping/stop-evaluator.js';
import { CoverageEvaluator } from '../stopping/coverage-evaluator.js';
import { AttackSurfaceGraphProjector } from '../graph/attack-surface-graph.js';
import { TimelineBuilder } from '../timeline/timeline-builder.js';

export interface AutonomousEngineDeps {
  repos: Repositories;
  eventBus: EventBus;
  logger?: Pick<Logger, 'info' | 'warn' | 'debug'>;
  config: Pick<AppConfig, 'autonomous'>;
  /** Tool registry — the compiler reads default worker palettes from it. */
  tools: ToolRegistry;
  /** Part 4 reasoning engine (structural port). Required for reasoning. */
  reasoning: ReasoningPort;
  /** Part 5 knowledge engine (structural port). Optional. */
  knowledge?: KnowledgePort;
  /** Part 2 agent launcher bridge (registry in the composition root). */
  launcher: LoopLauncher;
  /** Engagement lifecycle completion (orchestrator bridge). */
  completion: EngagementCompletionPort;
  /** Model router is NOT used: the engine itself is model-free; the agent
   * loop makes every model call through the validated leader/worker path. */
}

export class AutonomousEngine {
  private readonly repos: Repositories;
  private readonly eventBus: EventBus;
  private readonly logger?: AutonomousEngineDeps['logger'];
  private readonly reasoning: ReasoningPort;
  readonly compiler: TaskCompiler;
  private readonly hypothesisEngine: HypothesisEngine;
  private readonly lifecycle: LifecycleManager;
  private readonly branches: BranchManager;
  private readonly bridge: HypothesisBridge;
  private readonly planner: TaskPlanner;
  private readonly dispatcher: WorkerDispatcher;
  private readonly execution: ExecutionController;
  private readonly retries: RetryManager;
  private readonly recovery: RecoveryManager;
  private readonly observationAnalyzer: ObservationAnalyzer;
  private readonly dataflow: DataflowAnalyzer;
  private readonly stateAnalyzer: StateAnalyzer;
  private readonly correlator: EvidenceCorrelator;
  private readonly verifier: Verifier;
  private readonly ctf: CtfEngine | null;
  private readonly strategy: StrategyEngine;
  private readonly stopEvaluator: StopEvaluator;
  private readonly coverageEvaluator: CoverageEvaluator;
  private readonly graphProjector: AttackSurfaceGraphProjector;
  private readonly timeline: TimelineBuilder;
  private readonly loops = new Map<string, LoopController>();
  private readonly activeRuns = new Map<string, Promise<void>>();

  constructor(private readonly deps: AutonomousEngineDeps) {
    this.repos = deps.repos;
    this.eventBus = deps.eventBus;
    this.logger = deps.logger;
    this.reasoning = deps.reasoning;
    const opts = deps.config.autonomous;

    this.compiler = new TaskCompiler({ repos: this.repos, tools: deps.tools, eventBus: this.eventBus });
    this.hypothesisEngine = new HypothesisEngine({
      hypotheses: this.repos.hypotheses,
      deadEnds: this.repos.deadEnds,
      findings: this.repos.findings,
      eventBus: this.eventBus,
    });
    this.lifecycle = new LifecycleManager({ repos: this.repos, eventBus: this.eventBus, logger: this.logger });
    this.branches = new BranchManager({ repos: this.repos, eventBus: this.eventBus }, { maxActive: opts.branchLimit });
    this.bridge = new HypothesisBridge({
      repos: this.repos,
      eventBus: this.eventBus,
      hypothesisEngine: this.hypothesisEngine,
      branchManager: this.branches,
      maxPerCycle: opts.hypothesisLimit,
    });
    this.planner = new TaskPlanner({ repos: this.repos, compiler: this.compiler, options: { batchLimit: opts.candidateBatch } });
    this.dispatcher = new WorkerDispatcher({ repos: this.repos, compiler: this.compiler, eventBus: this.eventBus });
    this.execution = new ExecutionController({ repos: this.repos }, { taskLeaseMs: opts.taskLeaseMs });
    this.retries = new RetryManager(this.repos, { maxRepeatsPerFingerprint: opts.stopMaxConsecutiveFailures });
    this.recovery = new RecoveryManager({ repos: this.repos, eventBus: this.eventBus }, { sweepIntervalMs: opts.leaseSweepIntervalMs });
    this.observationAnalyzer = new ObservationAnalyzer({ repos: this.repos, eventBus: this.eventBus, reasoning: this.reasoning });
    this.dataflow = new DataflowAnalyzer(this.repos);
    this.stateAnalyzer = new StateAnalyzer(this.repos);
    this.correlator = new EvidenceCorrelator(this.repos);
    this.verifier = new Verifier({
      repos: this.repos,
      eventBus: this.eventBus,
      reasoning: this.reasoning,
      hypothesisEngine: this.hypothesisEngine,
      branchManager: this.branches,
    });
    // CTF reasoning works without live knowledge retrieval — the riddle
    // engine and flag conditions are deterministic; challenge memory is an
    // optional corroborator (§34).
    this.ctf = new CtfEngine({
      repos: this.repos,
      eventBus: this.eventBus,
      knowledge: deps.knowledge,
      hypothesisEngine: this.hypothesisEngine,
      branchManager: this.branches,
      flagPatterns: opts.flagPatterns,
      maxHypotheses: opts.hypothesisLimit,
    });
    this.strategy = new StrategyEngine(this.repos, {
      reconShare: opts.budgetReconShare,
      testingShare: opts.budgetTestingShare,
    });
    this.stopEvaluator = new StopEvaluator(
      { repos: this.repos, eventBus: this.eventBus },
      {
        minTests: opts.stopMinTests,
        minInformationGain: opts.stopMinInformationGain,
        maxConsecutiveFailures: opts.stopMaxConsecutiveFailures,
      },
    );
    this.coverageEvaluator = new CoverageEvaluator({ repos: this.repos, eventBus: this.eventBus });
    this.graphProjector = new AttackSurfaceGraphProjector(this.repos);
    this.timeline = new TimelineBuilder(this.repos);
  }

  // -------------------------------------------------------------------------
  // §73 AutonomousEngine interface
  // -------------------------------------------------------------------------

  /**
   * Start (or resume) the autonomous engine for an engagement (§9):
   * validate scope -> load targets/identities -> initialize sessions ->
   * passive + active discovery -> application mapping -> hypotheses.
   * Existing non-terminal state RESUMES (§1 restartable).
   */
  async start(engagement: EngagementRecord, actorId: string | null, reason?: string): Promise<{ stateId: string }> {
    const mode: AutonomousMode =
      engagement.mode === 'CTF' ? 'CTF_MODE' : 'PENTEST_MODE';
    const state = await this.lifecycle.initialize(engagement.id, mode);
    if (state && AUTONOMOUS_TERMINAL_PHASES.includes(state.phase)) {
      await this.lifecycle.force(engagement.id, 'INITIALIZING', { actorId });
    }

    // Crash recovery (§54): recover incomplete tasks from dead runs.
    await this.recovery.recoverIncomplete(engagement.id);

    // CREATED -> INITIALIZING (no-op when already initializing/resumed).
    await this.lifecycle.transitionIf(engagement.id, 'CREATED', 'INITIALIZING', { actorId });
    // CTF mode: ingest the challenge first (§4, §63).
    if (engagement.mode === 'CTF' && this.ctf) {
      await this.ctf.initialize(engagement, {});
    }

    // INITIALIZING -> RECON (the engine always starts the pipeline at recon;
    // resumed engagements re-enter through the persisted strategy state).
    await this.lifecycle.force(engagement.id, 'RECON', { actorId, strategySummary: 'initial recon (§9)' });

    await this.publishEngineStarted(engagement.id, mode, reason ?? null);

    // Launch the agent run FIRST (tasks reference the run id), then enqueue
    // the deterministic recon plan (§9).
    const { runId } = await this.execution.launchRun(this.deps.launcher, engagement, actorId, reason ?? 'autonomous engine start');
    this.trackRun(engagement, runId);

    const targets = await this.repos.targets.listByEngagement(engagement.id);
    const identities = await this.repos.identities.listByEngagement(engagement.id);
    const reconPlanner = new ReconPlanner({
      maxTasks: this.deps.config.autonomous.reconMaxTasks,
      maxPathsPerTarget: this.deps.config.autonomous.reconMaxPathsPerTarget,
    });
    const plan = await reconPlanner.plan({ engagement, targets, identities });
    const reconTasks = await this.dispatcher.enqueueReconTasks(
      engagement.id,
      runId,
      plan.tasks.map((task) => this.reconSpec(task)),
      'INITIAL',
    );
    await this.publishReconStarted(engagement.id, reconTasks.length, runId);

    this.startLoop(engagement.id);
    return { stateId: state?.id ?? 'AEN_RESUMED' };
  }

  async pause(engagementId: string, actorId: string | null, reason?: string): Promise<void> {
    await this.deps.launcher.pause(engagementId, actorId, reason ?? 'autonomous engine paused');
    await this.lifecycle.force(engagementId, 'WAITING_FOR_USER', { actorId, waitingReason: reason ?? 'paused by user' });
    await this.publishEngineEvent(engagementId, 'AUTONOMOUS_ENGINE_PAUSED', { reason: reason ?? 'paused by user' });
    this.stopLoop(engagementId);
  }

  async resume(engagementId: string, actorId: string | null): Promise<void> {
    const engagement = await this.repos.engagements.findById(engagementId);
    if (!engagement) return;
    await this.deps.launcher.resume(engagementId, actorId);
    await this.lifecycle.force(engagementId, 'REPLANNING', { actorId, waitingReason: null });
    await this.publishEngineEvent(engagementId, 'AUTONOMOUS_ENGINE_RESUMED', {});
    this.startLoop(engagementId);
    // Resume from persisted state (§1 restartable).
    await this.maintenanceTick(engagementId);
  }

  async cancel(engagementId: string, actorId: string | null, reason?: string): Promise<void> {
    await this.deps.launcher.cancel(engagementId, actorId, reason ?? 'autonomous engine cancelled');
    this.stopLoop(engagementId);
    await this.lifecycle.force(engagementId, 'CANCELLED', { actorId, stopReason: 'USER_STOP' });
  }

  /**
   * Replan (§64, §73): recompute strategy from the CURRENT evidence and
   * re-enter the testing phase with a fresh candidate batch.
   */
  async replan(engagementId: string, trigger: ReplanTrigger = 'MANUAL'): Promise<{ replanCount: number }> {
    const state = await this.lifecycle.get(engagementId);
    if (!state || AUTONOMOUS_TERMINAL_PHASES.includes(state.phase)) {
      return { replanCount: state?.replan_count ?? 0 };
    }
    const strategyPriorities = await this.strategy.replan(engagementId, trigger);
    const count = await this.lifecycle.recordReplan(engagementId, trigger);
    await this.lifecycle.force(engagementId, 'REPLANNING', {
      strategySummary: strategyPriorities.rationale.slice(0, 500),
    });
    await this.repos.strategies
      .createNext({
        engagementId,
        runId: null,
        summary: strategyPriorities.rationale.slice(0, 2000),
        focus: strategyPriorities.priorities.join(', '),
        reason: `replan:${trigger}`,
      })
      .catch(() => undefined);
    await this.maintenanceTick(engagementId);
    return { replanCount: count };
  }

  // -------------------------------------------------------------------------
  // Event + maintenance plumbing (§7-§8)
  // -------------------------------------------------------------------------

  /** Handle a platform event for an engagement (loop-controller callback). */
  async handlePlatformEvent(engagementId: string, event: PlatformEvent): Promise<void> {
    const state = await this.lifecycle.get(engagementId);
    if (!state || AUTONOMOUS_TERMINAL_PHASES.includes(state.phase)) return;

    if (event.type === 'TASK_COMPLETED' || event.type === 'TASK_FAILED') {
      if (event.task_id) {
        const task = await this.repos.tasks.findById(event.task_id);
        if (task) {
          if (event.type === 'TASK_FAILED') {
            await this.retries.recordFailure(task, task.failure_code).catch(() => undefined);
          }
          await this.observationAnalyzer.analyzeTaskCompletion(engagementId, task).catch(() => undefined);
          if (this.ctf) {
            await this.ctf.scanForFlag(engagementId).catch(() => undefined);
          }
        }
      }
      await this.advancePhase(engagementId);
    } else if (event.type === 'REASONING_INGEST_COMPLETED') {
      await this.advancePhase(engagementId);
    } else if (event.type === 'HYPOTHESIS_UPDATED') {
      // §7 loop: hypothesis update -> verification evaluation.
      const hypothesisId = typeof event.payload?.hypothesis_id === 'string' ? event.payload.hypothesis_id : null;
      if (hypothesisId) {
        await this.verifier.verifyAndBridge(engagementId, hypothesisId).catch(() => undefined);
      }
    } else if (event.type === 'VERIFICATION_COMPLETED') {
      await this.advancePhase(engagementId);
    } else if (event.type === 'AGENT_RUN_COMPLETED' || event.type === 'AGENT_RUN_FAILED') {
      await this.maintenanceTick(engagementId);
    }
  }

  /**
   * Maintenance tick (§8 fallback + §55 lease sweep + §50 stop evaluation).
   */
  async maintenanceTick(engagementId: string): Promise<void> {
    const engagement = await this.repos.engagements.findById(engagementId);
    if (!engagement || engagement.status !== 'RUNNING') return;
    const state = await this.lifecycle.get(engagementId);
    if (!state || AUTONOMOUS_TERMINAL_PHASES.includes(state.phase)) return;

    // §55 lease sweep.
    await this.recovery.sweep(engagementId).catch(() => undefined);

    // CTF flag scan (§31) on every tick.
    if (this.ctf) {
      const solved = await this.ctf.scanForFlag(engagementId).catch(() => false);
      if (solved) {
        await this.finish(engagement, 'COMPLETED', 'OBJECTIVE_COMPLETED', 'challenge solved (§31)');
        return;
      }
    }

    // §50 stop evaluation.
    const coverage = await this.coverageEvaluator.evaluate(engagementId).catch(() => null);
    const decision = await this.stopEvaluator.evaluate(engagement, coverage);
    if (decision.shouldStop) {
      await this.stopEvaluator.publish(engagementId, decision.reason!, decision.detail);
      await this.finish(engagement, decision.reason === 'OBJECTIVE_COMPLETED' ? 'COMPLETED' : 'STOPPED', decision.reason!, decision.detail);
      return;
    }

    // Phase advancement (deterministic rules).
    await this.advancePhase(engagementId);

    // §1 persistent loop: if no agent run is active but work remains (or the
    // engine has not exhausted replans), relaunch the run.
    await this.ensureRunActive(engagement);
  }

  // -------------------------------------------------------------------------
  // Deterministic phase advancement (§6, §9, §62)
  // -------------------------------------------------------------------------

  private async advancePhase(engagementId: string): Promise<void> {
    const state = await this.lifecycle.get(engagementId);
    if (!state) return;
    const phase = state.phase;
    if (AUTONOMOUS_TERMINAL_PHASES.includes(phase) || phase.startsWith('WAITING_FOR')) return;

    const pending = await this.pendingTasks(engagementId);
    const tasks = await this.repos.tasks.listByEngagement(engagementId, { limit: 200 });
    const completedCount = tasks.filter((t) => t.status === 'COMPLETED' || t.status === 'PARTIAL').length;

    if (phase === 'RECON') {
      const reconOutstanding = pending.filter(
        (t) => t.type === 'RECON' || t.type === 'BROWSER_INVESTIGATION' || t.type === 'AUTHENTICATION_ANALYSIS',
      );
      const endpoints = await this.repos.endpoints.listByEngagement(engagementId, { limit: 1 });
      if (reconOutstanding.length === 0 && (completedCount > 0 || endpoints.length > 0)) {
        // §9: baseline established -> model the attack surface.
        await this.reasoning.ingest(engagementId).catch(() => undefined);
        await this.lifecycle.transitionIf(engagementId, 'RECON', 'MODELING', {});
        await this.publishReconCompleted(engagementId);
      }
      return;
    }

    if (phase === 'MODELING') {
      // §14: consume hypothesis candidates -> hypotheses + branches.
      const groups = await this.reasoning.hypothesisCandidates(engagementId).catch(() => []);
      const result = await this.bridge.consumeCandidates(engagementId, groups);
      if (result.hypothesesCreated > 0 || groups.length === 0) {
        await this.reasoning.markSignalsConsumed(result.signalIdsConsumed).catch(() => undefined);
        await this.lifecycle.transitionIf(engagementId, 'MODELING', 'HYPOTHESIS_GENERATION', {});
      }
      return;
    }

    if (phase === 'HYPOTHESIS_GENERATION') {
      // §38: compile the next batch of test candidates.
      const runId = await this.currentRunId(engagementId);
      if (!runId) return;
      const candidates = await this.reasoning.testCandidates(engagementId).catch(() => ({ items: [] as TestCandidate[], total: 0 }));
      const batch = await this.planner.compileCandidates(engagementId, runId, candidates.items);
      if (batch.tasks.length > 0) {
        await this.lifecycle.transitionIf(engagementId, 'HYPOTHESIS_GENERATION', 'TESTING', {});
      } else if (pending.length === 0) {
        // No candidates — skip to analysis (§6 alternative path).
        await this.lifecycle.transitionIf(engagementId, 'HYPOTHESIS_GENERATION', 'ANALYSIS', {});
      }
      return;
    }

    if (phase === 'TESTING') {
      const testingPending = pending.filter((t) => t.type !== 'VERIFICATION');
      if (testingPending.length === 0 && completedCount > 0) {
        await this.lifecycle.transitionIf(engagementId, 'TESTING', 'ANALYSIS', {});
      }
      return;
    }

    if (phase === 'ANALYSIS') {
      // §25: correlate evidence; §26: queue verification for SUPPORTED.
      const queue = await this.verifier.verificationQueue(engagementId).catch(() => [] as string[]);
      if (queue.length > 0) {
        await this.lifecycle.transitionIf(engagementId, 'ANALYSIS', 'VERIFICATION', {});
      } else if (pending.length === 0) {
        await this.lifecycle.transitionIf(engagementId, 'ANALYSIS', 'REPLANNING', {});
      }
      return;
    }

    if (phase === 'VERIFICATION') {
      const queue = await this.verifier.verificationQueue(engagementId).catch(() => [] as string[]);
      const verificationPending = pending.filter((t) => t.type === 'VERIFICATION');
      if (queue.length === 0 && verificationPending.length === 0) {
        await this.pruneBranches(engagementId);
        await this.lifecycle.transitionIf(engagementId, 'VERIFICATION', 'REPLANNING', {});
      }
      return;
    }

    if (phase === 'REPLANNING') {
      // §64: continue the cycle — new candidates? new verification work?
      const state2 = await this.lifecycle.get(engagementId);
      const replans = state2?.replan_count ?? 0;
      const queue = await this.verifier.verificationQueue(engagementId).catch(() => [] as string[]);
      if (queue.length > 0) {
        await this.lifecycle.transitionIf(engagementId, 'REPLANNING', 'VERIFICATION', {});
        return;
      }
      if (replans < this.deps.config.autonomous.maxReplans) {
        await this.lifecycle.transitionIf(engagementId, 'REPLANNING', 'HYPOTHESIS_GENERATION', {});
      } else if (pending.length === 0) {
        // Replan budget exhausted (§42 stop or downgrade).
        await this.finishEngagementIfQuiet(engagementId);
      }
      return;
    }
  }

  // -------------------------------------------------------------------------
  // Human interventions (§48)
  // -------------------------------------------------------------------------

  /** Prioritize a hypothesis (§48: leader receives the user's signal). */
  async prioritizeHypothesis(engagementId: string, hypothesisId: string, note?: string): Promise<boolean> {
    const hypothesis = await this.repos.hypotheses.findByIdAndEngagement(hypothesisId, engagementId);
    if (!hypothesis) return false;
    await this.repos.hypotheses
      .update(hypothesisId, { priority: Math.min(1, hypothesis.priority + 0.3) })
      .catch(() => undefined);
    await this.publishEngineEvent(engagementId, 'HUMAN_OVERRIDE', {
      kind: 'PRIORITIZE_HYPOTHESIS',
      hypothesis_id: hypothesisId,
      ...(note ? { note } : {}),
    });
    return true;
  }

  /** §48 approve: a WAITING (user-approval) task resumes as READY. */
  async approveTask(engagementId: string, taskId: string, actorId: string | null, reason?: string): Promise<boolean> {
    const task = await this.repos.tasks.findByIdAndEngagement(taskId, engagementId);
    if (!task || task.status !== 'WAITING') return false;
    const updated = await this.repos.tasks.updateStatus(taskId, 'READY');
    if (!updated) return false;
    await this.publishEngineEvent(engagementId, 'APPROVAL_DECIDED', {
      task_id: taskId,
      decision: 'APPROVED',
      actor_id: actorId,
      ...(reason ? { reason } : {}),
    });
    await this.recordApprovalDecision(engagementId, taskId, 'APPROVED', actorId, reason);
    return true;
  }

  /** §48 reject: the task is cancelled (with dependents cascade by the scheduler path). */
  async rejectTask(engagementId: string, taskId: string, actorId: string | null, reason?: string): Promise<boolean> {
    const task = await this.repos.tasks.findByIdAndEngagement(taskId, engagementId);
    if (!task) return false;
    const updated = await this.repos.tasks.updateStatus(taskId, 'CANCELLED');
    if (!updated) return false;
    await this.repos.tasks.releaseLease(taskId).catch(() => undefined);
    await this.publishEngineEvent(engagementId, 'APPROVAL_DECIDED', {
      task_id: taskId,
      decision: 'REJECTED',
      actor_id: actorId,
      ...(reason ? { reason } : {}),
    });
    await this.recordApprovalDecision(engagementId, taskId, 'REJECTED', actorId, reason);
    return true;
  }

  // -------------------------------------------------------------------------
  // Read models (§52 dashboard, §53 timeline, §72 API)
  // -------------------------------------------------------------------------

  async graph(engagementId: string) {
    return this.graphProjector.project(engagementId);
  }

  async timelineView(engagementId: string, limit?: number) {
    return this.timeline.build(engagementId, limit ?? this.deps.config.autonomous.timelineLimit);
  }

  async coverage(engagementId: string) {
    return this.coverageEvaluator.evaluate(engagementId);
  }

  async engineState(engagementId: string) {
    return this.lifecycle.get(engagementId);
  }

  async pendingApproval(engagementId: string, taskId: string) {
    return this.repos.approvals.findPendingForTask(taskId);
  }

  async createApproval(input: {
    engagementId: string;
    taskId: string;
    risk: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
    actionSummary: string;
    metadata?: Record<string, unknown>;
  }) {
    const approval = await this.repos.approvals.create(input);
    await this.publishEngineEvent(input.engagementId, 'APPROVAL_REQUESTED', {
      approval_id: approval.id,
      task_id: input.taskId,
      risk: input.risk,
      action_summary: input.actionSummary,
    });
    return approval;
  }

  async verificationQueue(engagementId: string) {
    return this.verifier.verificationQueue(engagementId);
  }

  async workflowQuestions(engagementId: string) {
    return this.stateAnalyzer.questions(engagementId);
  }

  async dataFlowInsights(engagementId: string) {
    return this.dataflow.insights(engagementId);
  }

  async sessionRequirements(engagementId: string) {
    return new AuthDiscovery(this.repos).sessionRequirements(engagementId);
  }

  loopFor(engagementId: string): LoopController | undefined {
    return this.loops.get(engagementId);
  }

  /** CTF engine accessor (routes expose CTF context/clue management). */
  get ctfEngine(): CtfEngine | null {
    return this.ctf;
  }

  // -------------------------------------------------------------------------
  // Internals
  // -------------------------------------------------------------------------

  private startLoop(engagementId: string): void {
    const existing = this.loops.get(engagementId);
    if (existing?.isRunning) return;
    const loop = new LoopController(this, this.eventBus, {
      maintenanceIntervalMs: this.deps.config.autonomous.maintenanceIntervalMs,
    }, this.logger);
    this.loops.set(engagementId, loop);
    loop.start(engagementId);
  }

  private stopLoop(engagementId: string): void {
    this.loops.get(engagementId)?.stop(engagementId);
    this.loops.delete(engagementId);
  }

  private trackRun(engagement: EngagementRecord, runId: string): void {
    void runId;
    void engagement;
  }

  private async currentRunId(engagementId: string): Promise<string | null> {
    const active = await this.repos.agentRuns.findActiveByEngagement(engagementId);
    return active?.id ?? null;
  }

  private async pendingTasks(engagementId: string): Promise<TaskRecord[]> {
    return this.repos.tasks.listByEngagement(engagementId, {
      statuses: ['CREATED', 'QUEUED', 'READY', 'RUNNING', 'WAITING', 'RECOVERY_PENDING'],
      limit: 200,
    });
  }

  private async ensureRunActive(engagement: EngagementRecord): Promise<void> {
    const active = await this.repos.agentRuns.findActiveByEngagement(engagement.id);
    if (active) return;
    const pending = await this.pendingTasks(engagement.id);
    if (pending.length === 0) return;
    // Work remains but no run is driving it (§1 restartable loop).
    const { runId } = await this.execution.launchRun(this.deps.launcher, engagement, null, 'engine restart: pending work without an active run');
    void runId;
  }

  private async finishEngagementIfQuiet(engagementId: string): Promise<void> {
    const pending = await this.pendingTasks(engagementId);
    if (pending.length > 0) return;
    const engagement = await this.repos.engagements.findById(engagementId);
    if (!engagement) return;
    const coverage = await this.coverageEvaluator.evaluate(engagementId).catch(() => null);
    const decision = await this.stopEvaluator.evaluate(engagement, coverage);
    if (decision.shouldStop) {
      await this.finish(engagement, decision.reason === 'OBJECTIVE_COMPLETED' ? 'COMPLETED' : 'STOPPED', decision.reason!, decision.detail);
    }
  }

  private async finish(
    engagement: EngagementRecord,
    phase: 'COMPLETED' | 'STOPPED',
    reason: StopReason,
    detail: string,
  ): Promise<void> {
    this.stopLoop(engagement.id);
    await this.lifecycle.force(engagement.id, phase, { stopReason: reason });
    await this.publishEngineEvent(engagement.id, 'AUTONOMOUS_ENGINE_STOPPED', { phase, reason, detail });
    if (phase === 'COMPLETED') {
      await this.deps.completion.complete(engagement.id, null, `${reason}: ${detail}`).catch(() => undefined);
    }
  }

  private async pruneBranches(engagementId: string): Promise<void> {
    await this.branches.pruneDisproved(engagementId).catch(() => undefined);
  }

  private reconSpec(task: import('@aegis/contracts').ReconPlanTask): import('@aegis/contracts').LeaderTaskSpec {
    return {
      objective: task.objective,
      task_type: task.task_type as import('@aegis/shared').TaskType,
      worker_type: task.worker_type,
      identity_id: task.identity_id ?? undefined,
      expected_information_gain: task.expected_information_gain,
      potential_impact: 0.5,
      depends_on: [],
      inputs: {
        mode: 'RECON',
        stage: task.stage,
        reason: task.reason,
        paths: task.paths,
        instruction:
          task.stage === 'ACTIVE_DISCOVERY'
            ? 'Probe ONLY the listed paths with plain GET requests. Record status, content type and redirects. Do NOT attempt payloads or mutations (§11 bounded discovery).'
            : task.stage === 'SESSION_INIT'
              ? 'Complete the login workflow for this identity using registered credentials via the browser, capture the session, and verify authenticated access to a known endpoint.'
              : 'Observe and record. Do not mutate anything (§10 passive discovery).',
      },
      allowed_tools:
        task.worker_type === 'BROWSER_WORKER'
          ? ['browser.navigate', 'browser.capture_state', 'browser.snapshot', 'browser.submit', 'browser.click', 'browser.fill', 'http.request']
          : task.worker_type === 'HTTP_WORKER'
            ? ['http.request', 'http.replay', 'diff.response', 'reasoning.query']
            : ['reasoning.query', 'diff.response', 'parser.html', 'parser.json'],
      constraints: { max_tool_calls: 10, max_network_requests: 12, max_duration_seconds: 150 },
      target_hint: task.target_hint ?? undefined,
    };
  }

  private async recordApprovalDecision(
    engagementId: string,
    taskId: string,
    decision: 'APPROVED' | 'REJECTED',
    actorId: string | null,
    reason?: string,
  ): Promise<void> {
    const pendingApproval = await this.repos.approvals.findPendingForTask(taskId);
    if (pendingApproval) {
      await this.repos.approvals.decide(pendingApproval.id, decision, actorId ?? 'user', reason ?? null);
    } else {
      // Retroactive record: create the row AND decide it (exactly once, §49).
      await this.repos.approvals
        .create({
          engagementId,
          taskId,
          risk: 'HIGH',
          actionSummary: `task ${taskId} decision (retroactive record)`,
          requestedBy: 'engine',
          metadata: { retroactive: true },
        })
        .then((approval) => this.repos.approvals.decide(approval.id, decision, actorId ?? 'user', reason ?? null))
        .catch(() => undefined);
    }
  }

  private async publishEngineStarted(engagementId: string, mode: AutonomousMode, reason: string | null): Promise<void> {
    const event: PlatformEvent = {
      type: 'AUTONOMOUS_ENGINE_STARTED',
      engagement_id: engagementId,
      trace_id: generateId('TRC'),
      actor_id: null,
      payload: { mode, ...(reason ? { reason } : {}) },
      occurred_at: new Date().toISOString(),
      dedup_key: `engine-started:${engagementId}:${Date.now()}`,
    };
    await this.eventBus.publish(event).catch(() => undefined);
  }

  private async publishReconStarted(engagementId: string, tasks: number, runId: string): Promise<void> {
    const event: PlatformEvent = {
      type: 'RECON_PIPELINE_STARTED',
      engagement_id: engagementId,
      trace_id: generateId('TRC'),
      actor_id: null,
      payload: { tasks, run_id: runId },
      occurred_at: new Date().toISOString(),
      dedup_key: `recon-started:${engagementId}:${runId}`,
    };
    await this.eventBus.publish(event).catch(() => undefined);
  }

  private async publishReconCompleted(engagementId: string): Promise<void> {
    const event: PlatformEvent = {
      type: 'RECON_PIPELINE_COMPLETED',
      engagement_id: engagementId,
      trace_id: generateId('TRC'),
      actor_id: null,
      payload: {},
      occurred_at: new Date().toISOString(),
      dedup_key: `recon-completed:${engagementId}`,
    };
    await this.eventBus.publish(event).catch(() => undefined);
  }

  private async publishEngineEvent(engagementId: string, type: string, payload: Record<string, unknown>): Promise<void> {
    const event: PlatformEvent = {
      type: type as PlatformEvent['type'],
      engagement_id: engagementId,
      trace_id: generateId('TRC'),
      actor_id: typeof payload.actor_id === 'string' ? payload.actor_id : null,
      payload,
      occurred_at: new Date().toISOString(),
      dedup_key: `engine:${type}:${engagementId}:${Date.now()}`,
    };
    await this.eventBus.publish(event).catch(() => undefined);
  }
}
