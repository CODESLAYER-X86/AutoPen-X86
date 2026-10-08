/**
 * Agent integration-test helpers: build a REAL AgentLoopEngine against the
 * real test database with SCRIPTED mock model providers. No external target,
 * no network — deterministic simulation (spec Part 2 §72-§73).
 */
import { createPool, createRepositories, type Repositories } from '@aegis/database';
import { PersistingEventBus, InMemoryEventBus, type EventBus } from '@aegis/events';
import { MockModelProvider, type MockHandler } from '@aegis/model-runtime';
import { createDefaultToolRegistry, ToolGateway, ToolRegistry } from '@aegis/tools';
import { TacticalWorkerRuntime } from '@aegis/worker-runtime';
import { AgentLoopEngine, QuotaManager, TokenBudgeter, type LoopOptions } from '@aegis/agent';
import { createLogger, createMemorySink, type Logger } from '@aegis/logging';
import { OrchestratorService } from '@aegis/orchestrator';
import { hashPassword } from '@aegis/security';

export const TEST_DB_URL =
  process.env.TEST_DATABASE_URL ?? 'postgres://postgres:postgres@127.0.0.1:5433/aegis_test';

export interface AgentTestContext {
  pool: ReturnType<typeof createPool>;
  repos: Repositories;
  eventBus: EventBus;
  logger: Logger;
  logLines: string[];
  toolRegistry: ToolRegistry;
  toolGateway: ToolGateway;
  strategic: MockModelProvider;
  tactical: MockModelProvider;
  /** Scripted leader decision sequence (one entry per leader call). */
  strategicScript: unknown[];
  tacticalScript: unknown[];
  strategicCalls: { system?: string; user: string }[];
  tacticalCalls: { system?: string; user: string }[];
  /** Shared quota manager (exposed for quota-pressure simulation). */
  quota: QuotaManager;
  /** A fresh engine per test (one run per engine instance). */
  newEngine: () => AgentLoopEngine;
  engine: AgentLoopEngine;
  orchestrator: OrchestratorService;
  close: () => Promise<void>;
}

export interface CreateAgentContextOptions {
  loop?: Partial<LoopOptions>;
  quota?: ConstructorParameters<typeof QuotaManager>[0];
}

/** Scripted strategic provider: pops the next scripted decision as JSON. */
function strategicHandler(ctx: {
  script: unknown[];
  calls: { system?: string; user: string }[];
}): MockHandler {
  return (request) => {
    ctx.calls.push({ system: request.system, user: request.messages[0]?.content ?? '' });
    const next = ctx.script.shift();
    if (next === undefined) {
      // Exhausted script: stop the run so tests never loop forever.
      return JSON.stringify({
        decision: 'STOP',
        reasoning_summary: 'script exhausted; stopping for test determinism',
        objective_satisfied: true,
      });
    }
    if (next instanceof Error) throw next;
    return typeof next === 'string' ? next : JSON.stringify(next);
  };
}

/** Scripted tactical provider: extracts the task id from the prompt. */
function tacticalHandler(ctx: {
  script: unknown[];
  calls: { system?: string; user: string }[];
}): MockHandler {
  return (request) => {
    const user = request.messages[request.messages.length - 1]?.content ?? '';
    ctx.calls.push({ system: request.system, user });
    // The task id lives in the ORIGINAL packet prompt (first user message);
    // later turns are tool results / feedback without it.
    const firstUser = request.messages.find((m) => m.role === 'user')?.content ?? '';
    const extractTaskId = (): string | undefined =>
      /id: (TSK_[A-Z2-7]+)/.exec(firstUser)?.[1] ?? /id: (TSK_[A-Z2-7]+)/.exec(user)?.[1];
    const next = ctx.script.shift();
    if (next === undefined) {
      const taskId = extractTaskId() ?? 'TSK_SCRIPT_EXHAUSTED';
      return JSON.stringify({
        type: 'FINAL',
        result: {
          task_id: taskId,
          status: 'COMPLETED',
          observations: [],
          evidence_ids: [],
          hypothesis_updates: [],
        },
      });
    }
    if (next instanceof Error) throw next;
    if (typeof next === 'string') return next;
    if ((next as { type?: string }).type === 'TOOL_CALL' || (next as { type?: string }).type === 'FINAL') {
      const copy = { ...(next as Record<string, unknown>) };
      // Inject the real task id for FINAL results that reference the script.
      if (copy.type === 'FINAL') {
        const result = copy.result as Record<string, unknown> | undefined;
        const taskId = extractTaskId();
        if (result && taskId && result.task_id === 'AUTO') result.task_id = taskId;
      }
      return JSON.stringify(copy);
    }
    // Assume a worker-output object: wrap it as a FINAL turn.
    const result = { ...(next as Record<string, unknown>) };
    const taskId = extractTaskId();
    if (taskId && (!result.task_id || result.task_id === 'AUTO')) result.task_id = taskId;
    return JSON.stringify({ type: 'FINAL', result });
  };
}

export async function createAgentTestContext(
  options: CreateAgentContextOptions = {},
): Promise<AgentTestContext> {
  const pool = createPool(TEST_DB_URL, { max: 5 });
  const repos = createRepositories(pool);
  const memory = createMemorySink();
  const logger = createLogger({ level: 'info', sink: memory.sink });
  const eventBus = new PersistingEventBus(new InMemoryEventBus(), async (event) => {
    await repos.events.insert(event);
  });

  const toolRegistry = createDefaultToolRegistry();
  const toolGateway = new ToolGateway(toolRegistry);

  const strategicCalls: { system?: string; user: string }[] = [];
  const tacticalCalls: { system?: string; user: string }[] = [];
  const strategicScript: unknown[] = [];
  const tacticalScript: unknown[] = [];

  const strategic = new MockModelProvider(
    'mock-strategic-test',
    strategicHandler({ script: strategicScript, calls: strategicCalls }),
  );
  const tactical = new MockModelProvider(
    'mock-tactical-test',
    tacticalHandler({ script: tacticalScript, calls: tacticalCalls }),
  );

  const workerRuntime = new TacticalWorkerRuntime({
    provider: tactical,
    repos,
    eventBus,
    toolRegistry: {
      get: (name) => {
        const tool = toolRegistry.get(name);
        return tool ? { description: tool.description, implemented: tool.implemented } : null;
      },
    },
    options: { maxTurns: 6, maxInvalidTurns: 2, retryAttempts: 2 },
  });

  const quota = new QuotaManager(options.quota);
  const tokenBudgets = new TokenBudgeter();

  const buildEngine = (): AgentLoopEngine =>
    new AgentLoopEngine({
      repos,
      eventBus,
      logger,
      models: { strategic, tactical },
      tools: toolRegistry,
      toolGateway,
      workerRuntime,
      quota,
      tokenBudgets,
      options: {
        maxCycles: 12,
        maxIdleCycles: 2,
        idleBackoffMs: 5,
        maxWaitMs: 60,
        ...options.loop,
      },
    });
  const engine = buildEngine();

  const orchestrator = new OrchestratorService({
    engagements: repos.engagements,
    targets: repos.targets,
    scope: repos.scope,
    events: repos.events,
    audit: repos.audit,
    eventBus,
    logger,
  });
  const bindController = (target: AgentLoopEngine): void => {
    target.setEngagementController({
      complete: async (engagementId, actorId) => {
        const engagement = await repos.engagements.findById(engagementId);
        if (engagement) await orchestrator.complete(engagement, actorId);
      },
      fail: async (engagementId, actorId, reason) => {
        const engagement = await repos.engagements.findById(engagementId);
        if (engagement) await orchestrator.fail(engagement, actorId, reason);
      },
    });
  };
  bindController(engine);

  return {
    pool,
    repos,
    eventBus,
    logger,
    logLines: memory.lines,
    toolRegistry,
    toolGateway,
    strategic,
    tactical,
    strategicScript,
    tacticalScript,
    strategicCalls,
    tacticalCalls,
    quota,
    newEngine: () => {
      const fresh = buildEngine();
      bindController(fresh);
      return fresh;
    },
    engine,
    orchestrator,
    close: async () => {
      await pool.end();
    },
  };
}

/** Seeds a user/project/engagement/scope/target and starts the engagement. */
export async function seedEngagement(
  ctx: AgentTestContext,
  options: { mode?: 'PENTEST' | 'CTF'; description?: string } = {},
): Promise<{ engagementId: string; engagement: import('@aegis/database').EngagementRecord }> {
  const email = `agent-${Date.now()}-${Math.random().toString(36).slice(2, 8)}@test.local`;
  const user = await ctx.repos.users.create({
    email,
    name: 'Agent Tester',
    passwordHash: hashPassword('password1234'),
  });
  const project = await ctx.repos.projects.create({
    ownerId: user.id,
    name: 'Agent Test Project',
    description: 'project for agent integration tests',
  });
  const engagement = await ctx.repos.engagements.create({
    projectId: project.id,
    name: 'Agent Test Engagement',
    mode: options.mode ?? 'PENTEST',
    description: options.description ?? 'Determine whether object authorization is enforced.',
  });
  await ctx.repos.scope.upsert(engagement.id, {
    allowed_hosts: ['app.internal'],
    allowed_domains: [],
    allowed_ports: [8080],
    allowed_schemes: ['http'],
    excluded_hosts: [],
    excluded_paths: [],
    rate_limit: null,
    concurrency_limit: null,
    destructive_actions_allowed: false,
  });
  await ctx.repos.targets.create({
    engagementId: engagement.id,
    type: 'URL',
    value: 'http://app.internal:8080/',
    label: null,
    metadata: {},
  });
  await ctx.orchestrator.start(engagement, null);
  const current = (await ctx.repos.engagements.findById(engagement.id))!;
  return { engagementId: engagement.id, engagement: current };
}

export async function startRun(
  ctx: AgentTestContext,
  engagement: NonNullable<Awaited<ReturnType<Repositories['engagements']['findById']>>>,
  engine?: AgentLoopEngine,
): Promise<ReturnType<AgentLoopEngine['start']>> {
  const target = engine ?? ctx.engine;
  return target.start(engagement, {
    leaderModel: 'mock-strategic-test',
    workerModel: 'mock-tactical-test',
    reason: 'integration test',
  });
}
