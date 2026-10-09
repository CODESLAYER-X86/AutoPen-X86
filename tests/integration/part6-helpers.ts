/**
 * Part 6 integration helpers: composes the autonomous engine over the real
 * interaction + reasoning stack (Part 3/4 helpers). The agent-run launcher
 * is a recording stub — task EXECUTION belongs to the Part 2 loop tests;
 * Part 6 tests drive the ENGINE's deterministic layers (phases, candidates,
 * verification bridge, CTF reasoning, recovery, approvals) over real DB
 * state and real recorded lab traffic.
 */
import type { Pool } from 'pg';
import type { Repositories, EngagementRecord } from '@aegis/database';
import { AutonomousEngine } from '@aegis/autonomous';
import { createDefaultToolRegistry } from '@aegis/tools';
import { buildReasoningStack, type ReasoningStack } from './part4-helpers.js';
import { hashPassword } from '@aegis/security';
import { loadConfig } from '@aegis/config';

export interface AutonomousStack {
  reasoning: ReasoningStack;
  repos: Repositories;
  pool: Pool;
  engine: AutonomousEngine;
  launcher: RecordingLauncher;
  completions: Array<{ engagementId: string; kind: 'complete' | 'fail'; reason: string }>;
  close(): Promise<void>;
}

export interface RecordingLauncher {
  calls: Array<{ kind: 'start' | 'pause' | 'resume' | 'cancel'; engagementId: string; reason?: string }>;
  runId: string;
  start(engagement: EngagementRecord, actorId: string | null, reason?: string): Promise<{ runId: string }>;
  pause(engagementId: string, actorId: string | null, reason?: string): Promise<void>;
  resume(engagementId: string, actorId: string | null): Promise<void>;
  cancel(engagementId: string, actorId: string | null, reason?: string): Promise<void>;
}

let runCounter = 0;

export async function buildAutonomousStack(options: { pool: Pool }): Promise<AutonomousStack> {
  const reasoning = await buildReasoningStack({ pool: options.pool });
  const config = loadConfig({
    env: {
      NODE_ENV: 'test',
      AUTONOMOUS_MAINTENANCE_INTERVAL_MS: '50',
      AUTONOMOUS_LEASE_SWEEP_INTERVAL_MS: '50',
      AUTONOMOUS_MAX_REPLANS: '3',
      AUTONOMOUS_CANDIDATE_BATCH: '4',
      AUTONOMOUS_BRANCH_LIMIT: '6',
      AUTONOMOUS_HYPOTHESIS_LIMIT: '6',
      AUTONOMOUS_STOP_MIN_TESTS: '2',
    },
  });

  const launcher: RecordingLauncher = {
    calls: [],
    runId: '',
    async start(engagement, _actorId, reason) {
      runCounter += 1;
      this.runId = `RUN_TEST${runCounter}_${engagement.id}`;
      this.calls.push({ kind: 'start', engagementId: engagement.id, reason });
      // Record the run the engine compiles tasks against.
      await reasoning.repos.agentRuns.create({
        engagementId: engagement.id,
        leaderModel: 'mock-strategic',
        workerModel: 'mock-tactical',
        reason: reason ?? 'test',
      }).then((run) => {
        this.runId = run.id;
      });
      return { runId: this.runId };
    },
    async pause(engagementId, _actorId, reason) {
      this.calls.push({ kind: 'pause', engagementId, reason });
    },
    async resume(engagementId) {
      this.calls.push({ kind: 'resume', engagementId });
    },
    async cancel(engagementId, _actorId, reason) {
      this.calls.push({ kind: 'cancel', engagementId, reason });
    },
  };

  const completions: Array<{ engagementId: string; kind: 'complete' | 'fail'; reason: string }> = [];
  const registry = createDefaultToolRegistry();

  const engine = new AutonomousEngine({
    repos: reasoning.repos,
    eventBus: reasoning.interaction.eventBus,
    config,
    tools: registry,
    reasoning: reasoning.reasoning,
    launcher,
    completion: {
      complete: async (engagementId, _actorId, reason) => {
        completions.push({ engagementId, kind: 'complete', reason });
      },
      fail: async (engagementId, _actorId, reason) => {
        completions.push({ engagementId, kind: 'fail', reason });
      },
    },
  });

  return {
    reasoning,
    repos: reasoning.repos,
    pool: reasoning.pool,
    engine,
    launcher,
    completions,
    close: async () => {
      for (const state of await reasoning.repos.autonomousStates.listRunnable().catch(() => [])) {
        engine.loopFor(state.engagement_id)?.stop(state.engagement_id);
      }
      await reasoning.close();
    },
  };
}

/** Seed a running engagement wired to the lab app scope. */
export async function seedAutonomousEngagement(
  stack: AutonomousStack,
  options: { mode?: 'PENTEST' | 'CTF'; description?: string } = {},
): Promise<{ engagement: EngagementRecord; identityA: string; identityB: string }> {
  const suffix = `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
  const user = await stack.repos.users.create({
    email: `p6-${suffix}@test.local`,
    name: 'Part6 Tester',
    passwordHash: hashPassword('password1234'),
  });
  const project = await stack.repos.projects.create({
    ownerId: user.id,
    name: 'Part6 Project',
    description: 'autonomous engine tests',
  });
  const engagement = await stack.repos.engagements.create({
    projectId: project.id,
    name: 'Part6 Engagement',
    mode: options.mode ?? 'PENTEST',
    description: options.description ?? 'Determine whether object authorization is enforced.',
  });
  const lab = stack.reasoning.interaction.lab;
  await stack.repos.scope.upsert(engagement.id, {
    allowed_hosts: [lab.host],
    allowed_domains: [],
    allowed_ports: [lab.port],
    allowed_schemes: ['http', 'https'],
    excluded_hosts: [],
    excluded_paths: [],
    rate_limit: null,
    concurrency_limit: null,
    destructive_actions_allowed: false,
  });
  await stack.repos.targets.create({
    engagementId: engagement.id,
    type: 'APPLICATION',
    value: lab.url,
    label: 'lab app',
    metadata: {},
  });
  const identityA = await stack.repos.identities.create({
    engagementId: engagement.id,
    name: 'usera',
    role: 'user',
    type: 'USER',
    metadata: { note: 'lab user A' },
  });
  const identityB = await stack.repos.identities.create({
    engagementId: engagement.id,
    name: 'userb',
    role: 'user',
    type: 'USER',
    metadata: { note: 'lab user B' },
  });
  const started = await stack.repos.engagements.updateStatus(engagement.id, 'RUNNING');
  return { engagement: started ?? engagement, identityA: identityA.id, identityB: identityB.id };
}

/** Mark a task terminal (simulates the Part 2 worker completing it). */
export async function completeTask(repos: Repositories, taskId: string, status: 'COMPLETED' | 'FAILED' = 'COMPLETED'): Promise<void> {
  await repos.tasks.updateStatus(taskId, status);
  await repos.tasks.releaseLease(taskId);
}

/** Settle the engine's serial queue + event bus (§8). */
export async function settleEngine(ms = 300): Promise<void> {
  await new Promise((resolve) => setTimeout(resolve, ms));
}
