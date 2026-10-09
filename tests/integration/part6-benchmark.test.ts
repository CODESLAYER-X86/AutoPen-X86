/**
 * Part 6 evaluation framework tests (spec §79-§84).
 *
 * Benchmark engagements with KNOWN ground truth over the local fixture
 * apps. Metrics measured (§79): time to verified finding, false-positive
 * rate, duplicate-test rate, coverage, requests per finding, verification
 * success, CTF solve rate. A good agent solves with fewer meaningful
 * experiments (§84) — request efficiency is asserted, not just outcomes.
 */
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { resetDatabase } from './helpers.js';
import { TEST_DATABASE_URL } from '../../vitest.shared.js';
import { createPool } from '@aegis/database';
import { BenchmarkRunner, BENCHMARKS } from '@aegis/autonomous';
import { buildAutonomousStack, seedAutonomousEngagement, completeTask, settleEngine, type AutonomousStack } from './part6-helpers.js';
import { loginSession, getAs } from './part4-helpers.js';
import { startCtfApp, challengeText, type CtfApp } from '../fixtures/ctfApp.js';

let pool: ReturnType<typeof createPool>;
let stack: AutonomousStack;
let ctfApp: CtfApp;

beforeAll(async () => {
  pool = createPool(TEST_DATABASE_URL, { max: 5 });
  await resetDatabase(pool);
  stack = await buildAutonomousStack({ pool });
  ctfApp = await startCtfApp({ challenge: 'client-side' });
});

afterAll(async () => {
  await stack.close();
  await ctfApp.close();
});

beforeEach(async () => {
  for (const state of await stack.repos.autonomousStates.listRunnable().catch(() => [])) {
    stack.engine.loopFor(state.engagement_id)?.stop(state.engagement_id);
  }
  await resetDatabase(pool);
});

describe('benchmark definitions (§79-§80)', () => {
  it('exposes offline benchmarks with expected ground truth', () => {
    expect(BENCHMARKS.length).toBeGreaterThanOrEqual(5);
    const pentest = BENCHMARKS.find((benchmark) => benchmark.name === 'lab-pentest-authorization')!;
    expect(pentest.mode).toBe('PENTEST');
    // Known vulnerability ground truth (§80): the notes IDOR + workflow flaw.
    expect(pentest.expected_findings.length).toBe(2);
    expect(pentest.expected_findings[0]).toContain('/api/notes');
    // Known negative control (§79 expected dead ends).
    expect(pentest.expected_dead_ends[0]).toContain('/api/orders');

    for (const benchmark of BENCHMARKS) {
      expect(benchmark.measures.length).toBeGreaterThan(0);
      expect(benchmark.description.length).toBeGreaterThan(40);
    }
    const ctf = BENCHMARKS.filter((benchmark) => benchmark.mode === 'CTF');
    expect(ctf.length).toBeGreaterThanOrEqual(4);
  });
});

describe('pentest benchmark run (§79)', () => {
  it('computes honest metrics from the persisted state', async () => {
    const startedAt = Date.now();
    const { engagement, identityA, identityB } = await seedAutonomousEngagement(stack);
    await stack.engine.start(engagement, null, 'benchmark pentest');

    // The benchmark scenario: the §127 observation sequence over the lab.
    await loginSession(stack.reasoning, engagement.id, identityA, 'usera', 'password-a');
    await loginSession(stack.reasoning, engagement.id, identityB, 'userb', 'password-b');
    await getAs(stack.reasoning, engagement.id, identityA, '/api/notes/7');
    await getAs(stack.reasoning, engagement.id, identityA, '/api/notes/8');
    await getAs(stack.reasoning, engagement.id, identityB, '/api/notes/8');

    // Drive the engine to a terminal state (bounded).
    let guard = 0;
    while (guard < 30) {
      guard += 1;
      const phase = (await stack.repos.autonomousStates.findByEngagement(engagement.id))?.phase ?? '?';
      if (['COMPLETED', 'STOPPED', 'CANCELLED', 'FAILED'].includes(phase)) break;
      const pending = await stack.repos.tasks.listByEngagement(engagement.id, {
        statuses: ['QUEUED', 'READY', 'RUNNING', 'WAITING', 'RECOVERY_PENDING'],
        limit: 50,
      });
      for (const task of pending) {
        await completeTask(stack.repos, task.id, 'COMPLETED');
      }
      await stack.engine.maintenanceTick(engagement.id);
      await settleEngine(100);
    }

    const runner = new BenchmarkRunner(stack.repos);
    const coverage = await stack.engine.coverage(engagement.id);
    const metrics = await runner.compute({
      engagementId: engagement.id,
      startedAt,
      finishedAt: Date.now(),
      solved: false,
      coverage,
      expectedFindingsTotal: 2,
      expectedFindingsFound: 0,
      expectedDeadEndsAvoided: 0,
    });

    // §79 metrics computed from real DB state.
    expect(metrics.total_tests).toBeGreaterThan(0);
    expect(metrics.total_http_requests).toBeGreaterThanOrEqual(3);
    expect(metrics.duplicate_test_rate).toBeLessThan(0.5); // §84 efficiency
    expect(metrics.coverage).not.toBeNull();
    expect(metrics.requests_per_finding === null || metrics.requests_per_finding > 0).toBe(true);
    expect(metrics.time_to_first_finding_ms === null || metrics.time_to_first_finding_ms > 0).toBe(true);

    // Persisted benchmark run (§79 auditability).
    await runner.record('lab-pentest-authorization', engagement.id, metrics.solved ? 'SOLVED' : 'COMPLETED', metrics);
    const runs = await stack.repos.benchmarkRuns.listByBenchmark('lab-pentest-authorization', 5);
    expect(runs.length).toBe(1);
    expect(runs[0]!.outcome).toBe('COMPLETED');
    expect((runs[0]!.metrics as Record<string, unknown>).total_tests).toBeGreaterThan(0);
  });
});

describe('CTF benchmark solve (§84)', () => {
  it('client-side challenge: solved with evidence, not brute force', async () => {
    const startedAt = Date.now();
    const { engagement } = await seedAutonomousEngagement(stack, {
      mode: 'CTF',
      description: challengeText('client-side').description,
    });
    await stack.engine.start(engagement, null, 'benchmark ctf');

    // Evidence-driven path (§63): one request to the state endpoint follows
    // the clue; the engine must detect the flag from that single observation.
    await stack.reasoning.interaction.gateway.execute(
      'http.request',
      { method: 'GET', url: `${ctfApp.url}/api/state`, identity_id: null },
      {
        engagementId: engagement.id,
        scope: {
          allowed_hosts: [ctfApp.host], allowed_domains: [], allowed_ports: [ctfApp.port], allowed_schemes: ['http', 'https'],
          excluded_hosts: [], excluded_paths: [], rate_limit: null, concurrency_limit: null, destructive_actions_allowed: false,
        },
        permissions: { network: true, browser: true, destructive: false },
      },
    );

    let guard = 0;
    while (guard < 15) {
      guard += 1;
      const phase = (await stack.repos.autonomousStates.findByEngagement(engagement.id))?.phase ?? '?';
      if (phase === 'COMPLETED') break;
      await stack.engine.maintenanceTick(engagement.id);
      await settleEngine(100);
    }

    const context = await stack.repos.ctfContexts.findByEngagement(engagement.id);
    expect(context!.status).toBe('SOLVED');

    const runner = new BenchmarkRunner(stack.repos);
    const metrics = await runner.compute({
      engagementId: engagement.id,
      startedAt,
      finishedAt: Date.now(),
      solved: true,
      coverage: null,
      expectedFindingsTotal: 1,
      expectedFindingsFound: 1,
      expectedDeadEndsAvoided: 0,
    });
    expect(metrics.solved).toBe(true);
    expect(metrics.time_to_solve_ms).toBeGreaterThan(0);
    expect(metrics.time_to_solve_ms).toBeLessThan(60_000);
    // §84: solved with FEWER meaningful experiments — the single evidence
    // request plus the bounded recon probes, never brute force.
    expect(metrics.total_http_requests).toBeLessThan(20);
  });
});
