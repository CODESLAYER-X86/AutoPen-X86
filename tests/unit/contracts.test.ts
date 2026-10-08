import { describe, expect, it } from 'vitest';
import {
  CreateEngagementRequestSchema,
  CreateTargetRequestSchema,
  RegisterRequestSchema,
  ScopeRequestSchema,
  LeaderDecisionSchema,
  validateLeaderDecision,
  validateWorkerOutput,
  validateWorkerTurn,
} from '@aegis/contracts';
import { ValidationError } from '@aegis/shared';

describe('API contract schemas (spec §33: API schema validation)', () => {
  it('accepts a valid registration payload and enforces password policy', () => {
    const ok = RegisterRequestSchema.safeParse({
      email: 'user@example.com',
      name: 'User',
      password: 'longenoughpassword',
    });
    expect(ok.success).toBe(true);

    const short = RegisterRequestSchema.safeParse({
      email: 'user@example.com',
      name: 'User',
      password: 'short',
    });
    expect(short.success).toBe(false);
  });

  it('rejects unknown engagement modes (strict)', () => {
    const ok = CreateEngagementRequestSchema.safeParse({
      project_id: 'PRJ_ABCDEFGHIJKLMNOP',
      name: 'e',
      mode: 'PENTEST',
    });
    expect(ok.success).toBe(true);

    const bad = CreateEngagementRequestSchema.safeParse({
      project_id: 'PRJ_ABCDEFGHIJKLMNOP',
      name: 'e',
      mode: 'FUZZ',
    });
    expect(bad.success).toBe(false);
  });

  it('rejects target values outside size bounds and unknown types', () => {
    expect(
      CreateTargetRequestSchema.safeParse({ type: 'URL', value: 'http://a.com/' }).success,
    ).toBe(true);
    expect(
      CreateTargetRequestSchema.safeParse({ type: 'URL', value: '' }).success,
    ).toBe(false);
    expect(
      CreateTargetRequestSchema.safeParse({ type: 'DNS', value: 'x' }).success,
    ).toBe(false);
  });

  it('requires at least one allowed host/domain and one scheme in scope requests', () => {
    const empty = ScopeRequestSchema.safeParse({
      allowed_hosts: [],
      allowed_domains: [],
      allowed_schemes: ['http'],
    });
    expect(empty.success).toBe(false);

    const noSchemes = ScopeRequestSchema.safeParse({
      allowed_hosts: ['example.com'],
      allowed_schemes: [],
    });
    expect(noSchemes.success).toBe(false);

    const valid = ScopeRequestSchema.safeParse({
      allowed_hosts: ['example.com'],
      allowed_schemes: ['https'],
    });
    expect(valid.success).toBe(true);
    if (valid.success) {
      expect(valid.data.destructive_actions_allowed).toBe(false);
      expect(valid.data.excluded_hosts).toEqual([]);
    }
  });

  it('strict schemas reject unknown extra fields', () => {
    const withExtra = RegisterRequestSchema.safeParse({
      email: 'a@b.c',
      name: 'x',
      password: 'longenoughpassword',
      role: 'ADMIN', // not part of the contract
    });
    expect(withExtra.success).toBe(false);
  });
});

describe('agent decision validation (Part 2 §9: structured leader decisions)', () => {
  it('accepts the spec example decision', () => {
    const decision = validateLeaderDecision({
      decision: 'CREATE_TASK',
      reasoning_summary: 'Two object identifiers were observed; authorization behavior not yet compared.',
      task: {
        objective: 'Determine whether object authorization is enforced on the user record endpoint.',
        task_type: 'AUTHORIZATION_ANALYSIS',
        priority: 0.91,
        expected_information_gain: 0.8,
        inputs: { endpoint: '/api/users/{id}', observed_ids: ['381', '382'] },
      },
    });
    expect(decision.decision).toBe('CREATE_TASK');
    if (decision.decision === 'CREATE_TASK') {
      expect(decision.task.priority).toBe(0.91);
    }
  });

  it('fails closed on hallucinated decision enums and malformed payloads', () => {
    expect(() => validateLeaderDecision({ decision: 'NUKE_EVERYTHING' })).toThrowError(
      ValidationError,
    );
    expect(() =>
      validateLeaderDecision({
        decision: 'CREATE_TASK',
        reasoning_summary: '',
        task: { objective: 'x'.repeat(10), task_type: 'RECON' },
      }),
    ).toThrowError(ValidationError);
    expect(() => validateLeaderDecision('just a string model answer')).toThrowError(ValidationError);
    // Extra fields are rejected: the schema is strict — prompt-injection-style
    // additions such as shell_command never survive validation.
    expect(() =>
      validateLeaderDecision({
        decision: 'STOP',
        reasoning_summary: 'done',
        objective_satisfied: true,
        shell_command: 'rm -rf /', // hallucinated injection attempt
      }),
    ).toThrowError(ValidationError);
    // Unknown task_type / worker_type enum values fail closed.
    expect(() =>
      validateLeaderDecision({
        decision: 'CREATE_TASK',
        reasoning_summary: 'ok',
        task: { objective: 'test objective here', task_type: 'NOT_A_REAL_TYPE' },
      }),
    ).toThrowError(ValidationError);
  });

  it('accepts every decision type in the Part 2 vocabulary', () => {
    const ok = (raw: unknown) => expect(() => validateLeaderDecision(raw)).not.toThrow();
    ok({
      decision: 'CREATE_PARALLEL_TASKS',
      reasoning_summary: 'Three independent CTF interpretations can run in parallel.',
      tasks: [
        { objective: 'Probe the legacy endpoint path for the clue.', task_type: 'HTTP_ANALYSIS' },
        { objective: 'Inspect the hidden JS route referenced by the clue.', task_type: 'SOURCE_ANALYSIS' },
      ],
    });
    ok({
      decision: 'UPDATE_HYPOTHESIS',
      reasoning_summary: 'New observation contradicts the caching explanation.',
      hypothesis_id: 'HYP_ABCDEFGHIJKLMNOP',
      change: 'DECREASE_CONFIDENCE',
      confidence: 0.2,
    });
    ok({
      decision: 'REQUEST_KNOWLEDGE',
      reasoning_summary: 'Need known bypass techniques for this framework.',
      query: 'session fixation patterns in Express apps',
    });
    ok({
      decision: 'REQUEST_RECON',
      reasoning_summary: 'Attack surface is unmapped.',
      focus: 'Discover the API surface under /api',
    });
    ok({
      decision: 'REQUEST_VERIFICATION',
      reasoning_summary: 'Behavior needs reproduction before promotion.',
      hypothesis_id: 'HYP_ABCDEFGHIJKLMNOP',
    });
    ok({ decision: 'WAIT', reasoning_summary: 'Await pending authentication task.' });
    ok({ decision: 'STOP', reasoning_summary: 'Objective satisfied.', objective_satisfied: true });
    ok({ decision: 'PAUSE', reasoning_summary: 'Operator interaction required.' });
  });

  it('exposes the schema for downstream agents', () => {
    expect(LeaderDecisionSchema.options.length).toBe(9);
  });
});

describe('worker output validation (Part 2 §16/§17: structured worker results)', () => {
  it('accepts the spec example worker output', () => {
    const output = validateWorkerOutput({
      task_id: 'TSK_ABCDEFGHIJKLMNOP',
      status: 'COMPLETED',
      observations: [
        {
          type: 'AUTHORIZATION_BEHAVIOR',
          description: 'Identity A received object data associated with Identity B.',
          confidence: 0.91,
        },
      ],
      evidence_ids: ['EVD_ABCDEFGHIJKLMNOP'],
      hypothesis_updates: [
        {
          hypothesis_id: 'HYP_ABCDEFGHIJKLMNOP',
          change: 'INCREASE_CONFIDENCE',
          confidence: 0.86,
        },
      ],
      recommended_next_action: { type: 'VERIFY', reason: 'Repeat with a fresh session.' },
    });
    expect(output.status).toBe('COMPLETED');
    expect(output.observations).toHaveLength(1);
  });

  it('fails closed on invalid statuses, out-of-range confidence, unknown fields', () => {
    expect(() =>
      validateWorkerOutput({ task_id: 'TSK_ABCDEFGHIJKLMNOP', status: 'SORTA_DONE' }),
    ).toThrowError(ValidationError);
    expect(() =>
      validateWorkerOutput({
        task_id: 'TSK_ABCDEFGHIJKLMNOP',
        status: 'COMPLETED',
        observations: [{ type: 'X', description: 'd', confidence: 1.5 }],
      }),
    ).toThrowError(ValidationError);
    expect(() =>
      validateWorkerOutput({
        task_id: 'TSK_ABCDEFGHIJKLMNOP',
        status: 'COMPLETED',
        secret_exfiltration: 'vault-contents', // strict schema rejects additions
      }),
    ).toThrowError(ValidationError);
  });

  it('validates worker turns: tool calls and finals are discriminated', () => {
    expect(() =>
      validateWorkerTurn({ type: 'TOOL_CALL', tool: 'parser.jwt', input: { token: 'x' } }),
    ).not.toThrow();
    expect(() =>
      validateWorkerTurn({ type: 'FINAL', result: { task_id: 'TSK_ABCDEFGHIJKLMNOP', status: 'BLOCKED' } }),
    ).not.toThrow();
    expect(() =>
      validateWorkerTurn({ type: 'SHELL_EXEC', command: 'cat /etc/passwd' }),
    ).toThrowError(ValidationError);
    // Malformed tool NAMES fail the schema; well-formed but unregistered
    // names (e.g. shell.exec) are rejected by the ToolGateway/allow-list —
    // schema validates shape, the registry validates existence.
    expect(() =>
      validateWorkerTurn({ type: 'TOOL_CALL', tool: 'Shell Exec!', input: {} }),
    ).toThrowError(ValidationError);
  });
});
