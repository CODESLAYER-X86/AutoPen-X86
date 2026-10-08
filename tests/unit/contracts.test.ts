import { describe, expect, it } from 'vitest';
import {
  AgentDecisionSchema,
  CreateEngagementRequestSchema,
  CreateTargetRequestSchema,
  RegisterRequestSchema,
  ScopeRequestSchema,
  validateAgentDecision,
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

describe('agent decision validation (spec §20 principle)', () => {
  it('accepts the spec example decision', () => {
    const decision = validateAgentDecision({
      decision: 'CREATE_TASK',
      reason: 'The endpoint appears to expose an object identifier.',
      priority: 0.82,
      task_type: 'AUTHORIZATION_TEST',
      target: 'endpoint_123',
      identity: 'identity_02',
    });
    expect(decision.decision).toBe('CREATE_TASK');
    expect(decision.priority).toBe(0.82);
  });

  it('fails closed on hallucinated decision enums and malformed payloads', () => {
    expect(() => validateAgentDecision({ decision: 'NUKE_EVERYTHING' })).toThrowError(
      ValidationError,
    );
    expect(() =>
      validateAgentDecision({ decision: 'CREATE_TASK', reason: '', priority: 0.5 }),
    ).toThrowError(ValidationError);
    expect(() =>
      validateAgentDecision({ decision: 'CREATE_TASK', reason: 'ok', priority: 5 }),
    ).toThrowError(ValidationError);
    expect(() => validateAgentDecision('just a string model answer')).toThrowError(ValidationError);
    // Extra fields are rejected: the schema is strict.
    expect(() =>
      validateAgentDecision({
        decision: 'STOP',
        reason: 'done',
        priority: 1,
        shell_command: 'rm -rf /', // hallucinated injection attempt
      }),
    ).toThrowError(ValidationError);
  });

  it('exposes the schema for downstream agents', () => {
    expect(AgentDecisionSchema.shape.decision.options).toContain('STOP');
  });
});
