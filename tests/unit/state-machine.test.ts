import { describe, expect, it } from 'vitest';
import { ValidationError } from '@aegis/shared';
import { EngagementStateMachine, ENGAGEMENT_TRANSITIONS } from '@aegis/orchestrator';
import type { EngagementStatus } from '@aegis/shared';

describe('engagement state machine (spec §31, §33)', () => {
  it('allows exactly the documented transitions', () => {
    expect(EngagementStateMachine.canTransition('DRAFT', 'READY')).toBe(true);
    expect(EngagementStateMachine.canTransition('DRAFT', 'CANCELLED')).toBe(true);

    expect(EngagementStateMachine.canTransition('READY', 'RUNNING')).toBe(true);
    expect(EngagementStateMachine.canTransition('READY', 'CANCELLED')).toBe(true);

    expect(EngagementStateMachine.canTransition('RUNNING', 'PAUSED')).toBe(true);
    expect(EngagementStateMachine.canTransition('RUNNING', 'COMPLETED')).toBe(true);
    expect(EngagementStateMachine.canTransition('RUNNING', 'FAILED')).toBe(true);
    expect(EngagementStateMachine.canTransition('RUNNING', 'CANCELLED')).toBe(true);

    expect(EngagementStateMachine.canTransition('PAUSED', 'RUNNING')).toBe(true);
    expect(EngagementStateMachine.canTransition('PAUSED', 'CANCELLED')).toBe(true);
  });

  it('rejects invalid transitions with typed errors', () => {
    expect(() => EngagementStateMachine.assertTransition('DRAFT', 'RUNNING')).toThrowError(
      ValidationError,
    );
    expect(() => EngagementStateMachine.assertTransition('COMPLETED', 'RUNNING')).toThrowError(
      ValidationError,
    );
    expect(() => EngagementStateMachine.assertTransition('CANCELLED', 'READY')).toThrowError(
      ValidationError,
    );
    expect(() => EngagementStateMachine.assertTransition('PAUSED', 'COMPLETED')).toThrowError(
      ValidationError,
    );
    expect(() => EngagementStateMachine.assertTransition('RUNNING', 'RUNNING')).toThrowError(
      ValidationError,
    );
  });

  it('reports terminal states', () => {
    for (const terminal of ['COMPLETED', 'FAILED', 'CANCELLED'] as EngagementStatus[]) {
      expect(EngagementStateMachine.isTerminal(terminal)).toBe(true);
      expect(ENGAGEMENT_TRANSITIONS[terminal]).toHaveLength(0);
    }
    for (const active of ['DRAFT', 'READY', 'RUNNING', 'PAUSED'] as EngagementStatus[]) {
      expect(EngagementStateMachine.isTerminal(active)).toBe(false);
    }
  });

  it('includes allowed transitions in the error details', () => {
    try {
      EngagementStateMachine.assertTransition('DRAFT', 'COMPLETED');
      expect.unreachable('should have thrown');
    } catch (error) {
      const validationError = error as ValidationError;
      const details = validationError.details as { allowed_from: string[] };
      expect(details.allowed_from).toEqual(['READY', 'CANCELLED']);
    }
  });
});
