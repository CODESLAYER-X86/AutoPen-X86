import { describe, expect, it } from 'vitest';
import {
  AgentRunStateMachine,
  TaskStateMachine,
  AGENT_RUN_TRANSITIONS,
  TASK_TRANSITIONS,
} from '@aegis/agent';
import { ValidationError, type AgentRunStatus } from '@aegis/shared';

describe('agent run state machine (spec Part 2 §3)', () => {
  it('follows the documented lifecycle CREATED -> INITIALIZING -> RUNNING', () => {
    expect(AgentRunStateMachine.canTransition('CREATED', 'INITIALIZING')).toBe(true);
    expect(AgentRunStateMachine.canTransition('INITIALIZING', 'RUNNING')).toBe(true);
    expect(AgentRunStateMachine.canTransition('RUNNING', 'PAUSED')).toBe(true);
    expect(AgentRunStateMachine.canTransition('RUNNING', 'WAITING')).toBe(true);
    expect(AgentRunStateMachine.canTransition('WAITING', 'RUNNING')).toBe(true);
    expect(AgentRunStateMachine.canTransition('PAUSED', 'RUNNING')).toBe(true);
    expect(AgentRunStateMachine.canTransition('RUNNING', 'COMPLETED')).toBe(true);
    expect(AgentRunStateMachine.canTransition('RUNNING', 'FAILED')).toBe(true);
    expect(AgentRunStateMachine.canTransition('RUNNING', 'CANCELLED')).toBe(true);
  });

  it('rejects invalid transitions deterministically', () => {
    expect(AgentRunStateMachine.canTransition('CREATED', 'RUNNING')).toBe(false);
    expect(AgentRunStateMachine.canTransition('COMPLETED', 'RUNNING')).toBe(false);
    expect(AgentRunStateMachine.canTransition('PAUSED', 'COMPLETED')).toBe(false);
    expect(() => AgentRunStateMachine.assertTransition('CREATED', 'RUNNING')).toThrowError(
      ValidationError,
    );
  });

  it('marks terminal states', () => {
    const terminals: AgentRunStatus[] = ['COMPLETED', 'FAILED', 'CANCELLED'];
    for (const terminal of terminals) {
      expect(AgentRunStateMachine.isTerminal(terminal)).toBe(true);
      expect(AGENT_RUN_TRANSITIONS[terminal]).toHaveLength(0);
    }
  });
});

describe('task state machine (spec Part 2 §18, §64)', () => {
  it('follows CREATED -> QUEUED -> READY -> RUNNING -> terminal', () => {
    expect(TaskStateMachine.canTransition('CREATED', 'QUEUED')).toBe(true);
    expect(TaskStateMachine.canTransition('QUEUED', 'READY')).toBe(true);
    expect(TaskStateMachine.canTransition('QUEUED', 'WAITING')).toBe(true);
    expect(TaskStateMachine.canTransition('WAITING', 'READY')).toBe(true);
    expect(TaskStateMachine.canTransition('READY', 'RUNNING')).toBe(true);
    // Retry re-queue path (§44): RUNNING -> QUEUED -> READY.
    expect(TaskStateMachine.canTransition('RUNNING', 'QUEUED')).toBe(true);
    expect(TaskStateMachine.canTransition('RUNNING', 'COMPLETED')).toBe(true);
    expect(TaskStateMachine.canTransition('RUNNING', 'PARTIAL')).toBe(true);
    expect(TaskStateMachine.canTransition('RUNNING', 'FAILED')).toBe(true);
    expect(TaskStateMachine.canTransition('RUNNING', 'CANCELLED')).toBe(true);
    expect(TaskStateMachine.canTransition('RUNNING', 'RECOVERY_PENDING')).toBe(true);
    expect(TaskStateMachine.canTransition('RECOVERY_PENDING', 'READY')).toBe(true);
    expect(TaskStateMachine.canTransition('RECOVERY_PENDING', 'COMPLETED')).toBe(true);
  });

  it('rejects skipping states and reviving terminal tasks', () => {
    expect(TaskStateMachine.canTransition('CREATED', 'RUNNING')).toBe(false);
    expect(TaskStateMachine.canTransition('COMPLETED', 'READY')).toBe(false);
    expect(TaskStateMachine.canTransition('FAILED', 'RUNNING')).toBe(false);
    expect(TaskStateMachine.canTransition('CANCELLED', 'QUEUED')).toBe(false);
    expect(() => TaskStateMachine.assertTransition('COMPLETED', 'READY')).toThrowError(
      ValidationError,
    );
    const error = new ValidationError('x');
    void error;
    try {
      TaskStateMachine.assertTransition('READY', 'COMPLETED');
      expect.unreachable();
    } catch (thrown) {
      expect((thrown as ValidationError).code).toBe('INVALID_TASK_TRANSITION');
    }
  });

  it('classifies success states', () => {
    expect(TaskStateMachine.isSuccess('COMPLETED')).toBe(true);
    expect(TaskStateMachine.isSuccess('PARTIAL')).toBe(true);
    expect(TaskStateMachine.isSuccess('FAILED')).toBe(false);
  });

  it('keeps the transition table total (every status has an entry)', () => {
    for (const status of Object.keys(TASK_TRANSITIONS)) {
      expect(Array.isArray(TASK_TRANSITIONS[status as 'READY'])).toBe(true);
    }
  });
});
