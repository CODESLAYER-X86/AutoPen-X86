/**
 * Agent state machines (spec Part 2 §3, §18, §30).
 *
 * Both machines are pure, deterministic transition tables — identical in
 * spirit to Part 1's EngagementStateMachine. The LLM never participates in
 * these decisions; invalid transitions are typed errors.
 */

import { ValidationError, type AgentRunStatus, type TaskStatus } from '@aegis/shared';

// ---------------------------------------------------------------------------
// AgentRun (Part 2 §3): CREATED -> INITIALIZING -> RUNNING <-> PAUSED/WAITING
// -> terminal {COMPLETED, FAILED, CANCELLED}
// ---------------------------------------------------------------------------

export const AGENT_RUN_TRANSITIONS: Readonly<
  Record<AgentRunStatus, readonly AgentRunStatus[]>
> = {
  CREATED: ['INITIALIZING', 'CANCELLED'],
  INITIALIZING: ['RUNNING', 'FAILED', 'CANCELLED'],
  RUNNING: ['PAUSED', 'WAITING', 'COMPLETED', 'FAILED', 'CANCELLED'],
  // WAITING: leader chose WAIT or all tasks are in-flight; wakes on events.
  WAITING: ['RUNNING', 'PAUSED', 'COMPLETED', 'FAILED', 'CANCELLED'],
  PAUSED: ['RUNNING', 'CANCELLED'],
  COMPLETED: [],
  FAILED: [],
  CANCELLED: [],
};

export class AgentRunStateMachine {
  static canTransition(from: AgentRunStatus, to: AgentRunStatus): boolean {
    const allowed = AGENT_RUN_TRANSITIONS[from];
    return allowed !== undefined && allowed.includes(to);
  }

  static assertTransition(from: AgentRunStatus, to: AgentRunStatus): void {
    if (!AgentRunStateMachine.canTransition(from, to)) {
      throw new ValidationError(
        `Invalid agent run transition: ${from} -> ${to}`,
        'INVALID_AGENT_RUN_TRANSITION',
        { from, to, allowed_from: AGENT_RUN_TRANSITIONS[from] ?? [] },
      );
    }
  }

  static isTerminal(status: AgentRunStatus): boolean {
    return AGENT_RUN_TRANSITIONS[status]?.length === 0;
  }
}

// ---------------------------------------------------------------------------
// Task (Part 2 §18): CREATED -> QUEUED -> READY -> RUNNING -> terminal
// plus WAITING (unsatisfied dependency), RECOVERY_PENDING (Part 2 §64) and
// retry loops back to READY.
// ---------------------------------------------------------------------------

export const TASK_TRANSITIONS: Readonly<Record<TaskStatus, readonly TaskStatus[]>> = {
  CREATED: ['QUEUED', 'CANCELLED'],
  QUEUED: ['READY', 'WAITING', 'CANCELLED', 'EXPIRED'],
  // WAITING: dependencies not satisfied yet.
  WAITING: ['READY', 'CANCELLED', 'EXPIRED'],
  READY: ['RUNNING', 'CANCELLED', 'EXPIRED'],
  // RUNNING -> QUEUED is the retry re-queue path (§44 bounded backoff).
  RUNNING: ['COMPLETED', 'PARTIAL', 'FAILED', 'CANCELLED', 'RECOVERY_PENDING', 'QUEUED'],
  // RECOVERY_PENDING: found RUNNING after a crash (Part 2 §64). Recovery
  // decides: re-queue for retry, complete from recorded output, or fail.
  RECOVERY_PENDING: ['READY', 'QUEUED', 'COMPLETED', 'FAILED', 'CANCELLED'],
  COMPLETED: [],
  PARTIAL: [],
  FAILED: [],
  CANCELLED: [],
  EXPIRED: [],
};

export class TaskStateMachine {
  static canTransition(from: TaskStatus, to: TaskStatus): boolean {
    const allowed = TASK_TRANSITIONS[from];
    return allowed !== undefined && allowed.includes(to);
  }

  static assertTransition(from: TaskStatus, to: TaskStatus): void {
    if (!TaskStateMachine.canTransition(from, to)) {
      throw new ValidationError(
        `Invalid task transition: ${from} -> ${to}`,
        'INVALID_TASK_TRANSITION',
        { from, to, allowed_from: TASK_TRANSITIONS[from] ?? [] },
      );
    }
  }

  static isTerminal(status: TaskStatus): boolean {
    return TASK_TRANSITIONS[status]?.length === 0;
  }

  static isSuccess(status: TaskStatus): boolean {
    return status === 'COMPLETED' || status === 'PARTIAL';
  }
}

/** Terminal task statuses for scheduler bookkeeping. */
export const TERMINAL_TASK_STATUSES: readonly TaskStatus[] = [
  'COMPLETED',
  'PARTIAL',
  'FAILED',
  'CANCELLED',
  'EXPIRED',
];
