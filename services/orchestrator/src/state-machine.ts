/**
 * Engagement state machine (spec §31).
 *
 *   DRAFT -> READY -> RUNNING -> {PAUSED, COMPLETED, FAILED, CANCELLED}
 *   PAUSED -> RUNNING | CANCELLED
 *   Terminal states: COMPLETED, FAILED, CANCELLED
 *
 * Transitions are validated deterministically; invalid transitions are
 * rejected with a typed error. The LLM never participates in this decision.
 */
import { ValidationError, type EngagementStatus } from '@aegis/shared';

export const ENGAGEMENT_TRANSITIONS: Readonly<Record<EngagementStatus, readonly EngagementStatus[]>> = {
  DRAFT: ['READY', 'CANCELLED'],
  READY: ['RUNNING', 'CANCELLED'],
  RUNNING: ['PAUSED', 'COMPLETED', 'FAILED', 'CANCELLED'],
  PAUSED: ['RUNNING', 'CANCELLED'],
  COMPLETED: [],
  FAILED: [],
  CANCELLED: [],
};

export class EngagementStateMachine {
  static canTransition(from: EngagementStatus, to: EngagementStatus): boolean {
    const allowed = ENGAGEMENT_TRANSITIONS[from];
    return allowed !== undefined && allowed.includes(to);
  }

  static assertTransition(from: EngagementStatus, to: EngagementStatus): void {
    if (!EngagementStateMachine.canTransition(from, to)) {
      throw new ValidationError(
        `Invalid engagement transition: ${from} -> ${to}`,
        'INVALID_ENGAGEMENT_TRANSITION',
        {
          from,
          to,
          allowed_from: ENGAGEMENT_TRANSITIONS[from] ?? [],
        },
      );
    }
  }

  static isTerminal(status: EngagementStatus): boolean {
    return ENGAGEMENT_TRANSITIONS[status]?.length === 0;
  }
}
