/**
 * Autonomous engine phase state machine (spec Part 6 §6).
 *
 * The engine-level phase describes WHAT the engine is doing strategically:
 *
 *   CREATED -> INITIALIZING -> RECON -> MODELING -> HYPOTHESIS_GENERATION
 *           -> TESTING -> ANALYSIS -> VERIFICATION -> REPLANNING -> TESTING
 *
 * Terminal: COMPLETED / STOPPED / CANCELLED / FAILED.
 * Waiting:  WAITING_FOR_USER / RESOURCE / IDENTITY / QUOTA (resumable).
 *
 * The machine sits ABOVE the Part 2 agent-run state machine: agent runs
 * describe HOW tasks execute; phases describe the strategy. Both are
 * persisted in the database — never process memory (§54).
 */
import {
  AUTONOMOUS_PHASES,
  AUTONOMOUS_TERMINAL_PHASES,
  type AutonomousPhase,
} from '@aegis/shared';
import { ValidationError } from '@aegis/shared';

/** Core reasoning cycle (§6). */
export const CYCLE_PHASES: readonly AutonomousPhase[] = [
  'RECON',
  'MODELING',
  'HYPOTHESIS_GENERATION',
  'TESTING',
  'ANALYSIS',
  'VERIFICATION',
  'REPLANNING',
];

/** Legal phase transitions (§6). */
export const AUTONOMOUS_PHASE_TRANSITIONS: Readonly<Record<AutonomousPhase, readonly AutonomousPhase[]>> = {
  CREATED: ['INITIALIZING', 'CANCELLED'],
  INITIALIZING: ['RECON', 'FAILED', 'CANCELLED', 'WAITING_FOR_IDENTITY', 'WAITING_FOR_RESOURCE'],
  RECON: [
    'MODELING',
    'WAITING_FOR_IDENTITY',
    'WAITING_FOR_RESOURCE',
    'WAITING_FOR_USER',
    'WAITING_FOR_QUOTA',
    'STOPPED',
    'CANCELLED',
    'FAILED',
  ],
  MODELING: [
    'HYPOTHESIS_GENERATION',
    'TESTING',
    'RECON',
    'WAITING_FOR_RESOURCE',
    'WAITING_FOR_USER',
    'WAITING_FOR_QUOTA',
    'STOPPED',
    'CANCELLED',
    'FAILED',
  ],
  HYPOTHESIS_GENERATION: [
    'TESTING',
    'ANALYSIS',
    'REPLANNING',
    'WAITING_FOR_IDENTITY',
    'WAITING_FOR_USER',
    'WAITING_FOR_QUOTA',
    'STOPPED',
    'CANCELLED',
    'FAILED',
  ],
  TESTING: [
    'ANALYSIS',
    'REPLANNING',
    'VERIFICATION',
    'WAITING_FOR_USER',
    'WAITING_FOR_RESOURCE',
    'WAITING_FOR_QUOTA',
    'STOPPED',
    'CANCELLED',
    'FAILED',
  ],
  ANALYSIS: [
    'VERIFICATION',
    'HYPOTHESIS_GENERATION',
    'REPLANNING',
    'TESTING',
    'WAITING_FOR_USER',
    'WAITING_FOR_QUOTA',
    'STOPPED',
    'CANCELLED',
    'FAILED',
  ],
  VERIFICATION: [
    'REPLANNING',
    'ANALYSIS',
    'TESTING',
    'COMPLETED',
    'WAITING_FOR_USER',
    'WAITING_FOR_QUOTA',
    'STOPPED',
    'CANCELLED',
    'FAILED',
  ],
  REPLANNING: [
    'TESTING',
    'HYPOTHESIS_GENERATION',
    'RECON',
    'ANALYSIS',
    'COMPLETED',
    'WAITING_FOR_USER',
    'WAITING_FOR_IDENTITY',
    'WAITING_FOR_QUOTA',
    'STOPPED',
    'CANCELLED',
    'FAILED',
  ],
  // Waiting phases resume back into the strategic cycle (§6): the loop
  // controller re-enters the phase that fits the persisted strategy state.
  WAITING_FOR_USER: [
    'RECON',
    'MODELING',
    'HYPOTHESIS_GENERATION',
    'TESTING',
    'ANALYSIS',
    'VERIFICATION',
    'REPLANNING',
    'STOPPED',
    'CANCELLED',
  ],
  WAITING_FOR_RESOURCE: [
    'RECON',
    'MODELING',
    'TESTING',
    'REPLANNING',
    'STOPPED',
    'CANCELLED',
  ],
  WAITING_FOR_IDENTITY: [
    'RECON',
    'MODELING',
    'HYPOTHESIS_GENERATION',
    'TESTING',
    'STOPPED',
    'CANCELLED',
  ],
  WAITING_FOR_QUOTA: [
    'RECON',
    'MODELING',
    'TESTING',
    'VERIFICATION',
    'REPLANNING',
    'STOPPED',
    'CANCELLED',
  ],
  COMPLETED: [],
  STOPPED: [],
  CANCELLED: [],
  FAILED: [],
};

export class AutonomousPhaseStateMachine {
  static isTerminal(phase: AutonomousPhase): boolean {
    return AUTONOMOUS_TERMINAL_PHASES.includes(phase);
  }

  static isRunnable(phase: AutonomousPhase): boolean {
    return !AutonomousPhaseStateMachine.isTerminal(phase);
  }

  static canTransition(from: AutonomousPhase, to: AutonomousPhase): boolean {
    const allowed = AUTONOMOUS_PHASE_TRANSITIONS[from];
    return allowed !== undefined && allowed.includes(to);
  }

  static assertTransition(from: AutonomousPhase, to: AutonomousPhase): void {
    if (from === to) return;
    if (!AutonomousPhaseStateMachine.canTransition(from, to)) {
      throw new ValidationError(
        `Illegal autonomous phase transition ${from} -> ${to}`,
        'INVALID_AUTONOMOUS_PHASE_TRANSITION',
        { from, to, allowed: AUTONOMOUS_PHASE_TRANSITIONS[from] ?? [] },
      );
    }
  }

  static allPhases(): readonly AutonomousPhase[] {
    return AUTONOMOUS_PHASES;
  }
}
