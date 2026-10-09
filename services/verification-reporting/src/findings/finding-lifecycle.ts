/**
 * Finding lifecycle (spec Part 7 §4-§5).
 *
 *   CANDIDATE -> UNDER_REVIEW -> VERIFICATION_PENDING -> VERIFYING -> VERIFIED
 *   Alternatives: VERIFYING -> INCONCLUSIVE / REJECTED; CANDIDATE -> DUPLICATE;
 *   human terminal: ACCEPTED.
 *
 * Transitions are guarded and audited: every move persists a lifecycle event
 * (§5) and illegal transitions are rejected. Rejected findings are NEVER
 * deleted — they are false-positive evaluation data (§4).
 */
import type { FindingStatus } from '@aegis/shared';

export const FINDING_TRANSITIONS: Record<string, FindingStatus[]> = {
  CANDIDATE: ['UNDER_REVIEW', 'DUPLICATE', 'REJECTED'],
  UNDER_REVIEW: ['VERIFICATION_PENDING', 'DUPLICATE', 'REJECTED'],
  VERIFICATION_PENDING: ['VERIFYING', 'REJECTED'],
  VERIFYING: ['VERIFIED', 'INCONCLUSIVE', 'REJECTED'],
  INCONCLUSIVE: ['VERIFICATION_PENDING', 'REJECTED'],
  VERIFIED: ['ACCEPTED', 'REJECTED'],
  ACCEPTED: [],
  DUPLICATE: [],
  REJECTED: [],
  // Part 2 promotion aliases stay reachable from anywhere the Part 2 ladder
  // wrote them (PROPOSED -> CONFIRMED): only Part 7 states transition here.
  PROPOSED: ['CANDIDATE', 'REJECTED'],
  CONFIRMED: ['VERIFIED', 'ACCEPTED', 'REJECTED', 'INCONCLUSIVE'],
};

export function canTransition(from: string, to: string): boolean {
  const allowed = FINDING_TRANSITIONS[from];
  if (!allowed) return false;
  return allowed.includes(to as FindingStatus);
}

export function isTerminal(status: string): boolean {
  const allowed = FINDING_TRANSITIONS[status];
  return allowed !== undefined && allowed.length === 0;
}

/** Verdict -> lifecycle status mapping (§14 -> §4). */
export function verdictToStatus(verdict: 'VERIFIED' | 'REJECTED' | 'INCONCLUSIVE'): FindingStatus {
  if (verdict === 'VERIFIED') return 'VERIFIED';
  if (verdict === 'REJECTED') return 'REJECTED';
  return 'INCONCLUSIVE';
}
