/**
 * Reasoning port types (Part 7 verification bridge into Part 4 §71-§76).
 *
 * The Part 7 verifier re-uses the Part 4 skeptical checklist outcome —
 * verification is a SEPARATE system from discovery (§2), and the Part 4
 * engine already implements the checklist + alternative testing machinery.
 */
import type { AlternativeExplanationRecord } from '@aegis/database';

export interface VerificationCheck {
  check: string;
  status: string;
  detail: string;
}

export interface VerificationOutcome {
  kind: string;
  status: 'VERIFIED' | 'REFUTED' | 'INCONCLUSIVE';
  checklist: VerificationCheck[];
  alternatives: AlternativeExplanationRecord[];
  result: Record<string, unknown>;
  evidenceIds: string[];
}
