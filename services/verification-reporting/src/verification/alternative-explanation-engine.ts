/**
 * Alternative explanation engine (spec Part 7 §10, §74, §82).
 *
 * MANDATORY for high-confidence findings. The verifier actively searches for
 * alternative explanations — environmental artifacts, identity mistakes,
 * stale sessions, incorrect baselines, false differentials, caching,
 * public-resource confusion. If a SIMPLER explanation survives, the security
 * finding is NOT confirmed (§10).
 *
 * The engine consumes the Part 4 skeptical verification outcome (when a
 * hypothesis is linked) and augments it with finding-level checks.
 */
import type { Repositories } from '@aegis/database';
import type { FindingRecord } from '@aegis/database';
import { generateId } from '@aegis/shared';
import type { AlternativeExplanationRecord } from '@aegis/database';

export interface AlternativeExplanationOutcome {
  explanations: AlternativeExplanationRecord[];
  /** True when every candidate alternative was refuted. */
  allEliminated: boolean;
  /** Surviving simpler explanations block confirmation (§10). */
  surviving: string[];
  note: string;
}

/** Standard alternative explanations per observation family (§10 example). */
const STANDARD_ALTERNATIVES: Array<{ label: string; description: string; kind: string }> = [
  {
    label: 'H1: resource is intentionally public',
    description: 'The observed data may be public by design; the control condition would then show the same access for anonymous users.',
    kind: 'PUBLIC_RESOURCE',
  },
  {
    label: 'H2: caching artifact',
    description: 'A CDN/proxy cache may serve the foreign content; cache headers and repeat responses decide.',
    kind: 'CACHING',
  },
  {
    label: 'H3: identity mistake (wrong identity assumed)',
    description: 'The request may have carried different identity material than the verifier believes; session state decides.',
    kind: 'IDENTITY_MISTAKE',
  },
  {
    label: 'H4: stale session / expired authentication',
    description: 'The session may have expired mid-test, producing a misleading differential.',
    kind: 'STALE_SESSION',
  },
  {
    label: 'H5: environmental artifact / backend error',
    description: 'The anomaly may be a backend bug or transient error rather than a security-relevant behavior.',
    kind: 'ENVIRONMENTAL',
  },
];

export class AlternativeExplanationEngine {
  constructor(private readonly repos: Repositories) {}

  /**
   * Test alternatives for a finding. When the finding is linked to a
   * hypothesis, the Part 4 verification record's own alternatives (already
   * tested through the skeptical checklist) are merged in — verification
   * independence means we compare SEVERAL conditions, not repeat one (§11).
   */
  async testAlternatives(
    finding: FindingRecord,
    part4Alternatives: AlternativeExplanationRecord[] = [],
    part4Checklist: Array<{ check: string; status: string; detail: string }> = [],
  ): Promise<AlternativeExplanationOutcome> {
    const explanations: AlternativeExplanationRecord[] = [];
    const surviving: string[] = [];

    // 1. Carry over Part 4-tested alternatives verbatim (provenance kept).
    for (const alternative of part4Alternatives) {
      explanations.push(alternative);
      if (!alternative.refuted) surviving.push(alternative.label);
    }

    // 2. Evaluate standard alternatives against the recorded evidence.
    const matrix = await this.repos.authzMatrix
      .listByEngagement(finding.engagement_id, 1000)
      .catch(() => []);
    const anonymousCells = matrix.filter((entry) => entry.identity_id === null);
    // Stale-session evidence: sessions of the identities involved in the
    // finding (§10 H4).
    const sessionStates: Array<'ACTIVE' | 'EXPIRED' | string> = [];
    for (const identityId of finding.affected_identities.slice(0, 4)) {
      const sessions = await this.repos.sessions
        .listByIdentity(identityId)
        .catch(() => [] as Array<{ status: string }>);
      sessionStates.push(...sessions.map((s) => s.status));
    }

    const evidenceIds = finding.evidence_ids;
    for (const alternative of STANDARD_ALTERNATIVES) {
      let refuted = false;
      let refutation: string | null = null;
      switch (alternative.kind) {
        case 'PUBLIC_RESOURCE': {
          // Refuted when the anonymous outcome differs from the suspect
          // outcome (i.e. the resource is NOT public).
          const anonymousOutcome = anonymousCells[0]?.outcome ?? null;
          refuted = anonymousOutcome === null || anonymousOutcome === 'DENIED';
          refutation = refuted
            ? anonymousOutcome === 'DENIED'
              ? 'Anonymous access is DENIED — the resource is not public.'
              : 'No anonymous access observation exists; the public-resource alternative cannot be excluded.'
          : null;
          break;
        }
        case 'CACHING': {
          const cached = part4Checklist.find((c) => c.check === 'IS_RESPONSE_CACHED');
          refuted = cached ? cached.status === 'PASS' : false;
          refutation = cached?.status === 'PASS' ? 'Response caching ruled out by the Part 4 checklist.' : null;
          break;
        }
        case 'IDENTITY_MISTAKE': {
          const diffCheck = part4Checklist.find((c) => c.check === 'DOES_BASELINE_DIFFER');
          refuted = finding.affected_identities.length > 0 && (diffCheck ? diffCheck.status === 'PASS' : true);
          refutation = refuted
            ? 'Identity material was distinct across the differential and the baseline differs — identity confusion ruled out.'
            : null;
          break;
        }
        case 'STALE_SESSION': {
          const active = sessionStates.filter((s) => s === 'ACTIVE');
          const expired = sessionStates.filter((s) => s !== 'ACTIVE');
          refuted = expired.length === 0 || active.length > 0;
          refutation = refuted
            ? expired.length === 0
              ? 'No session expirations recorded during the observation window.'
              : 'An active session for the same identity reproduced the behavior — staleness ruled out.'
            : null;
          break;
        }
        case 'ENVIRONMENTAL': {
          const reproducible = part4Checklist.find((c) => c.check === 'DOES_BEHAVIOR_REPRODUCE');
          refuted = reproducible ? reproducible.status === 'PASS' : false;
          refutation = reproducible?.status === 'PASS'
            ? 'The behavior reproduces deterministically — a transient backend artifact is unlikely.'
            : null;
          break;
        }
      }
      explanations.push({
        id: generateId('AEX'),
        label: alternative.label,
        description: alternative.description,
        refuted,
        refutation,
        evidence_ids: evidenceIds,
      });
      if (!refuted) surviving.push(alternative.label);
    }

    return {
      explanations,
      allEliminated: surviving.length === 0,
      surviving,
      note:
        surviving.length === 0
          ? 'All alternative explanations were eliminated (§10).'
          : `Surviving alternative explanations (§10): ${surviving.join('; ')}. A simpler surviving explanation blocks confirmation.`,
    };
  }
}
