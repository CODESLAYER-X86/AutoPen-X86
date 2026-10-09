/**
 * Claim validator (spec Part 7 §33-§34).
 *
 * Every substantive technical claim in a report must reference evidence, and
 * its SCOPE must not exceed what the evidence proves (§33: "any authenticated
 * user can access all objects" backed by ONE cross-user test is too broad —
 * it gets rewritten to the tested scope). Report claim validation rejects
 * unsupported generalization before export.
 */
import { generateId } from '@aegis/shared';
import type { FindingRecord } from '@aegis/database';
import type { ReportClaimRecord } from '@aegis/database';

/** Universal-quantifier phrases that generalize beyond tested evidence. */
const GENERALIZERS: Array<{ pattern: RegExp; phrase: string }> = [
  { pattern: /\ball\b|\bevery\b|\bany\b|\banyone\b|\beveryone\b/gi, phrase: 'universal quantifier' },
  { pattern: /\balways\b|\bnever\b|\beverywhere\b/gi, phrase: 'absolute adverb' },
  { pattern: /\ball users\b|\ball objects\b|\ball endpoints\b/gi, phrase: 'total-scope noun' },
];

export interface ClaimAssessment {
  claim: ReportClaimRecord;
  /** §33: was the claim rewritten to match evidence scope? */
  rewritten: boolean;
  originalText: string;
  issue: string | null;
}

export class ClaimValidator {
  /**
   * Build claims from a finding's structured fields (§34): each substantive
   * sentence maps to the finding's evidence ids with its confidence.
   */
  buildClaimsForFinding(finding: FindingRecord): ReportClaimRecord[] {
    const claims: ReportClaimRecord[] = [];
    const evidenceIds = finding.evidence_ids;

    if (finding.observed_behavior ?? finding.description) {
      claims.push(this.makeClaim(finding, `Observed behavior: ${finding.observed_behavior ?? finding.description}`, evidenceIds));
    }
    if (finding.expected_behavior) {
      claims.push(
        this.makeClaim(finding, `Expected behavior: ${finding.expected_behavior}`, evidenceIds),
      );
    }
    if (finding.verification_ids.length > 0) {
      claims.push(
        this.makeClaim(
          finding,
          `Verification status: ${finding.status} (verified through ${finding.verification_ids.length} verification record(s))`,
          evidenceIds,
        ),
      );
    }
    if (finding.severity && finding.cvss) {
      claims.push(
        this.makeClaim(
          finding,
          `Severity ${finding.severity} computed deterministically from CVSS ${finding.cvss.version} vector ${finding.cvss.vector} (base ${finding.cvss.base_score})`,
          evidenceIds,
        ),
      );
    }
    return claims;
  }

  /**
   * §33: validate a claim against its evidence. Claims with no evidence are
   * UNSUPPORTED; claims with universal scope over limited evidence are
   * flagged BROADER_THAN_EVIDENCE and rewritten to the tested scope.
   */
  assess(claim: ReportClaimRecord, finding: FindingRecord, evidenceCount: number): ClaimAssessment {
    const originalText = claim.text;
    if (claim.evidence_ids.length === 0 || evidenceCount === 0) {
      return {
        claim: { ...claim, support: 'UNSUPPORTED' },
        rewritten: false,
        originalText,
        issue: 'claim has no evidence references (§34: every substantive claim must reference evidence)',
      };
    }

    const scoped = this.scopeText(originalText, finding);
    if (scoped !== originalText) {
      return {
        claim: { ...claim, text: scoped, support: 'BROADER_THAN_EVIDENCE', revision_of: claim.id },
        rewritten: true,
        originalText,
        issue: `claim scope exceeded evidence (§33); rewritten to the tested scope: ${scoped}`,
      };
    }
    return { claim: { ...claim, support: 'SUPPORTED' }, rewritten: false, originalText, issue: null };
  }

  /**
   * Rewrite universal claims into evidence-bounded statements (§33 example:
   * "any authenticated user..." -> "the tested endpoint allowed ID_A to
   * access an object observed to belong to ID_B").
   */
  private scopeText(text: string, finding: FindingRecord): string {
    let scoped = text;
    const hasGeneralizer = GENERALIZERS.some((g) => g.pattern.test(scoped));
    // reset lastIndex on global regexes
    GENERALIZERS.forEach((g) => (g.pattern.lastIndex = 0));
    if (!hasGeneralizer) return scoped;

    const endpoints =
      finding.affected_endpoints.length > 0
        ? finding.affected_endpoints.slice(0, 3).map((e) => `\`${e}\``).join(', ')
        : 'the tested endpoint';
    const identities = finding.affected_identities
      .slice(0, 2)
      .map((id) => id)
      .join(' and ');
    const identityClause = identities ? ` (${identities})` : '';

    scoped = scoped
      .replace(/\ball users\b|\bevery user\b|\bany (?:authenticated )?user\b/gi, 'the tested identities')
      .replace(/\ball objects\b|\bevery object\b|\bany object\b/gi, 'the tested objects')
      .replace(/\ball endpoints\b|\bevery endpoint\b/gi, 'the tested endpoints')
      .replace(/\bany\b/gi, 'the tested')
      .replace(/\bevery\b/gi, 'the tested')
      .replace(/\ball\b/gi, 'the tested');
    scoped = `${scoped} — evidenced only on ${endpoints}${identityClause} (§33: no unsupported generalization).`;
    return scoped;
  }

  private makeClaim(finding: FindingRecord, text: string, evidenceIds: string[]): ReportClaimRecord {
    return {
      id: generateId('CLM'),
      finding_id: finding.id,
      text,
      evidence_ids: evidenceIds.slice(0, 16),
      confidence: finding.confidence ?? 0.5,
      support: 'SUPPORTED',
      revision_of: null,
    };
  }
}
