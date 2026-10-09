/**
 * Evidence correlator (spec Part 6 §25, §57, §85).
 *
 * Builds the audit chain: Evidence -> Observation -> Test -> Hypothesis ->
 * Verification -> Finding. Evidence linkage is DETERMINISTIC — never
 * dependent on an LLM-generated summary alone (§25). Correlation ids
 * connect the entire chain (§85: decision -> task -> worker -> tool call ->
 * observation -> hypothesis -> evidence -> verification -> finding).
 */
import type { Repositories } from '@aegis/database';

export interface EvidenceChain {
  hypothesisId: string;
  observations: string[];
  tests: string[];
  evidence: string[];
  verifications: string[];
  findingId: string | null;
}

export class EvidenceCorrelator {
  constructor(private readonly repos: Repositories) {}

  /**
   * Assemble the evidence chain for a hypothesis (§25 example: EVIDENCE_01
   * User A accessed object 101 ... -> HYPOTHESIS H17 -> VERIFICATION).
   */
  async chainFor(engagementId: string, hypothesisId: string): Promise<EvidenceChain> {
    const links = await this.repos.hypotheses.linksByHypothesis(hypothesisId);
    const chain: EvidenceChain = {
      hypothesisId,
      observations: links.filter((l) => l.ref_type === 'OBSERVATION').map((l) => l.ref_id),
      tests: links.filter((l) => l.ref_type === 'TEST').map((l) => l.ref_id),
      evidence: links.filter((l) => l.ref_type === 'EVIDENCE').map((l) => l.ref_id),
      verifications: [],
      findingId: null,
    };

    const verifications = await this.repos.verifications.listByEngagement(engagementId, 100);
    chain.verifications = verifications.filter((v) => v.hypothesis_id === hypothesisId).map((v) => v.id);

    const finding = await this.repos.findings.findByHypothesis(hypothesisId);
    chain.findingId = finding?.id ?? null;
    return chain;
  }

  /**
   * Ensure a promoted finding carries its full evidence chain (§58: a
   * finding cannot become VERIFIED without verification evidence).
   */
  async attachFindingEvidence(engagementId: string, hypothesisId: string, findingId: string): Promise<void> {
    const chain = await this.chainFor(engagementId, hypothesisId);
    const allEvidence = [...new Set([...chain.evidence, ...chain.verifications])];
    const existing = await this.repos.findings.findByHypothesis(hypothesisId);
    const merged = [...new Set([...(existing?.evidence_ids ?? []), ...allEvidence])];
    await this.repos.findings
      .enrich(findingId, {
        verificationIds: chain.verifications,
        evidenceIds: merged,
      })
      .catch(() => undefined);
  }
}
