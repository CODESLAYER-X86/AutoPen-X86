/**
 * Verifier (spec Part 6 §26, §58, §60).
 *
 * Discovery and verification are SEPARATE. The verifier drives the Part 4
 * deterministic verification (skeptical checklist + alternative
 * explanations) and BRIDGES the verdict back into the Part 2 hypothesis
 * lifecycle:
 *
 *   VERIFIED    -> hypothesis CONFIRM (via verification) -> finding promoted
 *   REFUTED     -> hypothesis DISPROVED -> dead end + branch pruned
 *   INCONCLUSIVE -> stays SUPPORTED; reproduction may be scheduled (§27)
 *
 * A finding can never become VERIFIED without verification evidence (§58).
 */
import type { Repositories } from '@aegis/database';
import type { PlatformEvent } from '@aegis/contracts';
import type { EventBus } from '@aegis/events';
import { generateId } from '@aegis/shared';
import { HypothesisEngine } from '@aegis/agent';
import { BranchManager } from '../reasoning/branch-manager.js';
import { EvidenceCorrelator } from '../analysis/evidence-correlator.js';
import { ConfidenceEngine } from './confidence-engine.js';
import type { ReasoningPort } from '../engine/ports.js';

export interface VerificationBridgeResult {
  hypothesisId: string;
  verdict: 'VERIFIED' | 'REFUTED' | 'INCONCLUSIVE';
  verificationId: string;
  findingId: string | null;
  applied: 'CONFIRMED' | 'DISPROVED' | 'NONE';
}

export interface VerifierDeps {
  repos: Repositories;
  eventBus: EventBus;
  reasoning: ReasoningPort;
  hypothesisEngine: HypothesisEngine;
  branchManager: BranchManager;
}

export class Verifier {
  private readonly correlator: EvidenceCorrelator;
  private readonly confidence: ConfidenceEngine;

  constructor(private readonly deps: VerifierDeps) {
    this.correlator = new EvidenceCorrelator(deps.repos);
    this.confidence = new ConfidenceEngine();
  }

  /**
   * Verify a SUPPORTED hypothesis and bridge the verdict (§26). The worker's
   * "this looks like an authorization issue" is NOT a confirmed finding —
   * the verifier asks what exact behavior proves the hypothesis, what
   * control comparison is required, whether it reproduces, and whether
   * another explanation could produce the same result.
   */
  async verifyAndBridge(engagementId: string, hypothesisId: string): Promise<VerificationBridgeResult | null> {
    const hypothesis = await this.deps.repos.hypotheses.findByIdAndEngagement(hypothesisId, engagementId);
    if (!hypothesis) return null;
    if (hypothesis.status !== 'SUPPORTED' && hypothesis.status !== 'TESTING') return null;

    const { verification, outcome } = await this.deps.reasoning.verify({ engagementId, hypothesisId });
    const base: VerificationBridgeResult = {
      hypothesisId,
      verdict: outcome.status,
      verificationId: verification.id,
      findingId: null,
      applied: 'NONE',
    };

    if (outcome.status === 'VERIFIED') {
      // CONFIRM requires verification (Part 2 §55): applyChange enforces it.
      await this.deps.hypothesisEngine.applyChange(hypothesis, 'CONFIRM', {
        viaVerification: true,
        verificationRef: verification.id,
      });
      base.applied = 'CONFIRMED';

      // Promoted finding: attach evidence chain + confidence model (§28, §58).
      const finding = await this.deps.repos.findings.findByHypothesis(hypothesisId);
      if (finding) {
        base.findingId = finding.id;
        await this.correlator.attachFindingEvidence(engagementId, hypothesisId, finding.id);
        const assessment = this.confidence.assess({
          reproduced: outcome.checklist.some((c) => c.check.includes('REPRODUC') && c.status === 'PASS'),
          identityDifferential: outcome.kind.includes('AUTHORIZATION'),
          controlComparison: outcome.checklist.some((c) => c.check.includes('BASELINE') && c.status === 'PASS'),
          alternativesRuledOut: outcome.alternatives.length > 0 && outcome.alternatives.every((a) => a.refuted),
          directEvidenceCount: outcome.evidenceIds.length,
          consistentObservations: 1,
        });
        await this.deps.repos.findings
          .enrich(finding.id, {
            category: hypothesis.type,
            confidence: assessment.confidence,
            confidenceLevel: assessment.level,
            confidenceReasons: assessment.reasons,
            verificationIds: [verification.id],
            mode: 'PENTEST',
          })
          .catch(() => undefined);
        await this.publish(engagementId, 'FINDING_CONFIDENCE_COMPUTED', {
          finding_id: finding.id,
          confidence: assessment.confidence,
          level: assessment.level,
        });
      }
    } else if (outcome.status === 'REFUTED') {
      await this.deps.hypothesisEngine.applyChange(hypothesis, 'DISPROVE', {});
      base.applied = 'DISPROVED';
      // Dead end + branch pruning (§15, §66).
      await this.deps.repos.deadEnds
        .create({
          engagementId,
          hypothesisId,
          description: `Verification ${verification.id} refuted hypothesis: ${hypothesis.statement.slice(0, 400)}`,
          tests: [],
          reason: 'verification refuted the hypothesis with a control comparison (§26)',
        })
        .catch(() => undefined);
      await this.pruneBranchesFor(engagementId, hypothesisId);
    }

    await this.publish(engagementId, 'VERIFICATION_BRIDGE_APPLIED', {
      hypothesis_id: hypothesisId,
      verdict: outcome.status,
      applied: base.applied,
      verification_id: verification.id,
      finding_id: base.findingId,
    });
    return base;
  }

  /** SUPPORTED hypotheses that still need verification (§26 queue). */
  async verificationQueue(engagementId: string): Promise<string[]> {
    const supported = await this.deps.repos.hypotheses.listByEngagement(engagementId, {
      statuses: ['SUPPORTED'],
    });
    const verifications = await this.deps.repos.verifications.listByEngagement(engagementId, 100);
    const verified = new Set(verifications.filter((v) => v.status === 'VERIFIED' || v.status === 'REFUTED').map((v) => v.hypothesis_id));
    return supported.filter((h) => !verified.has(h.id)).map((h) => h.id);
  }

  private async pruneBranchesFor(engagementId: string, hypothesisId: string): Promise<void> {
    const branches = await this.deps.repos.branches.listByEngagement(engagementId, ['ACTIVE', 'PAUSED']);
    for (const branch of branches) {
      if (branch.hypothesis_ids.includes(hypothesisId)) {
        await this.deps.branchManager.prune(engagementId, branch.id, `hypothesis ${hypothesisId} disproved by verification`, 'DISPROVED');
      }
    }
  }

  private async publish(engagementId: string, type: string, payload: Record<string, unknown>): Promise<void> {
    const event: PlatformEvent = {
      type: type as PlatformEvent['type'],
      engagement_id: engagementId,
      trace_id: generateId('TRC'),
      actor_id: null,
      payload,
      occurred_at: new Date().toISOString(),
      dedup_key: `verifier:${type}:${engagementId}:${Date.now()}`,
    };
    await this.deps.eventBus.publish(event).catch(() => undefined);
  }
}
