/**
 * Finding service (spec Part 7 §6, §4-§5, §13, §17-§20, §70).
 *
 * Candidate creation, guarded lifecycle transitions, severity computation,
 * confidence recalculation, deduplication and the evidence graph (§21). The
 * DETERMINISTIC service makes every decision; the model only ever supplies
 * structured inputs. Reproducibility metadata (§13) is captured on every
 * verification.
 */
import type { Repositories } from '@aegis/database';
import type { EventBus } from '@aegis/events';
import type { PlatformEvent } from '@aegis/contracts';
import { generateId } from '@aegis/shared';
import type { FindingRecord, VerificationResultRecord } from '@aegis/database';
import { canTransition } from './finding-lifecycle.js';
import { SeverityEngine, type SeverityInputFields } from './severity-engine.js';
import { ConfidenceEngine } from './confidence-engine.js';
import { FindingDeduplicator, computeDedupKey } from './finding-deduplicator.js';
import { NotFoundError, ValidationError } from '@aegis/shared';

export interface CreateCandidateInput {
  engagementId: string;
  hypothesisId: string | null;
  category: string;
  title: string;
  description: string;
  observedBehavior: string;
  expectedBehavior: string | null;
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  evidenceIds: string[];
  testIds: string[];
  targetRefs: string[];
  endpointRefs: string[];
  identityRefs: string[];
}

export interface SeverityComputation {
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  cvss: {
    version: '3.1';
    vector: string;
    base_score: number;
    temporal_score: number | null;
    environmental_score: number | null;
    base_severity: string;
  };
  assessmentId: string;
}

export class FindingService {
  private readonly severityEngine = new SeverityEngine();
  private readonly confidenceEngine: ConfidenceEngine;
  private readonly deduplicator: FindingDeduplicator;

  constructor(
    private readonly deps: {
      repos: Repositories;
      eventBus: EventBus;
      confidenceWeights?: Record<string, number>;
      confidenceThresholds?: { high: number; medium: number };
    },
  ) {
    this.confidenceEngine = new ConfidenceEngine(deps.confidenceWeights, deps.confidenceThresholds);
    this.deduplicator = new FindingDeduplicator(deps.repos);
  }

  /** §6: create a candidate finding (not yet a reportable vulnerability). */
  async createCandidate(input: CreateCandidateInput): Promise<FindingRecord> {
    const finding = await this.repos().findings.createCandidate({
      engagementId: input.engagementId,
      hypothesisId: input.hypothesisId,
      title: input.title,
      description: input.description,
      severity: input.severity,
      status: 'CANDIDATE',
      evidenceIds: input.evidenceIds,
      category: input.category,
      observedBehavior: input.observedBehavior,
      expectedBehavior: input.expectedBehavior,
      targetRefs: input.targetRefs,
      affectedEndpoints: input.endpointRefs,
      affectedIdentities: input.identityRefs,
      dedupKey: computeDedupKey({
        category: input.category,
        hypothesis_id: input.hypothesisId,
        affected_endpoints: input.endpointRefs,
      }),
    });
    await this.repos().findings.recordLifecycleEvent(
      finding.id,
      input.engagementId,
      '(none)',
      'CANDIDATE',
      'candidate finding created from structured observation (§6)',
      'ENGINE',
    );
    await this.publish(input.engagementId, 'FINDING_CANDIDATE_CREATED', {
      finding_id: finding.id,
      category: input.category,
      title: input.title,
    });
    return finding;
  }

  /** §4-§5: guarded, audited lifecycle transition. */
  async transition(
    engagementId: string,
    findingId: string,
    to: string,
    reason: string,
    actor: 'ENGINE' | 'HUMAN' = 'ENGINE',
  ): Promise<FindingRecord> {
    const finding = await this.requireFinding(engagementId, findingId);
    if (finding.status === to) return finding;
    if (!canTransition(finding.status, to)) {
      throw new ValidationError(
        `Illegal finding transition ${finding.status} -> ${to} (§5 state machine)`,
        'FINDING_ILLEGAL_TRANSITION',
      );
    }
    const updated = await this.repos().findings.updateStatus(findingId, to as FindingRecord['status']);
    if (!updated) throw new ValidationError('Finding disappeared during transition', 'FINDING_MISSING');
    await this.repos().findings.recordLifecycleEvent(findingId, engagementId, finding.status, to, reason, actor);
    await this.publish(engagementId, 'FINDING_TRANSITION_RECORDED', {
      finding_id: findingId,
      from_status: finding.status,
      to_status: to,
      actor,
      reason: reason.slice(0, 400),
    });
    return updated;
  }

  /** §17-§18: deterministic CVSS severity computation (model supplies inputs). */
  async computeSeverity(
    engagementId: string,
    findingId: string,
    input: SeverityInputFields,
  ): Promise<SeverityComputation> {
    const finding = await this.requireFinding(engagementId, findingId);
    const cvss = this.severityEngine.compute(input);
    const severity = this.severityEngine.severityBand(cvss, input);
    await this.repos().severityAssessments.create(
      engagementId,
      findingId,
      input as unknown as Record<string, unknown>,
      severity,
      cvss,
      'CVSS_CALCULATOR',
    );
    await this.repos().findings.applyCvss(findingId, {
      version: cvss.version,
      vector: cvss.vector,
      baseScore: cvss.base_score,
      temporalScore: cvss.temporal_score,
      environmentalScore: cvss.environmental_score,
      baseSeverity: cvss.base_severity,
      severity,
      source: 'CVSS_CALCULATOR',
    });
    await this.publish(engagementId, 'SEVERITY_COMPUTED', {
      finding_id: findingId,
      severity,
      cvss: cvss.base_score,
      vector: cvss.vector,
      previous_severity: finding.severity,
    });
    return { severity, cvss, assessmentId: 'computed' };
  }

  /** §15: recalculate confidence from a verification result (deterministic). */
  async recalculateConfidence(engagementId: string, findingId: string, result: VerificationResultRecord): Promise<{
    confidence: number;
    level: 'HIGH' | 'MEDIUM' | 'LOW';
    reasons: string[];
  }> {
    const finding = await this.requireFinding(engagementId, findingId);
    const assessment = this.confidenceEngine.assess({
      evidenceCount: result.supporting_evidence_ids.length || finding.evidence_ids.length,
      reproduced: result.reproduced,
      reproductionConsistent: result.reproduced,
      controlComparison: result.supporting_evidence_ids.length >= 2,
      identityDifferential: (finding.affected_identities ?? []).length >= 2,
      alternativesEliminated: result.alternative_explanations.every((a) => a.refuted),
      contradictoryEvidencePresent: result.contradictory_evidence_ids.length > 0,
    });
    await this.repos().findings.enrich(findingId, {
      confidence: assessment.confidence,
      confidenceLevel: assessment.level,
      confidenceReasons: assessment.reasons,
      verificationIds: [result.id],
    });
    await this.publish(engagementId, 'CONFIDENCE_RECALCULATED', {
      finding_id: findingId,
      confidence: assessment.confidence,
      level: assessment.level,
      source: 'verification-result',
    });
    return { confidence: assessment.confidence, level: assessment.level, reasons: assessment.reasons };
  }

  /** §19-§20: deterministic deduplication (never the model's suggestion). */
  async deduplicate(engagementId: string, findingId: string): Promise<{
    duplicates: Array<{ duplicateId: string; primaryId: string }>;
    primary: string | null;
  }> {
    const finding = await this.requireFinding(engagementId, findingId);
    const outcome = await this.deduplicator.deduplicate(engagementId, finding);
    if (outcome.duplicates.length > 0) {
      await this.publish(engagementId, 'FINDING_DEDUPLICATED', {
        finding_id: findingId,
        primary: outcome.primary?.id ?? null,
        duplicates: outcome.duplicates.length,
        key: outcome.key,
      });
    }
    return {
      duplicates: outcome.duplicates,
      primary: outcome.primary?.id ?? null,
    };
  }

  /** §70: label evidence quality levels for a finding. */
  async labelEvidenceQuality(
    engagementId: string,
    findingId: string,
    entries: Array<{ evidence_id: string; quality: 'RAW' | 'EXTRACTED' | 'CORRELATED' | 'ANALYZED' | 'VERIFIED'; note?: string }>,
  ): Promise<void> {
    await this.requireFinding(engagementId, findingId);
    await this.repos().findings.setEvidenceQuality(findingId, engagementId, entries);
  }

  /** §21: the finding evidence graph (finding -> verification -> tests ->
   *  observations -> evidence -> requests). */
  async evidenceGraph(engagementId: string, findingId: string): Promise<{
    finding: FindingRecord;
    verifications: VerificationResultRecord[];
    tests: Array<Record<string, unknown>>;
    observations: Array<Record<string, unknown>>;
    evidence: Array<Record<string, unknown>>;
    requests: Array<Record<string, unknown>>;
    lifecycle: Array<Record<string, unknown>>;
  }> {
    const finding = await this.requireFinding(engagementId, findingId);
    const verifications = await this.repos().verificationResults.listByFinding(engagementId, findingId);
    const allTests = await this.repos().tests.listByEngagement(engagementId, 500).catch(() => []);
    const tests = finding.hypothesis_id
      ? allTests.filter((t) => t.hypothesis_id === finding.hypothesis_id)
      : allTests;
    const allObservations = await this.repos().observations.listByEngagement(engagementId, 500).catch(() => []);
    const observations = finding.hypothesis_id
      ? allObservations.filter((o) => o.hypothesis_id === finding.hypothesis_id)
      : allObservations;
    const evidence: Array<Record<string, unknown>> = [];
    for (const evidenceId of finding.evidence_ids.slice(0, 64)) {
      const record = await this.repos().evidence.findById(evidenceId).catch(() => null);
      if (record) evidence.push(record as unknown as Record<string, unknown>);
    }
    const requests: Array<Record<string, unknown>> = [];
    for (const item of evidence) {
      const requestId = (item.metadata as Record<string, unknown> | undefined)?.request_id;
      if (typeof requestId === 'string') {
        const request = await this.repos().httpRequests.findById(requestId).catch(() => null);
        if (request) requests.push(request as unknown as Record<string, unknown>);
      }
    }
    const lifecycle = await this.repos().findings.listLifecycleEvents(findingId);
    return {
      finding,
      verifications,
      tests: tests as unknown as Array<Record<string, unknown>>,
      observations: observations as unknown as Array<Record<string, unknown>>,
      evidence,
      requests,
      lifecycle: lifecycle as unknown as Array<Record<string, unknown>>,
    };
  }

  /** §13: reproducibility snapshot for a finding (what proves it). */
  async reproducibilitySnapshot(engagementId: string, findingId: string): Promise<Record<string, unknown>> {
    const graph = await this.evidenceGraph(engagementId, findingId);
    return {
      finding_id: findingId,
      engagement_id: engagementId,
      environment: 'recorded gateway traffic (immutable raw evidence, §23)',
      target_refs: graph.finding.target_refs,
      identity_refs: graph.finding.affected_identities,
      request_references: graph.requests.map((r) => r.id),
      verification_results: graph.verifications.map((v) => ({
        id: v.id,
        status: v.status,
        reproduced: v.reproduced,
        confidence: v.confidence,
      })),
      evidence_ids: graph.finding.evidence_ids,
      test_fingerprints: graph.tests.map((t) => (t as { fingerprint?: string }).fingerprint ?? null),
      timestamp: new Date().toISOString(),
    };
  }

  /** Apply a verification verdict to the lifecycle (§14 -> §4). */
  async applyVerificationResult(engagementId: string, result: VerificationResultRecord): Promise<FindingRecord> {
    const finding = await this.requireFinding(engagementId, result.finding_id);
    let target: string;
    if (result.status === 'VERIFIED') {
      target = finding.status === 'CONFIRMED' ? 'VERIFIED' : 'VERIFYING';
    } else if (result.status === 'REJECTED') {
      target = 'REJECTED';
    } else {
      target = 'INCONCLUSIVE';
    }
    // Merge the verification's evidence into the finding (§21 linking).
    await this.repos().findings.enrich(finding.id, {
      evidenceIds: result.supporting_evidence_ids,
      verificationIds: [result.id],
    });
    if (finding.status === target) return finding;
    // Walk the LEGAL path (§4-§5): mid-pipeline findings first move to
    // VERIFYING (via VERIFICATION_PENDING), then to the verdict state.
    const chain: string[] = [];
    const preStates = ['CANDIDATE', 'UNDER_REVIEW', 'VERIFICATION_PENDING'];
    if (preStates.includes(finding.status) && (target === 'VERIFIED' || target === 'INCONCLUSIVE' || target === 'REJECTED')) {
      if (finding.status === 'CANDIDATE') {
        chain.push('UNDER_REVIEW');
      }
      if (finding.status === 'CANDIDATE' || finding.status === 'UNDER_REVIEW') {
        chain.push('VERIFICATION_PENDING');
      }
      chain.push('VERIFYING');
    }
    chain.push(target);
    let current = finding;
    for (const step of chain) {
      if (current.status === step) continue;
      current = await this.transition(
        engagementId,
        finding.id,
        step,
        `verification ${result.id} verdict ${result.status} (§14)`,
        'ENGINE',
      ).catch(async (error: unknown) => {
        // CONFIRMED findings promoted by Part 6 may verify directly.
        if (finding.status === 'CONFIRMED' && step === 'VERIFIED') {
          return this.transition(engagementId, finding.id, 'VERIFIED', `verification ${result.id} (§14)`, 'ENGINE');
        }
        throw error;
      });
    }
    return current;
  }

  private requireFinding(engagementId: string, findingId: string): Promise<FindingRecord> {
    return this.repos()
      .findings.findByIdAndEngagement(findingId, engagementId)
      .then((finding) => {
        if (!finding) {
          throw new NotFoundError('Finding not found for this engagement', 'FINDING_NOT_FOUND');
        }
        return finding;
      });
  }

  private repos(): Repositories {
    return this.deps.repos;
  }

  private async publish(engagementId: string, type: string, payload: Record<string, unknown>): Promise<void> {
    const event: PlatformEvent = {
      type: type as PlatformEvent['type'],
      engagement_id: engagementId,
      trace_id: generateId('TRC'),
      actor_id: null,
      payload,
      occurred_at: new Date().toISOString(),
      dedup_key: `vr:${type}:${engagementId}:${payload.finding_id ?? ''}:${Date.now()}`,
    };
    await this.deps.eventBus.publish(event).catch(() => undefined);
  }
}
