/**
 * Verifier (spec Part 7 §2, §8, §11-§14, §72, §74-§75).
 *
 * Discovery and verification are SEPARATE (§2). The verifier drives the full
 * pipeline for one candidate finding:
 *
 *   PLAN (§8) -> sufficiency gate (§7) -> REPRODUCTION (§12) ->
 *   CONTROL COMPARISON (§9) -> ALTERNATIVE EXPLANATIONS (§10) ->
 *   policy evaluation (§71-§72) -> CONFIDENCE (§15) -> VERDICT (§14)
 *
 * Verdict semantics (§14, §75): VERIFIED requires policy satisfaction AND
 * elimination of alternative explanations AND (for high-risk findings) the
 * raised confidence threshold (§72). REJECTED when a control REFUTES the
 * hypothesis. INCONCLUSIVE otherwise — ambiguity is never confirmation
 * (§74: a good security agent must know when it does not know).
 */
import type { Repositories } from '@aegis/database';
import type { FindingRecord, VerificationResultRecord } from '@aegis/database';
import type { EventBus } from '@aegis/events';
import type { PlatformEvent } from '@aegis/contracts';
import { generateId } from '@aegis/shared';
import type { ControlledHttpPort, ReasoningVerificationPort } from '../ports.js';
import { VerificationPlanner } from './verification-planner.js';
import { ReproductionEngine } from './reproduction-engine.js';
import { ControlTestEngine } from './control-test-engine.js';
import { AlternativeExplanationEngine } from './alternative-explanation-engine.js';
import { evaluatePolicy } from './verification-policy.js';
import type { VerificationStrategy } from './verification-policy.js';
import { ConfidenceEngine } from '../findings/confidence-engine.js';

export interface VerifyFindingOptions {
  strategies?: VerificationStrategy[];
}

export interface VerifyFindingResult {
  findingId: string;
  planId: string;
  result: VerificationResultRecord;
  transition: string;
  violations: Array<{ requirement: string; detail: string }>;
}

export class Verifier {
  private readonly planner: VerificationPlanner;
  private readonly reproduction: ReproductionEngine;
  private readonly controls: ControlTestEngine;
  private readonly alternatives: AlternativeExplanationEngine;
  private readonly confidence: ConfidenceEngine;

  constructor(
    private readonly deps: {
      repos: Repositories;
      eventBus: EventBus;
      http: ControlledHttpPort;
      reasoning: ReasoningVerificationPort;
      confidenceWeights?: Record<string, number>;
      confidenceThresholds?: { high: number; medium: number };
    },
  ) {
    this.planner = new VerificationPlanner(deps.repos);
    this.reproduction = new ReproductionEngine(deps.repos, deps.http);
    this.controls = new ControlTestEngine(deps.repos);
    this.alternatives = new AlternativeExplanationEngine(deps.repos);
    this.confidence = new ConfidenceEngine(deps.confidenceWeights, deps.confidenceThresholds);
  }

  async verifyFinding(
    engagementId: string,
    finding: FindingRecord,
    options: VerifyFindingOptions = {},
  ): Promise<VerifyFindingResult> {
    // --- 1. PLAN (§8) ------------------------------------------------------
    const planned = await this.planner.plan(finding, { strategies: options.strategies });
    const plan = await this.deps.repos.verificationPlans.create({
      engagementId,
      findingId: finding.id,
      strategies: planned.strategies,
      controls: planned.controls,
      expectedResult: planned.expectedResult,
      requiredEvidence: planned.requiredEvidence,
      sufficiency: planned.sufficiency,
    });
    await this.publish(engagementId, 'VERIFICATION_PLAN_CREATED', {
      plan_id: plan.id,
      finding_id: finding.id,
      strategies: planned.strategies,
      sufficient: planned.sufficiency.sufficient,
    });
    await this.deps.repos.verificationPlans.markExecuting(plan.id);

    try {
      // --- 2. Part 4 bridge: skeptical checklist over the hypothesis -------
      let part4Checklist: Array<{ check: string; status: string; detail: string }> = [];
      let part4Alternatives: Awaited<ReturnType<ReasoningVerificationPort['verify']>>['outcome']['alternatives'] = [];
      let part4Verdict: 'VERIFIED' | 'REFUTED' | 'INCONCLUSIVE' | null = null;
      let part4EvidenceIds: string[] = [];
      if (finding.hypothesis_id) {
        try {
          const bridge = await this.deps.reasoning.verify({
            engagementId,
            hypothesisId: finding.hypothesis_id,
          });
          part4Checklist = bridge.outcome.checklist;
          part4Alternatives = bridge.outcome.alternatives;
          part4Verdict = bridge.outcome.status;
          part4EvidenceIds = bridge.outcome.evidenceIds;
        } catch {
          // The Part 4 bridge is best-effort: the Part 7 pipeline continues
          // with its own controls when the hypothesis is unverifiable there.
        }
      }

      // --- 3. REPRODUCTION (§12) ------------------------------------------
      const shouldReproduce = planned.strategies.includes('REPRODUCTION');
      const reproductionOutcome = shouldReproduce
        ? await this.reproduction.reproduce(finding)
        : null;
      if (reproductionOutcome) {
        await this.publish(engagementId, 'REPRODUCTION_ATTEMPTED', {
          finding_id: finding.id,
          plan_id: plan.id,
          reproduced: reproductionOutcome.reproduced,
          consistent: reproductionOutcome.consistent,
        });
      }

      // --- 4. CONTROL COMPARISON (§9) ---------------------------------------
      const controlOutcome = await this.controls.runControls(finding);
      await this.publish(engagementId, 'CONTROL_TEST_EXECUTED', {
        finding_id: finding.id,
        plan_id: plan.id,
        controls: controlOutcome.results.length,
        control_comparison: controlOutcome.controlComparison,
      });

      // --- 5. ALTERNATIVE EXPLANATIONS (§10) --------------------------------
      const alternativeOutcome = await this.alternatives.testAlternatives(
        finding,
        part4Alternatives,
        part4Checklist,
      );
      await this.publish(engagementId, 'ALTERNATIVE_EXPLANATION_TESTED', {
        finding_id: finding.id,
        plan_id: plan.id,
        tested: alternativeOutcome.explanations.length,
        surviving: alternativeOutcome.surviving.length,
      });

      // --- 6. CONFIDENCE (§15) ----------------------------------------------
      const assessment = this.confidence.assess({
        evidenceCount: finding.evidence_ids.length + part4EvidenceIds.length,
        reproduced: reproductionOutcome?.reproduced ?? false,
        reproductionConsistent: reproductionOutcome?.consistent ?? false,
        controlComparison: controlOutcome.controlComparison,
        identityDifferential: controlOutcome.identityDifferential,
        alternativesEliminated: alternativeOutcome.allEliminated,
        contradictoryEvidencePresent: part4Verdict === 'REFUTED',
      });
      await this.publish(engagementId, 'CONFIDENCE_RECALCULATED', {
        finding_id: finding.id,
        confidence: assessment.confidence,
        level: assessment.level,
      });

      // --- 7. POLICY + VERDICT (§14, §71-§72, §75) ---------------------------
      const violations = evaluatePolicy({
        policy: planned.policy,
        evidenceCount: finding.evidence_ids.length,
        reproduced: reproductionOutcome?.reproduced ?? false,
        controlComparison: controlOutcome.controlComparison,
        identityDifferential: controlOutcome.identityDifferential,
        alternativesEliminated: alternativeOutcome.allEliminated,
        confidence: assessment.confidence,
      });

      // Control REFUTES the hypothesis -> REJECTED (not merely INCONCLUSIVE).
      const controlRefutes =
        controlOutcome.results.some((r) => r.satisfied === false) || part4Verdict === 'REFUTED';
      const verdict: 'VERIFIED' | 'REJECTED' | 'INCONCLUSIVE' = controlRefutes
        ? 'REJECTED'
        : violations.length === 0 && alternativeOutcome.allEliminated
          ? 'VERIFIED'
          : 'INCONCLUSIVE';

      const reasoningSummary = this.buildReasoningSummary({
        finding,
        planned,
        reproduction: reproductionOutcome,
        controls: controlOutcome,
        alternatives: alternativeOutcome,
        assessment,
        violations,
        verdict,
      });

      const result = await this.deps.repos.verificationResults.create({
        engagementId,
        findingId: finding.id,
        planId: plan.id,
        status: verdict,
        confidence: assessment.confidence,
        supportingEvidenceIds: [
          ...new Set([...part4EvidenceIds, ...(reproductionOutcome?.evidenceIds ?? []), ...controlOutcome.evidenceIds]),
        ],
        contradictoryEvidenceIds: controlRefutes
          ? controlOutcome.results.filter((r) => r.satisfied === false).flatMap((r) => r.evidenceIds)
          : [],
        reproduced: reproductionOutcome?.reproduced ?? false,
        alternativeExplanations: alternativeOutcome.explanations,
        reasoningSummary,
      });
      await this.deps.repos.verificationPlans.complete(plan.id, result.id);
      await this.publish(engagementId, 'VERIFICATION_PLAN_EXECUTED', {
        finding_id: finding.id,
        plan_id: plan.id,
        result_id: result.id,
        verdict,
      });

      return {
        findingId: finding.id,
        planId: plan.id,
        result,
        transition: verdict,
        violations,
      };
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      await this.deps.repos.verificationPlans.fail(plan.id, message);
      throw error;
    }
  }

  private buildReasoningSummary(input: {
    finding: FindingRecord;
    planned: import('./verification-planner.js').PlannedVerification;
    reproduction: import('./reproduction-engine.js').ReproductionOutcome | null;
    controls: import('./control-test-engine.js').ControlComparisonOutcome;
    alternatives: import('./alternative-explanation-engine.js').AlternativeExplanationOutcome;
    assessment: import('../findings/confidence-engine.js').ConfidenceAssessmentResult;
    violations: Array<{ requirement: string; detail: string }>;
    verdict: 'VERIFIED' | 'REJECTED' | 'INCONCLUSIVE';
  }): string {
    const lines: string[] = [];
    lines.push(`Finding ${input.finding.id} (${input.finding.title}).`);
    lines.push(`Verification plan strategies: ${input.planned.strategies.join(', ')} (§9).`);
    lines.push(
      input.planned.sufficiency.sufficient
        ? `Evidence sufficiency (§7): all dimensions present.`
        : `Evidence sufficiency (§7): missing ${input.planned.sufficiency.missing.join(', ')}.`,
    );
    if (input.reproduction) {
      lines.push(`Reproduction (§12): ${input.reproduction.note}`);
    } else {
      lines.push('Reproduction (§12): not required by the plan strategy.');
    }
    lines.push(`Control comparison (§9): ${input.controls.note}`);
    lines.push(`Alternative explanations (§10): ${input.alternatives.note}`);
    lines.push(
      `Confidence (§15): ${input.assessment.confidence.toFixed(3)} (${input.assessment.level}) from dimensions: ${Object.entries(
        input.assessment.dimensions,
      )
        .map(([k, v]) => `${k}=${v.toFixed(2)}`)
        .join(', ')}.`,
    );
    if (input.violations.length > 0) {
      lines.push(
        `Policy violations (§71): ${input.violations.map((v) => `${v.requirement} — ${v.detail}`).join('; ')}.`,
      );
    }
    lines.push(
      input.verdict === 'VERIFIED'
        ? 'Verdict: VERIFIED — every policy requirement satisfied and all alternative explanations eliminated.'
        : input.verdict === 'REJECTED'
          ? 'Verdict: REJECTED — a control condition refuted the suspected behavior.'
          : 'Verdict: INCONCLUSIVE — the evidence does not yet support confirmation (§74: uncertainty stays uncertainty).',
    );
    return lines.join(' ');
  }

  private async publish(engagementId: string, type: string, payload: Record<string, unknown>): Promise<void> {
    const event: PlatformEvent = {
      type: type as PlatformEvent['type'],
      engagement_id: engagementId,
      trace_id: generateId('TRC'),
      actor_id: null,
      payload,
      occurred_at: new Date().toISOString(),
      dedup_key: `vr:${type}:${engagementId}:${payload.finding_id ?? ''}:${payload.plan_id ?? Date.now()}`,
    };
    await this.deps.eventBus.publish(event).catch(() => undefined);
  }
}
