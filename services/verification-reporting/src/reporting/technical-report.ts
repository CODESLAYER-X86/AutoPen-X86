/**
 * Technical report (spec Part 7 §27-§28).
 *
 * Finding template (§28): title, severity, confidence, components, summary,
 * technical details, expected/observed behavior, impact, preconditions,
 * evidence (rendered, §29), reproduction, remediation, verification status.
 */
import type { FindingRecord } from '@aegis/database';
import type { VerificationResultRecord } from '@aegis/database';
import type { RenderedEvidence } from './evidence-renderer.js';
import type { RemediationGuidance } from './remediation-builder.js';

export interface TechnicalFindingSection {
  /** §28 template fields. */
  id: string;
  title: string;
  severity: string;
  confidence: { value: number | null; level: string | null; reasons: string[] };
  affected_components: string[];
  affected_endpoints: string[];
  summary: string;
  technical_details: string;
  expected_behavior: string;
  observed_behavior: string;
  impact: string;
  preconditions: string[];
  evidence: RenderedEvidence[];
  evidence_references: string[];
  reproduction: { plan: string; steps: string[] };
  remediation: RemediationGuidance | null;
  verification: {
    status: string;
    confidence: number | null;
    reproduced: boolean;
    alternative_explanations: Array<{ label: string; refuted: boolean; refutation: string | null }>;
    reasoning_summary: string;
    result_id: string | null;
  };
  reported_status: 'VERIFIED' | 'NOT_VERIFIED';
  retest_state: string;
}

export interface TechnicalReportContent {
  title: string;
  engagement: { id: string; name: string; mode: string };
  generated_at: string;
  finding_sections: TechnicalFindingSection[];
  statistics: Record<string, number>;
}

export class TechnicalReportBuilder {
  build(input: {
    engagement: { id: string; name: string; mode: string };
    generatedAt: string;
    findings: FindingRecord[];
    renderedEvidence: Map<string, RenderedEvidence[]>;
    remediations: Map<string, RemediationGuidance>;
    verifications: Map<string, VerificationResultRecord>;
    reproductionPlans: Map<string, Array<{ kind: string; reference: string; description: string }>>;
  }): TechnicalReportContent {
    const findingSections = input.findings.map((finding): TechnicalFindingSection => {
      const evidence = input.renderedEvidence.get(finding.id) ?? [];
      const remediation = input.remediations.get(finding.id) ?? null;
      const verification = input.verifications.get(finding.id) ?? null;
      const reproduction = input.reproductionPlans.get(finding.id) ?? [];

      return {
        id: finding.id,
        title: finding.title,
        severity: finding.severity,
        confidence: {
          value: finding.confidence,
          level: finding.confidence_level,
          reasons: finding.confidence_reasons ?? [],
        },
        affected_components: finding.target_refs,
        affected_endpoints: finding.affected_endpoints,
        summary: finding.description.slice(0, 1200),
        technical_details: finding.description,
        expected_behavior:
          finding.expected_behavior ?? 'The expected security control was not recorded for this finding.',
        observed_behavior: finding.observed_behavior ?? finding.description,
        impact: finding.impact ?? remediation?.rootCause
          ? `Root cause: ${remediation?.rootCause ?? 'not classified'}`
          : 'Impact statement pending enrichment.',
        preconditions: [
          ...(verification ? ['verification plan prerequisites satisfied'] : []),
          ...(finding.affected_identities.length > 0
            ? [`identity material for ${finding.affected_identities.join(', ')}`]
            : []),
          'target reachable within the engagement scope',
        ],
        evidence,
        evidence_references: evidence.map((e) => e.evidence_reference),
        reproduction: {
          plan: reproduction.length > 0 ? 'controlled reproduction plan (§12)' : 'not recorded',
          steps: reproduction.map((s) => `${s.kind}: ${s.description}`),
        },
        remediation,
        verification: {
          status: finding.status,
          confidence: verification?.confidence ?? finding.confidence,
          reproduced: verification?.reproduced ?? false,
          alternative_explanations: (verification?.alternative_explanations ?? []).map((a) => ({
            label: a.label,
            refuted: a.refuted,
            refutation: a.refutation,
          })),
          reasoning_summary: verification?.reasoning_summary ?? 'No verification result recorded for this finding.',
          result_id: verification?.id ?? null,
        },
        // §75: reported status stays binary; uncertainty is internal.
        reported_status: finding.status === 'VERIFIED' || finding.status === 'ACCEPTED' ? 'VERIFIED' : 'NOT_VERIFIED',
        retest_state: finding.retest_state,
      };
    });

    const statistics: Record<string, number> = {
      findings_total: input.findings.length,
      verified: input.findings.filter((f) => f.status === 'VERIFIED' || f.status === 'ACCEPTED').length,
      with_evidence: input.findings.filter((f) => f.evidence_ids.length > 0).length,
      with_verification: input.findings.filter((f) => f.verification_ids.length > 0).length,
      reproduced: input.findings.filter((f) => input.verifications.get(f.id)?.reproduced).length,
    };

    return {
      title: `Technical Report — ${input.engagement.name}`,
      engagement: input.engagement,
      generated_at: input.generatedAt,
      finding_sections: findingSections,
      statistics,
    };
  }
}
