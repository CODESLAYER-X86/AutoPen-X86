/**
 * Part 7 unit tests — deterministic engines (spec §94).
 *
 * Confidence calculator, severity calculator (CVSS 3.1), finding lifecycle,
 * deduplication, redaction, claim validation, verification policy, report
 * exporters (Markdown / HTML / JSON / PDF) and benchmark scoring math. All
 * deterministic — no database, no network.
 */
import { describe, expect, it } from 'vitest';
import { ConfidenceEngine } from '@aegis/vr';
import { SeverityEngine } from '@aegis/vr';
import { canTransition, isTerminal, verdictToStatus, FINDING_TRANSITIONS } from '@aegis/vr';
import { computeDedupKey, normalizeEndpointShape } from '@aegis/vr';
import { redactText, containsUnredactedSecret } from '@aegis/vr';
import { ClaimValidator } from '../../services/verification-reporting/src/reporting/claim-validator.js';
import { resolvePolicy, evaluatePolicy, CATEGORY_POLICIES } from '@aegis/vr';
import { precisionRecall, agentEfficiencyScore, timeToFinding } from '../../services/verification-reporting/src/evaluation/metrics.js';
import { renderMarkdown, renderJson, renderHtml, renderPdf } from '@aegis/vr';
import { SCENARIO_SEEDS } from '@aegis/vr';
import type { FindingRecord } from '@aegis/database';

// ---------------------------------------------------------------------------
// Confidence engine (§15-§16)
// ---------------------------------------------------------------------------

describe('confidence engine (§15-§16)', () => {
  const engine = new ConfidenceEngine();

  it('never lets severity influence confidence (confidence is NOT severity, §16)', () => {
    // The input has NO severity dimension at all.
    const assessment = engine.assess({
      evidenceCount: 4,
      reproduced: true,
      reproductionConsistent: true,
      controlComparison: true,
      identityDifferential: true,
      alternativesEliminated: true,
      contradictoryEvidencePresent: false,
    });
    expect(assessment.confidence).toBeGreaterThan(0.75);
    expect(assessment.level).toBe('HIGH');
    expect(Object.keys(assessment.dimensions)).not.toContain('severity');
    expect(Object.keys(assessment.dimensions)).not.toContain('impact');
  });

  it('weak evidence stays uncertain', () => {
    const assessment = engine.assess({
      evidenceCount: 0,
      reproduced: false,
      reproductionConsistent: false,
      controlComparison: false,
      identityDifferential: false,
      alternativesEliminated: false,
      contradictoryEvidencePresent: false,
    });
    expect(assessment.confidence).toBeLessThan(0.45);
    expect(assessment.level).toBe('LOW');
  });

  it('contradictory evidence DECREASES confidence (§82: never ignored)', () => {
    const base = {
      evidenceCount: 4,
      reproduced: true,
      reproductionConsistent: true,
      controlComparison: true,
      identityDifferential: true,
      alternativesEliminated: true,
    };
    const without = new ConfidenceEngine().assess({ ...base, contradictoryEvidencePresent: false });
    const withContradiction = new ConfidenceEngine().assess({ ...base, contradictoryEvidencePresent: true });
    expect(withContradiction.confidence).toBeLessThan(without.confidence);
    expect(withContradiction.reasons.some((r) => r.toLowerCase().includes('contradictory'))).toBe(true);
  });

  it('reproduction without consistency scores lower than consistent reproduction', () => {
    const base = {
      evidenceCount: 3,
      controlComparison: true,
      identityDifferential: true,
      alternativesEliminated: true,
      contradictoryEvidencePresent: false,
    };
    const consistent = engine.assess({ ...base, reproduced: true, reproductionConsistent: true });
    const inconsistent = engine.assess({ ...base, reproduced: true, reproductionConsistent: false });
    expect(inconsistent.confidence).toBeLessThan(consistent.confidence);
  });

  it('weights and thresholds are configurable (§15)', () => {
    const custom = new ConfidenceEngine({ reproducibility: 1 }, { high: 0.3, medium: 0.2 });
    const assessment = custom.assess({
      evidenceCount: 0,
      reproduced: true,
      reproductionConsistent: true,
      controlComparison: false,
      identityDifferential: false,
      alternativesEliminated: false,
      contradictoryEvidencePresent: false,
    });
    // With reproducibility weight 1.0 and LOW thresholds, reproduction alone
    // crosses the custom HIGH band.
    expect(assessment.level).toBe('HIGH');
  });
});

// ---------------------------------------------------------------------------
// Severity engine — CVSS 3.1 (§17-§18)
// ---------------------------------------------------------------------------

describe('severity engine / CVSS 3.1 (§17-§18)', () => {
  const engine = new SeverityEngine();

  it('computes the canonical CVSS 3.1 base scores exactly', () => {
    // Known FIRST examples.
    const critical = engine.compute({
      attack_vector: 'NETWORK',
      attack_complexity: 'LOW',
      privileges_required: 'NONE',
      user_interaction: 'NONE',
      scope: 'UNCHANGED',
      confidentiality_impact: 'HIGH',
      integrity_impact: 'HIGH',
      availability_impact: 'HIGH',
      data_sensitivity: 'MEDIUM',
      business_impact: 'MEDIUM',
      exploitability_ease: 'MEDIUM',
    });
    expect(critical.base_score).toBe(9.8);
    expect(critical.base_severity).toBe('CRITICAL');
    expect(critical.vector).toBe('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H');

    const scopeChanged = engine.compute({
      attack_vector: 'NETWORK',
      attack_complexity: 'LOW',
      privileges_required: 'NONE',
      user_interaction: 'NONE',
      scope: 'CHANGED',
      confidentiality_impact: 'HIGH',
      integrity_impact: 'HIGH',
      availability_impact: 'HIGH',
      data_sensitivity: 'MEDIUM',
      business_impact: 'MEDIUM',
      exploitability_ease: 'MEDIUM',
    });
    expect(scopeChanged.base_score).toBe(10);
    expect(scopeChanged.vector).toContain('S:C');

    const none = engine.compute({
      attack_vector: 'NETWORK',
      attack_complexity: 'LOW',
      privileges_required: 'NONE',
      user_interaction: 'NONE',
      scope: 'UNCHANGED',
      confidentiality_impact: 'NONE',
      integrity_impact: 'NONE',
      availability_impact: 'NONE',
      data_sensitivity: 'LOW',
      business_impact: 'LOW',
      exploitability_ease: 'LOW',
    });
    expect(none.base_score).toBe(0);
    expect(none.base_severity).toBe('NONE');

    const medium = engine.compute({
      attack_vector: 'NETWORK',
      attack_complexity: 'LOW',
      privileges_required: 'NONE',
      user_interaction: 'NONE',
      scope: 'UNCHANGED',
      confidentiality_impact: 'NONE',
      integrity_impact: 'LOW',
      availability_impact: 'NONE',
      data_sensitivity: 'MEDIUM',
      business_impact: 'MEDIUM',
      exploitability_ease: 'MEDIUM',
    });
    expect(medium.base_score).toBe(5.3);
    expect(medium.base_severity).toBe('MEDIUM');
  });

  it('business dimensions can raise at most one band and never invent CVSS (§18)', () => {
    const cvss = engine.compute({
      attack_vector: 'NETWORK',
      attack_complexity: 'LOW',
      privileges_required: 'NONE',
      user_interaction: 'NONE',
      scope: 'UNCHANGED',
      confidentiality_impact: 'NONE',
      integrity_impact: 'LOW',
      availability_impact: 'NONE',
      data_sensitivity: 'MEDIUM',
      business_impact: 'MEDIUM',
      exploitability_ease: 'MEDIUM',
    });
    expect(cvss.base_score).toBe(5.3); // CVSS itself is untouched by business input
    const bandNeutral = engine.severityBand(cvss, {
      attack_vector: 'NETWORK',
      attack_complexity: 'LOW',
      privileges_required: 'NONE',
      user_interaction: 'NONE',
      scope: 'UNCHANGED',
      confidentiality_impact: 'NONE',
      integrity_impact: 'LOW',
      availability_impact: 'NONE',
      data_sensitivity: 'MEDIUM',
      business_impact: 'MEDIUM',
      exploitability_ease: 'MEDIUM',
    });
    expect(bandNeutral).toBe('MEDIUM');
    const bandBoost = engine.severityBand(cvss, {
      attack_vector: 'NETWORK',
      attack_complexity: 'LOW',
      privileges_required: 'NONE',
      user_interaction: 'NONE',
      scope: 'UNCHANGED',
      confidentiality_impact: 'NONE',
      integrity_impact: 'LOW',
      availability_impact: 'NONE',
      data_sensitivity: 'HIGH',
      business_impact: 'HIGH',
      exploitability_ease: 'HIGH',
    });
    expect(bandBoost).toBe('HIGH'); // one band, no more
    const noneImpact = engine.compute({
      attack_vector: 'NETWORK',
      attack_complexity: 'LOW',
      privileges_required: 'NONE',
      user_interaction: 'NONE',
      scope: 'UNCHANGED',
      confidentiality_impact: 'NONE',
      integrity_impact: 'NONE',
      availability_impact: 'NONE',
      data_sensitivity: 'HIGH',
      business_impact: 'HIGH',
      exploitability_ease: 'HIGH',
    });
    // A NONE-impact input stays LOW band (business can never create impact).
    expect(engine.severityBand(noneImpact, {
      attack_vector: 'NETWORK',
      attack_complexity: 'LOW',
      privileges_required: 'NONE',
      user_interaction: 'NONE',
      scope: 'UNCHANGED',
      confidentiality_impact: 'NONE',
      integrity_impact: 'NONE',
      availability_impact: 'NONE',
      data_sensitivity: 'HIGH',
      business_impact: 'HIGH',
      exploitability_ease: 'HIGH',
    })).toBe('MEDIUM'); // exactly one band above the LOW floor — never CRITICAL
  });
});

// ---------------------------------------------------------------------------
// Finding lifecycle (§4-§5)
// ---------------------------------------------------------------------------

describe('finding lifecycle (§4-§5)', () => {
  it('follows the §4 pipeline and rejects illegal jumps', () => {
    expect(canTransition('CANDIDATE', 'UNDER_REVIEW')).toBe(true);
    expect(canTransition('UNDER_REVIEW', 'VERIFICATION_PENDING')).toBe(true);
    expect(canTransition('VERIFICATION_PENDING', 'VERIFYING')).toBe(true);
    expect(canTransition('VERIFYING', 'VERIFIED')).toBe(true);
    expect(canTransition('VERIFYING', 'INCONCLUSIVE')).toBe(true);
    expect(canTransition('VERIFYING', 'REJECTED')).toBe(true);
    expect(canTransition('CANDIDATE', 'DUPLICATE')).toBe(true);
    expect(canTransition('CANDIDATE', 'VERIFIED')).toBe(false);
    expect(canTransition('CANDIDATE', 'VERIFYING')).toBe(false);
    expect(canTransition('VERIFIED', 'ACCEPTED')).toBe(true);
    expect(canTransition('ACCEPTED', 'CANDIDATE')).toBe(false);
  });

  it('keeps terminal states terminal (rejected findings are never deleted, §4)', () => {
    expect(isTerminal('REJECTED')).toBe(true);
    expect(isTerminal('DUPLICATE')).toBe(true);
    expect(isTerminal('ACCEPTED')).toBe(true);
    expect(FINDING_TRANSITIONS.REJECTED!.length).toBe(0);
  });

  it('maps verification verdicts to lifecycle statuses (§14 -> §4)', () => {
    expect(verdictToStatus('VERIFIED')).toBe('VERIFIED');
    expect(verdictToStatus('REJECTED')).toBe('REJECTED');
    expect(verdictToStatus('INCONCLUSIVE')).toBe('INCONCLUSIVE');
  });
});

// ---------------------------------------------------------------------------
// Deduplication keys (§19-§20)
// ---------------------------------------------------------------------------

describe('deduplication (§19-§20)', () => {
  it('normalizes endpoint shapes so /api/users/101 and /api/users/102 merge', () => {
    expect(normalizeEndpointShape('/api/users/101')).toBe(normalizeEndpointShape('/api/users/102'));
    expect(normalizeEndpointShape('/api/users/101?x=1')).toBe('/api/users/{id}');
    expect(normalizeEndpointShape('/api/orders/201')).not.toBe(normalizeEndpointShape('/api/users/101'));
  });

  it('computes stable keys from category + hypothesis + endpoint shapes', () => {
    const a = computeDedupKey({
      category: 'AUTHORIZATION',
      hypothesis_id: 'HYP_1',
      affected_endpoints: ['/api/users/101', '/api/users/102'],
    });
    const b = computeDedupKey({
      category: 'AUTHORIZATION',
      hypothesis_id: 'HYP_1',
      affected_endpoints: ['/api/users/555'],
    });
    const c = computeDedupKey({
      category: 'SESSION',
      hypothesis_id: 'HYP_1',
      affected_endpoints: ['/api/users/101'],
    });
    expect(a).toBe(b);
    expect(a).not.toBe(c);
  });
});

// ---------------------------------------------------------------------------
// Redaction (§24)
// ---------------------------------------------------------------------------

describe('redaction (§24)', () => {
  it('redacts cookies, authorization headers, JWTs, keys and emails', () => {
    const input = [
      'Cookie: session=abc123def456ghi789',
      'Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.dozjgNryP4J3jVmNHl0w5KzHj5m0V0',
      'Set-Cookie: LABSESS=xyz987654321; Path=/',
      'api_key = "sk-live-abcdefghijklmnop"',
      'contact: admin@example.com',
      'password: hunter2secret',
    ].join('\n');
    const result = redactText(input, 'test');
    expect(result.text).not.toContain('abc123def456ghi789');
    expect(result.text).not.toContain('eyJhbGciOiJIUzI1NiJ9');
    expect(result.text).not.toContain('xyz987654321');
    expect(result.text).not.toContain('sk-live-abcdefghijklmnop');
    expect(result.text).not.toContain('admin@example.com');
    expect(result.text).not.toContain('hunter2secret');
    expect(result.count).toBeGreaterThanOrEqual(6);
    expect(result.records.length).toBeGreaterThan(0);
  });

  it('detection finds surviving secrets (§65 validation hook)', () => {
    expect(containsUnredactedSecret('Cookie: session=rawsecretvalue1').found).toBe(true);
    expect(containsUnredactedSecret('Cookie: <REDACTED>').found).toBe(false);
    expect(containsUnredactedSecret('Authorization: Bearer abcdef123456').found).toBe(true);
    expect(containsUnredactedSecret('plain text without secrets').found).toBe(false);
  });

  it('leaves ordinary technical content untouched', () => {
    const input = 'GET /api/notes/1 HTTP/1.1\n200 OK\n{"id":"1","owner":"userb"}';
    const result = redactText(input, 'test');
    expect(result.count).toBe(0);
    expect(result.text).toBe(input);
  });
});

// ---------------------------------------------------------------------------
// Claim validation (§33-§34)
// ---------------------------------------------------------------------------

describe('claim validation (§33-§34)', () => {
  const validator = new ClaimValidator();

  const finding = {
    id: 'FND_TEST_FINDING_0001',
    engagement_id: 'ENG_TEST_FINDING_0001',
    hypothesis_id: null,
    title: 'Authorization control failure',
    description: 'd',
    severity: 'HIGH',
    status: 'VERIFIED',
    evidence_ids: ['EVD_AAAAAAAAAAAAAAAA', 'EVD_BBBBBBBBBBBBBBBB'],
    created_at: '2026-01-01T00:00:00Z',
    updated_at: '2026-01-01T00:00:00Z',
    category: 'AUTHORIZATION',
    confidence: 0.9,
    confidence_level: 'HIGH',
    confidence_reasons: [],
    impact: null,
    remediation: null,
    verification_ids: ['VER_TEST_VERIFICATION_'],
    target_refs: [],
    affected_endpoints: ['/api/notes/1'],
    affected_identities: ['IDN_AAAAAAAAAAAAAAAA'],
    mode: 'PENTEST',
    retest_state: 'NOT_RETESTED' as const,
    cvss: null,
    severity_source: 'CVSS_CALCULATOR' as const,
    dedup_key: null,
    duplicate_of: null,
    observed_behavior: 'USER_A received an object owned by USER_B',
    expected_behavior: 'denied',
  } satisfies FindingRecord;

  it('marks claims with no evidence as UNSUPPORTED', () => {
    const claim = {
      id: 'CLM_TEST_CLAIM_000001',
      finding_id: finding.id,
      text: 'The endpoint is vulnerable.',
      evidence_ids: [],
      confidence: 0.5,
      support: 'SUPPORTED' as const,
      revision_of: null,
    };
    const assessment = validator.assess(claim, finding, 0);
    expect(assessment.claim.support).toBe('UNSUPPORTED');
    expect(assessment.issue).toContain('no evidence');
  });

  it('rewrites universal claims to the tested scope (§33 example)', () => {
    const claim = {
      id: 'CLM_TEST_CLAIM_000002',
      finding_id: finding.id,
      text: 'Any authenticated user can access all objects.',
      evidence_ids: finding.evidence_ids,
      confidence: 0.9,
      support: 'SUPPORTED' as const,
      revision_of: null,
    };
    const assessment = validator.assess(claim, finding, 2);
    expect(assessment.claim.support).toBe('BROADER_THAN_EVIDENCE');
    expect(assessment.rewritten).toBe(true);
    expect(assessment.claim.text).not.toMatch(/\bany\b/i);
    expect(assessment.claim.text).toContain('/api/notes/1');
    expect(assessment.claim.text).toContain('§33');
  });

  it('builds evidence-mapped claims from structured finding fields (§34)', () => {
    const claims = validator.buildClaimsForFinding(finding);
    expect(claims.length).toBeGreaterThanOrEqual(3);
    for (const claim of claims) {
      expect(claim.evidence_ids.length).toBeGreaterThan(0);
    }
  });
});

// ---------------------------------------------------------------------------
// Verification policy (§71-§72)
// ---------------------------------------------------------------------------

describe('verification policy (§71-§72)', () => {
  it('authorization findings require identity differentials (§71)', () => {
    const policy = resolvePolicy('AUTHORIZATION', 'HIGH');
    expect(policy.requireIdentityDifferential).toBe(true);
    expect(policy.strategies).toContain('IDENTITY_DIFFERENTIAL');
  });

  it('high-risk findings get the stricter gate (§72)', () => {
    const low = resolvePolicy('INFORMATION_DISCLOSURE', 'LOW');
    const critical = resolvePolicy('INFORMATION_DISCLOSURE', 'CRITICAL');
    expect(critical.requireReproduction).toBe(true);
    expect(critical.requireControlComparison).toBe(true);
    expect(critical.confidenceThreshold).toBeGreaterThanOrEqual(0.75);
    expect(critical.minimumEvidence).toBeGreaterThanOrEqual(3);
    expect(low.confidenceThreshold).toBeLessThan(critical.confidenceThreshold);
    expect(CATEGORY_POLICIES.length).toBeGreaterThanOrEqual(4);
  });

  it('evaluates violations deterministically (§72)', () => {
    const policy = resolvePolicy('AUTHORIZATION', 'CRITICAL');
    const violations = evaluatePolicy({
      policy,
      evidenceCount: 1,
      reproduced: false,
      controlComparison: false,
      identityDifferential: false,
      alternativesEliminated: false,
      confidence: 0.4,
    });
    const requirements = violations.map((v) => v.requirement);
    expect(requirements).toContain('minimum_evidence');
    expect(requirements).toContain('reproduction');
    expect(requirements).toContain('control_comparison');
    expect(requirements).toContain('identity_differential');
    expect(requirements).toContain('alternative_explanations');
    expect(requirements).toContain('confidence_threshold');

    const clean = evaluatePolicy({
      policy,
      evidenceCount: 5,
      reproduced: true,
      controlComparison: true,
      identityDifferential: true,
      alternativesEliminated: true,
      confidence: 0.9,
    });
    expect(clean).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------
// Benchmark scoring math (§47-§51)
// ---------------------------------------------------------------------------

describe('benchmark scoring (§47-§51, §87)', () => {
  it('computes precision, recall and false-positive rate (§47-§48)', () => {
    const { precision, recall, falsePositiveRate } = precisionRecall({
      truePositives: 8,
      falsePositives: 2,
      falseNegatives: 2,
      duplicates: 1,
    });
    expect(precision).toBeCloseTo(0.8, 3);
    expect(recall).toBeCloseTo(0.8, 3);
    expect(falsePositiveRate).toBeCloseTo(0.2, 3);
  });

  it('handles empty ground truth honestly (null, not zero)', () => {
    const { precision, recall } = precisionRecall({ truePositives: 0, falsePositives: 0, falseNegatives: 0, duplicates: 0 });
    expect(precision).toBeNull();
    expect(recall).toBeNull();
  });

  it('computes the agent efficiency score (§51) and keeps it 0 for no findings', () => {
    expect(agentEfficiencyScore({ verifiedFindings: 0, modelCost: 10, networkCost: 10, executionSeconds: 10 })).toBeNull();
    const score = agentEfficiencyScore({ verifiedFindings: 4, modelCost: 20, networkCost: 20, executionSeconds: 60 });
    expect(score).toBeCloseTo(4 / 41, 3);
  });

  it('computes time-to-finding from real timestamps (§49)', () => {
    const result = timeToFinding({
      engagementStartedAt: '2026-01-01T00:00:00Z',
      firstCandidateAt: '2026-01-01T00:02:30Z',
      firstVerifiedAt: '2026-01-01T00:10:00Z',
    });
    expect(result.time_to_first_candidate_seconds).toBeCloseTo(150, 1);
    expect(result.time_to_first_verified_finding_seconds).toBeCloseTo(600, 1);
  });
});

// ---------------------------------------------------------------------------
// Exporters (§63-§64)
// ---------------------------------------------------------------------------

const technicalSection = {
  title: 'Technical Report — Test Engagement',
  engagement: { id: 'ENG_TEST_EXPORT_0001', name: 'Test Engagement', mode: 'PENTEST' },
  generated_at: '2026-01-01T00:00:00Z',
  finding_sections: [
    {
      id: 'FND_TEST_EXPORT_0001',
      title: 'Authorization control failure',
      severity: 'HIGH',
      confidence: { value: 0.94, level: 'HIGH', reasons: ['3 pieces of linked evidence'] },
      affected_components: [],
      affected_endpoints: ['/api/notes/1'],
      summary: 'Object-level authorization missing.',
      technical_details: 'Any authenticated identity reads foreign objects.',
      expected_behavior: 'Denied',
      observed_behavior: '200 OK with foreign owner data',
      impact: 'Root cause: object-level authorization is not enforced',
      preconditions: ['identity material'],
      evidence: [
        {
          evidence_id: 'EVD_TEST_EXPORT_0001',
          type: 'HTTP_RESPONSE',
          quality: 'CORRELATED' as const,
          request: { method: 'GET', url: '/api/notes/1', identity: 'IDN_A' },
          response: { status: 200, excerpt: JSON.stringify({ id: '1', owner: 'userb' }), truncated: false },
          relevant_observation: 'foreign owner returned',
          evidence_reference: 'EVD_TEST_EXPORT_0001 (sha256 abc123…, §23 immutable raw)',
          redactions: [],
        },
      ],
      evidence_references: ['EVD_TEST_EXPORT_0001'],
      reproduction: { plan: 'controlled reproduction plan (§12)', steps: ['HTTP_REQUEST: replay GET /api/notes/1'] },
      remediation: {
        rootCause: 'object-level authorization is not enforced',
        remediation: 'Perform server-side authorization checks against the authenticated principal.',
        priority: 'IMMEDIATE',
        fixComplexity: 'LOW',
        note: 'template',
      },
      verification: {
        status: 'VERIFIED',
        confidence: 0.94,
        reproduced: true,
        alternative_explanations: [{ label: 'H1: public resource', refuted: true, refutation: 'anonymous DENIED' }],
        reasoning_summary: 'Control refuted the alternatives; reproduction consistent.',
        result_id: 'VRR_TEST_EXPORT_0001',
      },
      reported_status: 'VERIFIED',
      retest_state: 'NOT_RETESTED' as const,
    },
  ],
  statistics: { findings_total: 1 },
} satisfies import('../../services/verification-reporting/src/reporting/technical-report.js').TechnicalReportContent;

const exportInput = {
  type: 'TECHNICAL',
  title: 'Technical Report — Test Engagement',
  engagement: { id: 'ENG_TEST_EXPORT_0001', name: 'Test Engagement', mode: 'PENTEST' },
  generatedAt: '2026-01-01T00:00:00Z',
  technical: technicalSection,
  findings: [
    {
      id: 'FND_TEST_EXPORT_0001',
      title: 'Authorization control failure',
      severity: 'HIGH',
      confidence: 0.94,
      status: 'VERIFIED',
      reported_status: 'VERIFIED',
      cvss: { vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', base_score: 9.8 },
      affected_endpoints: ['/api/notes/1'],
      evidence_ids: ['EVD_TEST_EXPORT_0001'],
      verification_ids: ['VRR_TEST_EXPORT_0001'],
    },
  ],
  manifest: { report_hash: 'a'.repeat(64), evidence_hashes: { EVD_TEST_EXPORT_0001: 'b'.repeat(64) } },
};

describe('exporters (§63-§64)', () => {
  it('renders Markdown with the §28 finding template', () => {
    const markdown = renderMarkdown(exportInput);
    expect(markdown).toContain('# Technical Report — Test Engagement');
    expect(markdown).toContain('**Severity:** HIGH');
    expect(markdown).toContain('confidence is NOT severity');
    expect(markdown).toContain('CVSS 9.8');
    expect(markdown).toContain('Report Integrity (§66)');
  });

  it('renders JSON matching the §64 machine schema', () => {
    const json = renderJson(exportInput);
    const parsed = JSON.parse(json) as {
      report_version: string;
      findings: Array<{ id: string; severity: string; reported_status: string; evidence_ids: string[] }>;
    };
    expect(parsed.report_version).toBe('1.0');
    expect(parsed.findings).toHaveLength(1);
    expect(parsed.findings[0]!.reported_status).toBe('VERIFIED');
    expect(parsed.findings[0]!.evidence_ids).toContain('EVD_TEST_EXPORT_0001');
  });

  it('renders self-contained HTML with escaped content', () => {
    const html = renderHtml(exportInput, 'RPR_TEST_REPORT_0001');
    expect(html).toContain('<!DOCTYPE html>');
    expect(html).toContain('Technical Report');
    expect(html).toContain('RPR_TEST_REPORT_0001');
    expect(html).not.toContain('<script src=');
  });

  it('renders a structurally valid multi-page PDF (§63)', () => {
    const longInput = {
      ...exportInput,
      findings: Array.from({ length: 80 }, (_, index) => ({
        ...exportInput.findings[0]!,
        id: `FND_TEST_EXPORT_${String(index).padStart(4, '0')}`,
        title: `Finding ${index} with a reasonably long title describing an authorization control failure`,
      })),
    };
    const bytes = renderPdf(longInput);
    const text = bytes.toString('latin1');
    expect(text.startsWith('%PDF-1.4')).toBe(true);
    expect(text.trimEnd().endsWith('%%EOF')).toBe(true);
    expect(text).toContain('/Type /Catalog');
    expect(text).toContain('/Count ');
    // Multi-page: more than one /Type /Page object.
    const pageObjects = text.match(/\/Type \/Page[^s]/g) ?? [];
    expect(pageObjects.length).toBeGreaterThan(1);
    // xref table present with correct startxref pointer.
    const startxref = /startxref\n(\d+)/.exec(text);
    expect(startxref).not.toBeNull();
    const offset = Number(startxref![1]);
    expect(text.slice(offset, offset + 4)).toBe('xref');
  });
});

// ---------------------------------------------------------------------------
// Scenario seeds (§39-§41)
// ---------------------------------------------------------------------------

describe('scenario seeds (§39-§41)', () => {
  it('covers the entire loop plus safety benchmarks (§40, §76-§82)', () => {
    const kinds = new Set(SCENARIO_SEEDS.map((s) => s.kind));
    for (const kind of [
      'AUTHORIZATION',
      'AUTHENTICATION',
      'HONESTY',
      'SCOPE_SAFETY',
      'PROMPT_INJECTION',
      'HALLUCINATION',
      'REPETITION',
      'RESOURCE_AWARENESS',
      'CTF_REASONING',
    ]) {
      expect(kinds.has(kind)).toBe(true);
    }
    // Ground truth is controlled (§41): authorization scenario carries it.
    const authorization = SCENARIO_SEEDS.find((s) => s.name === 'authorization-object-access')!;
    expect(authorization.expectedFindings.length).toBe(1);
    expect(authorization.expectedFindings[0]!.match_tokens.length).toBeGreaterThan(0);
    // Safety expectations attached to the safety scenarios.
    expect(
      SCENARIO_SEEDS.find((s) => s.name === 'scope-safety-out-of-scope')!.safetyExpectations.length,
    ).toBeGreaterThan(0);
  });
});
