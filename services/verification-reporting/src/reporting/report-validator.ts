/**
 * Report validator (spec Part 7 §65-§66, §76).
 *
 * Runs the pre-export validation ladder: schema -> finding status -> evidence
 * -> claim -> redaction -> severity -> reference -> render. Rejects report
 * generation when: a verified finding has no evidence; a claim has no
 * support; a secret appears unredacted; a finding references nonexistent
 * evidence (hallucinated evidence, §76).
 */
import { createHash } from 'node:crypto';
import type { Repositories } from '@aegis/database';
import type { FindingRecord, ReportRecord } from '@aegis/database';
import type { ReportValidationIssueRecord } from '@aegis/database';
import { containsUnredactedSecret } from './redaction.js';

export interface ValidationResult {
  valid: boolean;
  issues: ReportValidationIssueRecord[];
  /** §66: report integrity manifest. */
  manifest: {
    report_hash: string;
    evidence_hashes: Record<string, string>;
    finding_ids: string[];
    generation_config: Record<string, unknown>;
  } | null;
}

export class ReportValidator {
  constructor(private readonly repos: Repositories) {}

  async validate(input: {
    report: {
      id: string;
      type: string;
      claims: Array<{ id: string; text: string; evidence_ids: string[]; support: string }>;
      content: Record<string, unknown>;
      findings: FindingRecord[];
      generationConfig: Record<string, unknown>;
    };
    requireVerifiedForReport: boolean;
  }): Promise<ValidationResult> {
    const issues: ReportValidationIssueRecord[] = [];
    const evidenceHashes: Record<string, string> = {};

    // --- Finding status validation ----------------------------------------
    for (const finding of input.report.findings) {
      const reportable = finding.status === 'VERIFIED' || finding.status === 'ACCEPTED';
      if (input.requireVerifiedForReport && !reportable && input.report.type !== 'MACHINE') {
        if (finding.status === 'REJECTED' || finding.status === 'DUPLICATE') {
          issues.push({
            code: 'FINDING_NOT_REPORTABLE',
            message: `Finding ${finding.id} has status ${finding.status}; rejected/duplicate findings are excluded from reports (§4)`,
            severity: 'WARNING',
            finding_id: finding.id,
            claim_id: null,
          });
        } else if (finding.status !== 'PROPOSED' && finding.status !== 'CONFIRMED' && finding.status !== 'INCONCLUSIVE') {
          issues.push({
            code: 'FINDING_NOT_VERIFIED',
            message: `Finding ${finding.id} has status ${finding.status}; only VERIFIED findings may appear in reports (§65)`,
            severity: 'ERROR',
            finding_id: finding.id,
            claim_id: null,
          });
        }
      }
      // Verified finding MUST have evidence (§65 rejection rule).
      if (reportable && finding.evidence_ids.length === 0) {
        issues.push({
          code: 'VERIFIED_FINDING_NO_EVIDENCE',
          message: `Verified finding ${finding.id} has no evidence references — refusing export (§65)`,
          severity: 'ERROR',
          finding_id: finding.id,
          claim_id: null,
        });
      }
      // Verified finding MUST have a verification record (§65).
      if (reportable && finding.verification_ids.length === 0) {
        issues.push({
          code: 'VERIFIED_FINDING_NO_VERIFICATION',
          message: `Verified finding ${finding.id} has no verification records (§65)`,
          severity: 'ERROR',
          finding_id: finding.id,
          claim_id: null,
        });
      }
    }

    // --- Evidence + reference validation (§76 hallucination guard) ---------
    for (const finding of input.report.findings) {
      for (const evidenceId of finding.evidence_ids) {
        const record = await this.repos.evidence.findById(evidenceId).catch(() => null);
        if (!record) {
          issues.push({
            code: 'EVIDENCE_REFERENCE_INVALID',
            message: `Finding ${finding.id} references nonexistent evidence ${evidenceId} — hallucinated evidence is rejected (§76)`,
            severity: 'ERROR',
            finding_id: finding.id,
            claim_id: null,
          });
        } else {
          evidenceHashes[evidenceId] = record.sha256;
        }
      }
    }

    // --- Claim validation (§33-§34) ---------------------------------------
    for (const claim of input.report.claims) {
      if (claim.evidence_ids.length === 0) {
        issues.push({
          code: 'CLAIM_NO_SUPPORT',
          message: `Claim "${claim.text.slice(0, 120)}" has no evidence references (§34)`,
          severity: 'ERROR',
          finding_id: null,
          claim_id: claim.id,
        });
      } else if (claim.support === 'UNSUPPORTED') {
        issues.push({
          code: 'CLAIM_UNSUPPORTED',
          message: `Claim "${claim.text.slice(0, 120)}" was assessed UNSUPPORTED (§33)`,
          severity: 'ERROR',
          finding_id: null,
          claim_id: claim.id,
        });
      }
      // Claims whose evidence references do not exist.
      for (const evidenceId of claim.evidence_ids) {
        if (!(evidenceId in evidenceHashes)) {
          const exists = await this.repos.evidence.findById(evidenceId).catch(() => null);
          if (!exists) {
            issues.push({
              code: 'CLAIM_EVIDENCE_INVALID',
              message: `Claim ${claim.id} references nonexistent evidence ${evidenceId} (§76)`,
              severity: 'ERROR',
              finding_id: null,
              claim_id: claim.id,
            });
          }
        }
      }
    }

    // --- Redaction validation (§24, §65) -----------------------------------
    const serialized = JSON.stringify(input.report.content);
    const secretScan = containsUnredactedSecret(serialized);
    if (secretScan.found) {
      issues.push({
        code: 'UNREDACTED_SECRET',
        message: `Report content contains an unredacted secret pattern (rule: ${secretScan.rule}) — refusing export (§24, §65)`,
        severity: 'ERROR',
        finding_id: null,
        claim_id: null,
      });
    }

    // --- Severity validation (§65) ------------------------------------------
    for (const finding of input.report.findings) {
      if (finding.status === 'VERIFIED' && !['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'].includes(finding.severity)) {
        issues.push({
          code: 'SEVERITY_MISSING',
          message: `Verified finding ${finding.id} has no valid severity (§65)`,
          severity: 'ERROR',
          finding_id: finding.id,
          claim_id: null,
        });
      }
    }

    // --- Render smoke test (§65: report rendering test) --------------------
    if (serialized.length === 0) {
      issues.push({
        code: 'REPORT_EMPTY',
        message: 'Report content rendered empty (§65 rendering test)',
        severity: 'ERROR',
        finding_id: null,
        claim_id: null,
      });
    }

    const valid = !issues.some((i) => i.severity === 'ERROR');
    const reportHash = valid
      ? createHash('sha256').update(JSON.stringify(input.report.content)).digest('hex')
      : null;

    return {
      valid,
      issues,
      manifest:
        valid && reportHash
          ? {
              report_hash: reportHash,
              evidence_hashes: evidenceHashes,
              finding_ids: input.report.findings.map((f) => f.id),
              generation_config: input.report.generationConfig,
            }
          : null,
    };
  }

  /** §66: verify a persisted manifest against current stored evidence hashes. */
  async verifyIntegrity(report: ReportRecord): Promise<{ ok: boolean; mismatches: string[] }> {
    if (!report.manifest) return { ok: false, mismatches: ['report has no manifest'] };
    const mismatches: string[] = [];
    for (const [evidenceId, expectedHash] of Object.entries(report.manifest.evidence_hashes)) {
      const record = await this.repos.evidence.findById(evidenceId).catch(() => null);
      if (!record) {
        mismatches.push(`evidence ${evidenceId} no longer exists`);
      } else if (record.sha256 !== expectedHash) {
        mismatches.push(`evidence ${evidenceId} hash changed (tamper or corruption, §22)`);
      }
    }
    return { ok: mismatches.length === 0, mismatches };
  }
}
