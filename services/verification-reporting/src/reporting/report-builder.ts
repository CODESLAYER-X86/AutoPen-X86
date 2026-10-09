/**
 * Report builder (spec Part 7 §31-§32, §63-§66, §73).
 *
 * Pipeline:
 *   Verified findings -> normalization -> deduplication -> severity ->
 *   confidence -> evidence selection -> redaction -> composition ->
 *   validation -> export.
 *
 * Reports are NEVER generated from raw LLM conversations (§32): the builder
 * composes from structured verified facts + evidence references + templates.
 * Validation failure REJECTS the report before export (§65).
 */
import { createHash } from 'node:crypto';
import type { EventBus } from '@aegis/events';
import type { PlatformEvent } from '@aegis/contracts';
import { generateId } from '@aegis/shared';
import type { Repositories } from '@aegis/database';
import type { FindingRecord, ReportRecord } from '@aegis/database';
import type { AppConfig } from '@aegis/config';
import { EvidenceRenderer } from './evidence-renderer.js';
import { RemediationBuilder } from './remediation-builder.js';
import { ClaimValidator } from './claim-validator.js';
import { ExecutiveSummaryBuilder } from './executive-summary.js';
import { TechnicalReportBuilder } from './technical-report.js';
import { ReportValidator } from './report-validator.js';
import { FindingDeduplicator } from '../findings/finding-deduplicator.js';
import { renderMarkdown, type ExportInput } from './exporters/markdown.js';
import { renderJson } from './exporters/json.js';
import { renderHtml } from './exporters/html.js';
import { renderPdf } from './exporters/pdf.js';
import { ValidationError } from '@aegis/shared';

export interface GenerateReportInput {
  type: 'EXECUTIVE' | 'TECHNICAL' | 'MACHINE' | 'RETEST' | 'CTF_SOLUTION';
  formats: Array<'JSON' | 'HTML' | 'MARKDOWN' | 'PDF'>;
  title?: string;
  includeEvidence: boolean;
  includeRemediation: boolean;
  generatedBy: string;
}

export interface GeneratedReport {
  report: ReportRecord;
  exports: Array<{ format: string; byteSize: number; sha256: string; exportId: string }>;
  validationIssues: Array<{ code: string; message: string; severity: string }>;
}

export class ReportBuilder {
  private readonly evidenceRenderer: EvidenceRenderer;
  private readonly remediationBuilder = new RemediationBuilder();
  private readonly claimValidator = new ClaimValidator();
  private readonly executiveBuilder = new ExecutiveSummaryBuilder();
  private readonly technicalBuilder = new TechnicalReportBuilder();
  private readonly validator: ReportValidator;
  private readonly deduplicator: FindingDeduplicator;

  constructor(
    private readonly deps: {
      repos: Repositories;
      eventBus: EventBus;
      config: AppConfig;
      objectStore: { put(key: string, content: Buffer | string): Promise<void>; get(key: string): Promise<Buffer | null> };
    },
  ) {
    this.evidenceRenderer = new EvidenceRenderer(deps.repos);
    this.validator = new ReportValidator(deps.repos);
    this.deduplicator = new FindingDeduplicator(deps.repos);
  }

  /** §31: the full generation pipeline for one engagement. */
  async generate(engagementId: string, input: GenerateReportInput): Promise<GeneratedReport> {
    await this.publish(engagementId, 'REPORT_GENERATION_STARTED', {
      type: input.type,
      formats: input.formats,
    });

    const engagement = await this.deps.repos.engagements.findById(engagementId);
    if (!engagement) {
      throw new ValidationError('Engagement not found', 'ENGAGEMENT_NOT_FOUND');
    }

    // --- Step 2-3: normalization + deduplication (§31) ---------------------
    await this.deduplicator.deduplicateEngagement(engagementId);
    const reportable = await this.deps.repos.findings.listByEngagement(engagementId, {
      statuses: input.type === 'MACHINE'
        ? ['VERIFIED', 'ACCEPTED', 'REJECTED', 'INCONCLUSIVE', 'CANDIDATE']
        : ['VERIFIED', 'ACCEPTED', 'INCONCLUSIVE'],
      limit: this.deps.config.reporting.maxFindingsPerReport,
    });

    // --- Step 4-5: severity + confidence already computed per finding ------
    // (CVSS persisted by the severity engine; confidence by the engines.)

    // --- Step 6-7: evidence selection + redaction (§29, §24) ----------------
    const renderedEvidence = new Map<string, Awaited<ReturnType<EvidenceRenderer['renderForFinding']>>>();
    const remediations = new Map<string, ReturnType<RemediationBuilder['build']>>();
    const verifications = new Map<string, Awaited<ReturnType<Repositories['verificationResults']['listByFinding']>>[number]>();
    const reproductionPlans = new Map<string, Array<{ kind: string; reference: string; description: string }>>();
    const allRedactions: Array<{ location: string; rule: string }> = [];

    for (const finding of reportable) {
      if (input.includeEvidence) {
        const rendered = await this.evidenceRenderer.renderForFinding(finding, {
          maxEvidence: this.deps.config.reporting.maxEvidencePerFinding,
          excerptBytes: this.deps.config.reporting.evidenceExcerptBytes,
        });
        renderedEvidence.set(finding.id, rendered);
        allRedactions.push(...rendered.redactions);
      }
      if (input.includeRemediation) {
        remediations.set(finding.id, this.remediationBuilder.build(finding));
      }
      const results = await this.deps.repos.verificationResults.listByFinding(engagementId, finding.id);
      if (results[0]) verifications.set(finding.id, results[0]);
      const reproduction = await this.deps.repos.reproductionPlans.findLatestForFinding(engagementId, finding.id);
      if (reproduction) reproductionPlans.set(finding.id, reproduction.steps);
    }

    // --- Step 8: composition (§25-§28, §32: from structured facts) -----------
    const generatedAt = new Date().toISOString();
    const scopeRecord = await this.deps.repos.scope.findByEngagement(engagementId).catch(() => null);
    const scopeSummary = scopeRecord
      ? `allowed hosts: ${scopeRecord.allowed_hosts.join(', ') || '(none recorded)'}; excluded: ${scopeRecord.excluded_hosts.join(', ') || '(none)'}`
      : 'authorized engagement scope (see scope records)';

    const executive = this.executiveBuilder.build({
      engagement: {
        id: engagement.id,
        name: engagement.name,
        mode: engagement.mode,
        status: engagement.status,
        startedAt: engagement.created_at,
      },
      findings: reportable,
      scopeSummary,
      generatedAt,
    });

    const technical = this.technicalBuilder.build({
      engagement: { id: engagement.id, name: engagement.name, mode: engagement.mode },
      generatedAt,
      findings: reportable,
      renderedEvidence: new Map(
        [...renderedEvidence.entries()].map(([id, value]) => [id, value.items]),
      ),
      remediations,
      verifications,
      reproductionPlans,
    });

    // --- Claims (§33-§34): every substantive claim maps to evidence ---------
    const claims = reportable.flatMap((finding) => this.claimValidator.buildClaimsForFinding(finding));
    const assessedClaims = claims.map((claim) => {
      const finding = reportable.find((f) => f.id === claim.finding_id)!;
      const assessment = this.claimValidator.assess(claim, finding, finding.evidence_ids.length);
      return assessment;
    });
    for (const assessment of assessedClaims) {
      if (assessment.rewritten) {
        await this.publish(engagementId, 'REPORT_CLAIM_FLAGGED', {
          claim_id: assessment.claim.id,
          issue: assessment.issue,
        });
      }
    }

    const version = await this.deps.repos.reports.nextVersion(engagementId, input.type);
    const title =
      input.title ??
      `${input.type.charAt(0)}${input.type.slice(1).toLowerCase()} report — ${engagement.name} v${version}`;
    const content: Record<string, unknown> = {
      executive,
      technical,
      engagement: { id: engagement.id, name: engagement.name, mode: engagement.mode },
      generated_at: generatedAt,
      findings: reportable.map((f) => this.machineFinding(f)),
    };

    const report = await this.deps.repos.reports.create({
      engagementId,
      type: input.type,
      version,
      title,
      claims: assessedClaims.map((a) => a.claim),
      content,
      redactions: allRedactions,
      generatedBy: input.generatedBy,
    });

    // --- Step 9: validation (§65) — REJECT before export on errors -----------
    const validation = await this.validator.validate({
      report: {
        id: report.id,
        type: input.type,
        claims: assessedClaims.map((a) => ({
          id: a.claim.id,
          text: a.claim.text,
          evidence_ids: a.claim.evidence_ids,
          support: a.claim.support,
        })),
        content,
        findings: reportable,
        generationConfig: {
          type: input.type,
          formats: input.formats,
          include_evidence: input.includeEvidence,
          include_remediation: input.includeRemediation,
          version,
        },
      },
      requireVerifiedForReport: this.deps.config.reporting.requireVerifiedForReport,
    });

    if (!validation.valid) {
      const rejected = await this.deps.repos.reports.markRejected(report.id, validation.issues);
      await this.publish(engagementId, 'REPORT_REJECTED', {
        report_id: report.id,
        issues: validation.issues.length,
      });
      return {
        report: rejected ?? report,
        exports: [],
        validationIssues: validation.issues,
      };
    }

    const validated = await this.deps.repos.reports.markValidated(report.id, validation.manifest, validation.issues);
    await this.publish(engagementId, 'REPORT_VALIDATED', {
      report_id: report.id,
      findings: reportable.length,
      claims: claims.length,
      evidence_hashes: Object.keys(validation.manifest?.evidence_hashes ?? {}).length,
    });

    // --- Step 10: export (§63-§64) --------------------------------------------
    const exportInput: ExportInput = {
      type: input.type,
      title,
      engagement: { id: engagement.id, name: engagement.name, mode: engagement.mode },
      generatedAt,
      executive,
      technical,
      findings: reportable.map((f) => this.machineFinding(f)),
      manifest: validation.manifest
        ? { report_hash: validation.manifest.report_hash, evidence_hashes: validation.manifest.evidence_hashes }
        : null,
    };

    const exports: GeneratedReport['exports'] = [];
    for (const format of input.formats) {
      const bytes =
        format === 'JSON'
          ? Buffer.from(renderJson(exportInput, report.id), 'utf8')
          : format === 'HTML'
            ? Buffer.from(renderHtml(exportInput, report.id), 'utf8')
            : format === 'MARKDOWN'
              ? Buffer.from(renderMarkdown(exportInput), 'utf8')
              : renderPdf(exportInput);
      const sha256 = createHash('sha256').update(bytes).digest('hex');
      const contentReference = `reports/${report.id}/${format.toLowerCase()}`;
      await this.deps.objectStore.put(contentReference, bytes);
      const exportRecord = await this.deps.repos.reportExports.create(
        engagementId,
        report.id,
        format,
        bytes.length,
        sha256,
        contentReference,
      );
      exports.push({ format, byteSize: bytes.length, sha256, exportId: exportRecord.id });
      await this.publish(engagementId, 'REPORT_EXPORTED', {
        report_id: report.id,
        format,
        byte_size: bytes.length,
        sha256,
      });
    }

    if (exports.length > 0) {
      await this.deps.repos.reports.markExported(report.id);
    }

    const finalReport =
      (await this.deps.repos.reports.findByIdAndEngagement(report.id, engagementId)) ??
      validated ??
      report;
    return { report: finalReport, exports, validationIssues: validation.issues };
  }

  /** Fetch a previously rendered artifact (§63 download). */
  async getExport(engagementId: string, reportId: string, format: string): Promise<{
    bytes: Buffer;
    sha256: string;
    byteSize: number;
  } | null> {
    const record = await this.deps.repos.reportExports.findLatest(engagementId, reportId, format);
    if (!record) return null;
    const bytes = await this.deps.objectStore.get(record.content_reference);
    if (!bytes) return null;
    return { bytes, sha256: record.sha256, byteSize: record.byte_size };
  }

  private machineFinding(finding: FindingRecord): ExportInput['findings'][number] {
    return {
      id: finding.id,
      title: finding.title,
      severity: finding.severity,
      confidence: finding.confidence,
      status: finding.status,
      reported_status:
        finding.status === 'VERIFIED' || finding.status === 'ACCEPTED' ? 'VERIFIED' : 'NOT_VERIFIED',
      cvss: finding.cvss
        ? { vector: finding.cvss.vector, base_score: finding.cvss.base_score }
        : null,
      affected_endpoints: finding.affected_endpoints,
      evidence_ids: finding.evidence_ids,
      verification_ids: finding.verification_ids,
    };
  }

  private async publish(engagementId: string, type: string, payload: Record<string, unknown>): Promise<void> {
    const event: PlatformEvent = {
      type: type as PlatformEvent['type'],
      engagement_id: engagementId,
      trace_id: generateId('TRC'),
      actor_id: null,
      payload,
      occurred_at: new Date().toISOString(),
      dedup_key: `vr:${type}:${engagementId}:${payload.report_id ?? Date.now()}`,
    };
    await this.deps.eventBus.publish(event).catch(() => undefined);
  }
}
