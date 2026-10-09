/**
 * JSON exporter (spec Part 7 §63-§64). The machine-readable report contains
 * STRUCTURED finding data (§64 schema): report_version, engagement, findings
 * with severity/confidence/status/targets/evidence/verification references.
 */
import type { ExportInput } from './markdown.js';

export interface JsonReportDocument {
  report_version: '1.0';
  report_id?: string;
  generated_at: string;
  engagement: { id: string; name: string; mode: string };
  type: string;
  findings: Array<{
    id: string;
    title: string;
    category: string | null;
    severity: string;
    confidence: number | null;
    status: string;
    reported_status: string;
    cvss: { version: string; vector: string; base_score: number } | null;
    affected_targets: string[];
    affected_endpoints: string[];
    evidence_ids: string[];
    verification_ids: string[];
    retest_state: string;
  }>;
  statistics: Record<string, number>;
  integrity: { report_hash: string; evidence_count: number } | null;
}

export function renderJson(input: ExportInput, reportId?: string): string {
  const document: JsonReportDocument = {
    report_version: '1.0',
    ...(reportId ? { report_id: reportId } : {}),
    generated_at: input.generatedAt,
    engagement: input.engagement,
    type: input.type,
    findings: input.findings.map((f) => ({
      id: f.id,
      title: f.title,
      category: null,
      severity: f.severity,
      confidence: f.confidence,
      status: f.status,
      reported_status: f.reported_status,
      cvss: f.cvss ? { version: '3.1', vector: f.cvss.vector, base_score: f.cvss.base_score } : null,
      affected_targets: [],
      affected_endpoints: f.affected_endpoints,
      evidence_ids: f.evidence_ids,
      verification_ids: f.verification_ids,
      retest_state: 'NOT_RETESTED',
    })),
    statistics: input.technical?.statistics ?? { findings_total: input.findings.length },
    integrity: input.manifest
      ? { report_hash: input.manifest.report_hash, evidence_count: Object.keys(input.manifest.evidence_hashes).length }
      : null,
  };
  return JSON.stringify(document, null, 2);
}
