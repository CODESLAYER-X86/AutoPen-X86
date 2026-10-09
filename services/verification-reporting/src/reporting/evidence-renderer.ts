/**
 * Evidence renderer (spec Part 7 §29-§30).
 *
 * Reports never dump huge responses: the renderer selects the RELEVANT
 * request, the RELEVANT response, the important difference, and produces
 * bounded, REDACTED excerpts with evidence references. The complete raw
 * artifact stays separately attached (immutable, hashed, §23-§24).
 */
import type { Repositories } from '@aegis/database';
import type { FindingRecord } from '@aegis/database';
import { redactText, type RedactionRecord } from './redaction.js';

export interface RenderedEvidence {
  evidence_id: string;
  type: string;
  quality: 'RAW' | 'EXTRACTED' | 'CORRELATED' | 'ANALYZED' | 'VERIFIED';
  /** §29: relevant request (redacted, bounded). */
  request: { method: string; url: string; identity: string | null } | null;
  /** §29: relevant response (redacted, bounded). */
  response: { status: number | null; excerpt: string; truncated: boolean } | null;
  /** §29: the important difference vs the control. */
  relevant_observation: string | null;
  evidence_reference: string;
  redactions: RedactionRecord[];
}

export interface EvidenceRenderOptions {
  maxEvidence: number;
  excerptBytes: number;
}

export class EvidenceRenderer {
  constructor(private readonly repos: Repositories) {}

  /**
   * §29: render the evidence supporting one finding. Excerpts are bounded and
   * every text passes deterministic redaction (§24).
   */
  async renderForFinding(
    finding: FindingRecord,
    options: EvidenceRenderOptions,
  ): Promise<{ items: RenderedEvidence[]; redactions: RedactionRecord[] }> {
    const qualityRows = await this.repos.findings.listEvidenceQuality(finding.id).catch(() => []);
    const qualityByEvidence = new Map(qualityRows.map((q) => [q.evidence_id, q.quality]));
    const items: RenderedEvidence[] = [];
    const redactions: RedactionRecord[] = [];

    for (const evidenceId of finding.evidence_ids.slice(0, options.maxEvidence)) {
      const record = await this.repos.evidence.findById(evidenceId).catch(() => null);
      if (!record) continue;
      const metadata = (record.metadata ?? {}) as Record<string, unknown>;
      const quality = qualityByEvidence.get(evidenceId) ?? 'RAW';

      let request: RenderedEvidence['request'] = null;
      let response: RenderedEvidence['response'] = null;

      const requestId = metadata.request_id;
      if (typeof requestId === 'string') {
        const requestRow = (await this.repos.httpRequests.findById(requestId).catch(() => null)) as
          | Record<string, unknown>
          | null;
        if (requestRow) {
          const method = String(requestRow.method ?? 'GET');
          const url = redactText(String(requestRow.url ?? ''), `evidence:${evidenceId}:request_url`);
          redactions.push(...url.records);
          request = {
            method,
            url: url.text,
            identity: (requestRow.identity_id as string | undefined) ?? null,
          };
        }
      }

      const preview = typeof metadata.body_preview === 'string' ? metadata.body_preview : null;
      const status = typeof metadata.status === 'number' ? metadata.status : null;
      if (preview !== null || status !== null) {
        const source = preview ?? '';
        const bounded = source.slice(0, options.excerptBytes);
        const redacted = redactText(bounded, `evidence:${evidenceId}:response_body`);
        redactions.push(...redacted.records);
        response = {
          status,
          excerpt: redacted.text,
          truncated: source.length > options.excerptBytes,
        };
      }

      items.push({
        evidence_id: evidenceId,
        type: record.type,
        quality,
        request,
        response,
        relevant_observation: finding.observed_behavior ?? null,
        evidence_reference: `${record.id} (sha256 ${record.sha256.slice(0, 12)}…, §23 immutable raw)`,
        redactions: [],
      });
    }

    return { items, redactions };
  }
}
