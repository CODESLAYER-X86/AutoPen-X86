/**
 * Data-flow analyzer (spec Part 6 §23).
 *
 * Projects Part 4-recorded data flows (SOURCE -> TRANSFORMATION -> SINK)
 * into engine intelligence: reaches-sensitive-sink flows become hypothesis
 * candidates, reflected-input flows feed input-validation priority. The
 * analyzer NEVER claims a vulnerability merely because a source reaches a
 * sink (§23) — that creates a hypothesis, not a finding.
 */
import type { Repositories } from '@aegis/database';

export interface DataFlowInsight {
  flowId: string;
  sourceKind: string;
  sinkKind: string;
  sensitive: boolean;
  untrustedToSensitiveSink: boolean;
  note: string;
}

const SENSITIVE_SINKS = new Set(['HTML_DOM', 'SCRIPT_CONTEXT', 'REDIRECT', 'DOWNLOAD']);
const UNTRUSTED_SOURCES = new Set(['URL_PARAM', 'FORM_FIELD', 'JSON_FIELD', 'HEADER', 'COOKIE', 'WEBSOCKET_MESSAGE', 'UPLOADED_FILE']);

export class DataflowAnalyzer {
  constructor(private readonly repos: Repositories) {}

  /** Summarize recorded data flows into engine insights (§23). */
  async insights(engagementId: string): Promise<DataFlowInsight[]> {
    const flows = await this.repos.dataFlows.listByEngagement(engagementId, 100);
    const out: DataFlowInsight[] = [];
    for (const flow of flows) {
      const sourceKind = String((flow.source as Record<string, unknown>)?.kind ?? '');
      const sinkKind = String((flow.sink as Record<string, unknown>)?.kind ?? '');
      const untrusted = UNTRUSTED_SOURCES.has(sourceKind);
      const sensitive = SENSITIVE_SINKS.has(sinkKind);
      if (!untrusted && !sensitive) continue;
      out.push({
        flowId: flow.id,
        sourceKind,
        sinkKind,
        sensitive,
        untrustedToSensitiveSink: untrusted && sensitive,
        note:
          untrusted && sensitive
            ? `Untrusted source (${sourceKind}) reaches a sensitive sink (${sinkKind}): input-validation hypothesis candidate (§23 — hypothesis, NOT a finding)`
            : `Flow ${sourceKind} -> ${sinkKind} recorded`,
      });
    }
    return out.slice(0, 40);
  }

  /** How many untrusted->sensitive flows exist (input-validation priority, §32). */
  async untrustedToSensitiveCount(engagementId: string): Promise<number> {
    const insights = await this.insights(engagementId);
    return insights.filter((i) => i.untrustedToSensitiveSink).length;
  }
}
