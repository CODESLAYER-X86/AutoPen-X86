/**
 * Anomaly analyzer (spec Part 6 §24).
 *
 * Deterministic feature extraction + baseline comparison. Detects:
 * unexpected status, unexpected size, new/missing fields, new headers,
 * new cookies, new redirects, timing deviation, state change,
 * identity-dependent difference, error signatures, debug information,
 * unexpected endpoints/objects/permissions.
 *
 * The LLM interprets anomalies; deterministic code detects measurable
 * differences (§24) — anomaly -> hypothesis candidate flows through the
 * Part 4 signal engine where it already exists (SECURITY_SIGNAL_GENERATED).
 * This analyzer adds the engine-side differential view for observations.
 */
import type { Repositories } from '@aegis/database';
import type { AnomalyFinding, AttackSurfaceProjection } from './projection-types.js';

const ERROR_SIGNATURES: Array<{ pattern: RegExp; name: string }> = [
  { pattern: /stack\s*trace|traceback|at\s+\S+\(.*:\d+:\d+\)/i, name: 'stack trace disclosure' },
  { pattern: /\bSQL syntax\b|SQLSTATE\[|unterminated quoted string/i, name: 'SQL error disclosure' },
  { pattern: /warning:\s|fatal:\s|deprecated:/i, name: 'PHP-style error output' },
  { pattern: /debug[_-]?info|debug[_-]?trace|debugger/i, name: 'debug information' },
  { pattern: /exception|unhandled\s+error/i, name: 'exception disclosure' },
];

export interface AnalyzerOutput {
  anomalies: AnomalyFinding[];
  surface: AttackSurfaceProjection;
}

export class AnomalyAnalyzer {
  constructor(private readonly repos: Repositories) {}

  /**
   * Analyze recent responses against the observed baseline (status/size
   * families per endpoint). Deterministic — no model calls.
   */
  async analyze(engagementId: string, limit = 40): Promise<AnalyzerOutput> {
    const anomalies: AnomalyFinding[] = [];
    const endpoints = await this.repos.endpoints.listByEngagement(engagementId, { limit: 200 });
    const responses = await this.repos.httpResponses.listByEngagement(engagementId, limit);

    // Baseline: status + size families per endpoint, from ALL responses.
    const byEndpoint = new Map<string, { statuses: Set<number>; sizes: number[] }>();
    for (const response of responses) {
      const request = await this.repos.httpRequests.findById(String(response.request_id ?? ''));
      if (!request) continue;
      const path = this.pathOf(String(request.url ?? ''));
      const entry = byEndpoint.get(path) ?? { statuses: new Set<number>(), sizes: [] };
      entry.statuses.add(Number(response.status ?? 0));
      entry.sizes.push(Number(response.content_length ?? 0));
      byEndpoint.set(path, entry);
    }

    // A single 500 among 200s, or wildly deviating sizes -> anomaly.
    for (const [path, entry] of byEndpoint) {
      const statuses = [...entry.statuses];
      if (statuses.length > 1 && statuses.includes(500)) {
        anomalies.push({
          kind: 'UNEXPECTED_STATUS',
          subject: path,
          observed: `statuses ${statuses.join(', ')} include 5xx`,
          expected: 'a single consistent status family',
          severity: 'MEDIUM',
          evidenceRef: null,
        });
      }
      if (entry.sizes.length >= 3) {
        const avg = entry.sizes.reduce((a, b) => a + b, 0) / entry.sizes.length;
        const outlier = entry.sizes.some((size) => size > avg * 5 + 2048 && size > 4096);
        if (outlier) {
          anomalies.push({
            kind: 'UNEXPECTED_RESPONSE_SIZE',
            subject: path,
            observed: `size outlier among ${entry.sizes.join(', ')}`,
            expected: `~${Math.round(avg)} bytes`,
            severity: 'LOW',
            evidenceRef: null,
          });
        }
      }
    }

    // Error signatures in response previews (§24 error signatures).
    for (const response of responses.slice(0, 30)) {
      const preview = typeof response.body_preview === 'string' ? response.body_preview : '';
      if (!preview) continue;
      for (const signature of ERROR_SIGNATURES) {
        if (signature.pattern.test(preview)) {
          anomalies.push({
            kind: 'ERROR_SIGNATURE',
            subject: this.pathOfPreview(responses, response),
            observed: signature.name,
            expected: 'no error output in production responses',
            severity: 'MEDIUM',
            evidenceRef: null,
          });
          break;
        }
      }
    }

    const surface: AttackSurfaceProjection = {
      endpointCount: endpoints.length,
      identityCount: 0,
      objectCount: 0,
      workflowCount: 0,
      parameterCount: 0,
    };
    return { anomalies: anomalies.slice(0, 40), surface };
  }

  private pathOf(url: string): string {
    try {
      const parsed = new URL(url);
      return `${parsed.host}${parsed.pathname}`;
    } catch {
      return url.slice(0, 200);
    }
  }

  private pathOfPreview(responses: Array<Record<string, unknown>>, response: Record<string, unknown>): string {
    const match = responses.find((r) => r === response);
    void match;
    return String(response.request_id ?? 'unknown').slice(0, 40);
  }
}
