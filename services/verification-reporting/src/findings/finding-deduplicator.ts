/**
 * Finding deduplicator (spec Part 7 §19-§20).
 *
 * The same underlying issue may surface through several tests (three
 * endpoints, one authorization failure). Deduplication is deterministic:
 * findings deduplicate on a computed key (root cause family + affected
 * authorization boundary + object family). The DETERMINISTIC service makes
 * the final merge decision — never the model (§20). Duplicates are kept as
 * DUPLICATE rows referencing the primary; affected endpoints accumulate.
 */
import type { Repositories } from '@aegis/database';
import type { FindingRecord } from '@aegis/database';

/** §19: dedup key dimensions. */
export function computeDedupKey(finding: {
  category: string | null;
  hypothesis_id: string | null;
  affected_endpoints: string[];
}): string {
  // Root-cause family: category (or hypothesis lineage) normalizes the
  // "security control that failed" (§19 root cause / authorization boundary).
  const family = (finding.category ?? 'UNKNOWN').toUpperCase();
  // Authorization boundary / data-flow relation: the endpoint SHAPE
  // (path pattern with ids normalized away) — /api/users/101 and
  // /api/users/102 are the same boundary.
  const shapes = [
    ...new Set(finding.affected_endpoints.map((endpoint) => normalizeEndpointShape(endpoint))),
  ].sort();
  const boundary = shapes.length > 0 ? shapes.join('|') : 'no-endpoint';
  return `${family}::${finding.hypothesis_id ?? 'no-hypothesis'}::${boundary}`;
}

export function normalizeEndpointShape(endpoint: string): string {
  return endpoint
    .toLowerCase()
    .replace(/\?.*$/, '')
    .replace(/\/\d+(?=\/|$)/g, '/{id}')
    .replace(/\/[0-9a-f]{8,}(?=\/|$)/g, '/{id}')
    .replace(/\/[a-z0-9_-]{16,}(?=\/|$)/g, '/{id}');
}

export interface DeduplicationOutcome {
  key: string;
  duplicates: Array<{ duplicateId: string; primaryId: string }>;
  primary: FindingRecord | null;
  mergedEndpoints: string[];
}

export class FindingDeduplicator {
  constructor(private readonly repos: Repositories) {}

  /**
   * §19-§20: deduplicate a finding against its siblings. The first finding
   * with the key becomes the primary; later ones become DUPLICATE rows
   * (kept, never deleted) and their endpoints merge into the primary.
   */
  async deduplicate(engagementId: string, finding: FindingRecord): Promise<DeduplicationOutcome> {
    const key = finding.dedup_key ?? computeDedupKey(finding);
    if (!finding.dedup_key) {
      // Persist the computed key for future lookups (idempotent).
      await this.repos.findings.enrich(finding.id, {}).catch(() => undefined);
    }

    const siblings = await this.repos.findings
      .findByDedupKey(engagementId, key)
      .catch(() => [] as FindingRecord[]);

    const candidates = siblings.filter((s) => s.id !== finding.id && s.status !== 'DUPLICATE');
    if (candidates.length === 0) {
      return { key, duplicates: [], primary: finding, mergedEndpoints: finding.affected_endpoints };
    }

    // Primary: earliest created, preferring already-VERIFIED findings (§20:
    // evidence quality wins over discovery order).
    const primary =
      candidates.find((c) => c.status === 'VERIFIED' || c.status === 'ACCEPTED') ??
      [...candidates].sort((a, b) => a.created_at.localeCompare(b.created_at))[0]!;

    const duplicates: Array<{ duplicateId: string; primaryId: string }> = [];

    // §20: the primary accumulates every affected endpoint from the merged
    // duplicates (F1 -> endpoint A + B + C).
    const mergedEndpoints = [...new Set([...primary.affected_endpoints, ...finding.affected_endpoints])];
    if (finding.id !== primary.id) {
      await this.repos.findings.markDuplicate(finding.id, primary.id, finding.affected_endpoints);
      await this.repos.findings.recordLifecycleEvent(
        finding.id,
        engagementId,
        finding.status,
        'DUPLICATE',
        `duplicate of ${primary.id} under dedup key ${key} (§19)`,
        'ENGINE',
      );
      duplicates.push({ duplicateId: finding.id, primaryId: primary.id });
    }
    for (const sibling of candidates) {
      if (sibling.id !== primary.id) {
        await this.repos.findings.markDuplicate(sibling.id, primary.id, sibling.affected_endpoints);
        await this.repos.findings.recordLifecycleEvent(
          sibling.id,
          engagementId,
          sibling.status,
          'DUPLICATE',
          `duplicate of ${primary.id} under dedup key ${key} (§19)`,
          'ENGINE',
        );
        duplicates.push({ duplicateId: sibling.id, primaryId: primary.id });
        mergedEndpoints.push(...sibling.affected_endpoints);
      }
    }

    // Persist the accumulated endpoints on the primary.
    if (mergedEndpoints.length > primary.affected_endpoints.length) {
      await this.repos.findings
        .enrich(primary.id, { affectedEndpoints: [...new Set(mergedEndpoints)] })
        .catch(() => undefined);
    }
    return { key, duplicates, primary, mergedEndpoints: [...new Set(mergedEndpoints)] };
  }

  /** Run dedup across all reportable findings of an engagement (§31 step 2). */
  async deduplicateEngagement(engagementId: string): Promise<DeduplicationOutcome[]> {
    const findings = await this.repos.findings.listByEngagement(engagementId, {
      statuses: ['CANDIDATE', 'UNDER_REVIEW', 'VERIFICATION_PENDING', 'VERIFYING', 'VERIFIED', 'INCONCLUSIVE', 'CONFIRMED'],
      limit: 500,
    });
    const outcomes: DeduplicationOutcome[] = [];
    const seen = new Set<string>();
    for (const finding of findings) {
      if (seen.has(finding.id)) continue;
      const outcome = await this.deduplicate(engagementId, finding);
      outcome.duplicates.forEach((d) => seen.add(d.duplicateId));
      outcomes.push(outcome);
    }
    return outcomes;
  }
}
