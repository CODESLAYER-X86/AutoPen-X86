/**
 * Executive summary (spec Part 7 §26, §73).
 *
 * Audience: management / project owner / non-technical stakeholder. Includes
 * scope, testing period, overall risk summary, finding counts, severity
 * distribution, business impacts, priority recommendations — WITHOUT
 * unnecessary exploit detail (§26, §73: the technical evidence package is a
 * separate artifact).
 */
import type { FindingRecord } from '@aegis/database';

export interface ExecutiveSummaryContent {
  title: string;
  engagement: { id: string; name: string; mode: string; status: string };
  scope_summary: string;
  testing_period: { started: string; ended: string };
  overall_risk: 'CRITICAL' | 'HIGH' | 'MODERATE' | 'LOW' | 'NONE';
  finding_counts: { verified: number; rejected: number; inconclusive: number; duplicates: number; total: number };
  severity_distribution: Record<string, number>;
  major_impacts: string[];
  priority_recommendations: Array<{ priority: string; recommendation: string }>;
  note: string;
}

export class ExecutiveSummaryBuilder {
  build(input: {
    engagement: { id: string; name: string; mode: string; status: string; startedAt: string };
    findings: FindingRecord[];
    scopeSummary: string;
    generatedAt: string;
  }): ExecutiveSummaryContent {
    const verified = input.findings.filter((f) => f.status === 'VERIFIED' || f.status === 'ACCEPTED');
    const rejected = input.findings.filter((f) => f.status === 'REJECTED');
    const inconclusive = input.findings.filter((f) => f.status === 'INCONCLUSIVE');
    const duplicates = input.findings.filter((f) => f.status === 'DUPLICATE');

    const severityDistribution: Record<string, number> = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
    for (const finding of verified) {
      const band = (finding.severity ?? 'MEDIUM').toUpperCase();
      if (band in severityDistribution) severityDistribution[band]!++;
    }

    const overallRisk: ExecutiveSummaryContent['overall_risk'] =
      severityDistribution.CRITICAL! > 0
        ? 'CRITICAL'
        : severityDistribution.HIGH! > 0
          ? 'HIGH'
          : severityDistribution.MEDIUM! > 0
            ? 'MODERATE'
            : verified.length > 0
              ? 'LOW'
              : 'NONE';

    const impacts: string[] = [];
    const highCritical = verified.filter((f) => f.severity === 'CRITICAL' || f.severity === 'HIGH');
    for (const finding of highCritical.slice(0, 5)) {
      const category = (finding.category ?? 'SECURITY').replace(/_/g, ' ').toLowerCase();
      const endpointScope =
        finding.affected_endpoints.length > 1
          ? `${finding.affected_endpoints.length} endpoints`
          : 'one endpoint';
      impacts.push(
        `${category} issue affecting ${endpointScope}${finding.impact ? `: ${finding.impact.slice(0, 220)}` : `: ${finding.title.slice(0, 220)}`}`,
      );
    }
    if (impacts.length === 0 && verified.length > 0) {
      impacts.push('Verified issues were lower severity; review the technical report for detail.');
    }

    const recommendations: Array<{ priority: string; recommendation: string }> = [];
    if (severityDistribution.CRITICAL! > 0) {
      recommendations.push({
        priority: 'IMMEDIATE',
        recommendation: `${severityDistribution.CRITICAL} critical finding(s) require remediation before the next release.`,
      });
    }
    if (severityDistribution.HIGH! > 0) {
      recommendations.push({
        priority: 'IMMEDIATE',
        recommendation: `${severityDistribution.HIGH} high-severity finding(s): schedule remediation within the current sprint.`,
      });
    }
    if (severityDistribution.MEDIUM! > 0) {
      recommendations.push({
        priority: 'SHORT_TERM',
        recommendation: `${severityDistribution.MEDIUM} medium-severity finding(s): remediate within the normal planning cycle.`,
      });
    }
    if (rejected.length + inconclusive.length > 0) {
      recommendations.push({
        priority: 'INFORMATIONAL',
        recommendation: `${rejected.length} rejected and ${inconclusive.length} inconclusive candidates were retained for evaluation and false-positive analysis; they are NOT reported as vulnerabilities.`,
      });
    }
    if (recommendations.length === 0) {
      recommendations.push({
        priority: 'NONE',
        recommendation: 'No verified vulnerabilities in scope for this engagement at this time.',
      });
    }

    return {
      title: `Executive Summary — ${input.engagement.name}`,
      engagement: {
        id: input.engagement.id,
        name: input.engagement.name,
        mode: input.engagement.mode,
        status: input.engagement.status,
      },
      scope_summary: input.scopeSummary,
      testing_period: { started: input.engagement.startedAt, ended: input.generatedAt },
      overall_risk: overallRisk,
      finding_counts: {
        verified: verified.length,
        rejected: rejected.length,
        inconclusive: inconclusive.length,
        duplicates: duplicates.length,
        total: input.findings.length,
      },
      severity_distribution: severityDistribution,
      major_impacts: impacts,
      priority_recommendations: recommendations,
      note: 'This executive report deliberately excludes exploit detail and raw evidence; the technical evidence package is a separate, access-controlled artifact (§73).',
    };
  }
}
