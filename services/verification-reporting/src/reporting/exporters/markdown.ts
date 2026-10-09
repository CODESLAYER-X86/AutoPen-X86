/**
 * Markdown exporter (spec Part 7 §63).
 */
import type { TechnicalReportContent } from '../technical-report.js';
import type { ExecutiveSummaryContent } from '../executive-summary.js';

export interface ExportInput {
  type: string;
  title: string;
  engagement: { id: string; name: string; mode: string };
  generatedAt: string;
  executive?: ExecutiveSummaryContent;
  technical?: TechnicalReportContent;
  findings: Array<{
    id: string;
    title: string;
    severity: string;
    confidence: number | null;
    status: string;
    reported_status: string;
    cvss: { vector: string; base_score: number } | null;
    affected_endpoints: string[];
    evidence_ids: string[];
    verification_ids: string[];
  }>;
  manifest: { report_hash: string; evidence_hashes: Record<string, string> } | null;
}

export function renderMarkdown(input: ExportInput): string {
  const lines: string[] = [];
  lines.push(`# ${input.title}`);
  lines.push('');
  lines.push(`- Engagement: ${input.engagement.name} (\`${input.engagement.id}\`)`);
  lines.push(`- Mode: ${input.engagement.mode}`);
  lines.push(`- Generated: ${input.generatedAt}`);
  lines.push(`- Report type: ${input.type}`);
  lines.push('');

  if (input.executive) {
    const e = input.executive;
    lines.push('## Executive Summary');
    lines.push('');
    lines.push(`**Overall risk: ${e.overall_risk}**`);
    lines.push('');
    lines.push(`Scope: ${e.scope_summary}`);
    lines.push('');
    lines.push(
      `Findings: ${e.finding_counts.verified} verified, ${e.finding_counts.rejected} rejected, ${e.finding_counts.inconclusive} inconclusive, ${e.finding_counts.duplicates} duplicates.`,
    );
    lines.push('');
    lines.push('Severity distribution:');
    lines.push('');
    lines.push('| Severity | Count |');
    lines.push('| --- | --- |');
    for (const [severity, count] of Object.entries(e.severity_distribution)) {
      lines.push(`| ${severity} | ${count} |`);
    }
    lines.push('');
    if (e.major_impacts.length > 0) {
      lines.push('Major business impacts:');
      for (const impact of e.major_impacts) lines.push(`- ${impact}`);
      lines.push('');
    }
    lines.push('Priority recommendations:');
    for (const rec of e.priority_recommendations) {
      lines.push(`- **${rec.priority}**: ${rec.recommendation}`);
    }
    lines.push('');
    lines.push(`> ${e.note}`);
    lines.push('');
  }

  if (input.technical) {
    const t = input.technical;
    lines.push('## Technical Findings');
    lines.push('');
    for (const section of t.finding_sections) {
      lines.push(`### ${section.title}`);
      lines.push('');
      lines.push(`**Finding ID:** \`${section.id}\``);
      lines.push(`**Severity:** ${section.severity} (reported status: ${section.reported_status}, §75)`);
      lines.push(
        `**Confidence:** ${section.confidence.value ?? 'n/a'} (${section.confidence.level ?? 'n/a'}) — confidence is NOT severity (§16)`,
      );
      if (section.affected_endpoints.length > 0) {
        lines.push(`**Affected endpoints:** ${section.affected_endpoints.map((e) => `\`${e}\``).join(', ')}`);
      }
      lines.push('');
      lines.push(`**Summary.** ${section.summary}`);
      lines.push('');
      lines.push(`**Technical details.** ${section.technical_details}`);
      lines.push('');
      lines.push(`**Expected behavior.** ${section.expected_behavior}`);
      lines.push('');
      lines.push(`**Observed behavior.** ${section.observed_behavior}`);
      lines.push('');
      lines.push(`**Impact.** ${typeof section.impact === 'string' ? section.impact : JSON.stringify(section.impact)}`);
      lines.push('');
      if (section.evidence.length > 0) {
        lines.push('**Evidence (§29 relevant excerpts, redacted):**');
        for (const evidence of section.evidence) {
          lines.push(`- \`${evidence.evidence_reference}\` (${evidence.type}, quality ${evidence.quality})`);
          if (evidence.request) {
            lines.push(`  - Request: \`${evidence.request.method} ${evidence.request.url}\``);
          }
          if (evidence.response) {
            lines.push(`  - Response: ${evidence.response.status ?? 'n/a'}${evidence.response.truncated ? ' (truncated)' : ''}`);
            if (evidence.response.excerpt) {
              lines.push('  ```');
              for (const line of evidence.response.excerpt.split('\n').slice(0, 12)) lines.push(`  ${line}`);
              lines.push('  ```');
            }
          }
        }
        lines.push('');
      }
      if (section.reproduction.steps.length > 0) {
        lines.push('**Reproduction (§12 controlled steps):**');
        for (const step of section.reproduction.steps) lines.push(`- ${step}`);
        lines.push('');
      }
      if (section.remediation) {
        lines.push(`**Remediation (${section.remediation.priority}).** ${section.remediation.remediation}`);
        lines.push('');
      }
      lines.push(`**Verification (§14).** Status: ${section.verification.status}`);
      if (section.verification.result_id) lines.push(`- Verification record: \`${section.verification.result_id}\``);
      lines.push(`- Reproduced: ${section.verification.reproduced}`);
      for (const alt of section.verification.alternative_explanations) {
        lines.push(`- Alternative: ${alt.label} — ${alt.refuted ? `refuted (${alt.refutation ?? 'see verification record'})` : 'SURVIVING (blocks confirmation, §10)'}`);
      }
      lines.push(`- Reasoning: ${section.verification.reasoning_summary.slice(0, 1200)}`);
      lines.push('');
      lines.push('---');
      lines.push('');
    }
  }

  lines.push('## Machine-Readable Findings');
  lines.push('');
  for (const finding of input.findings) {
    lines.push(
      `- \`${finding.id}\` ${finding.title} — ${finding.severity}/${finding.reported_status}, confidence ${finding.confidence ?? 'n/a'}${finding.cvss ? `, CVSS ${finding.cvss.base_score} (${finding.cvss.vector})` : ''}`,
    );
  }
  lines.push('');

  if (input.manifest) {
    lines.push('## Report Integrity (§66)');
    lines.push('');
    lines.push(`- Report hash: \`${input.manifest.report_hash}\``);
    lines.push(`- Evidence hashes: ${Object.keys(input.manifest.evidence_hashes).length} artifact(s) covered`);
    lines.push('');
  }

  return lines.join('\n');
}
