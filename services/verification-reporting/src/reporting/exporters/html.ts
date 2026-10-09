/**
 * HTML exporter (spec Part 7 §63). Renders a self-contained, styled HTML
 * document from the structured content — no external resources, safe
 * escaping of all interpolated text.
 */
import type { ExportInput } from './markdown.js';

function escapeHtml(text: string): string {
  return text
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

export function renderHtml(input: ExportInput, reportId?: string): string {
  const sections: string[] = [];

  if (input.executive) {
    const e = input.executive;
    const severityRows = Object.entries(e.severity_distribution)
      .map(([severity, count]) => `<tr><td>${escapeHtml(severity)}</td><td>${count}</td></tr>`)
      .join('');
    const impacts = e.major_impacts.map((i) => `<li>${escapeHtml(i)}</li>`).join('');
    const recs = e.priority_recommendations
      .map((r) => `<li><strong>${escapeHtml(r.priority)}</strong>: ${escapeHtml(r.recommendation)}</li>`)
      .join('');
    sections.push(`
<section id="executive">
  <h2>Executive Summary</h2>
  <p class="risk risk-${e.overall_risk.toLowerCase()}">Overall risk: ${escapeHtml(e.overall_risk)}</p>
  <p>Scope: ${escapeHtml(e.scope_summary)}</p>
  <p>Findings: ${e.finding_counts.verified} verified, ${e.finding_counts.rejected} rejected, ${e.finding_counts.inconclusive} inconclusive, ${e.finding_counts.duplicates} duplicates.</p>
  <table><thead><tr><th>Severity</th><th>Count</th></tr></thead><tbody>${severityRows}</tbody></table>
  ${impacts ? `<h3>Major business impacts</h3><ul>${impacts}</ul>` : ''}
  <h3>Priority recommendations</h3><ul>${recs}</ul>
  <p class="note">${escapeHtml(e.note)}</p>
</section>`);
  }

  if (input.technical) {
    const findingSections = input.technical.finding_sections
      .map((section) => {
        const evidenceItems = section.evidence
          .map((ev) => {
            const request = ev.request ? `<div class="mono">${escapeHtml(ev.request.method)} ${escapeHtml(ev.request.url)}</div>` : '';
            const response = ev.response
              ? `<div>Response: ${ev.response.status ?? 'n/a'}${ev.response.truncated ? ' (truncated)' : ''}</div><pre>${escapeHtml(ev.response.excerpt.slice(0, 1500))}</pre>`
              : '';
            return `<li><code>${escapeHtml(ev.evidence_reference)}</code> (${escapeHtml(ev.type)}, quality ${escapeHtml(ev.quality)})${request}${response}</li>`;
          })
          .join('');
        const reproduction = section.reproduction.steps.map((s) => `<li>${escapeHtml(s)}</li>`).join('');
        const alternatives = section.verification.alternative_explanations
          .map(
            (a) =>
              `<li>${escapeHtml(a.label)} — ${a.refuted ? `refuted: ${escapeHtml(a.refutation ?? '')}` : '<strong>surviving (blocks confirmation)</strong>'}</li>`,
          )
          .join('');
        return `
<article class="finding severity-${section.severity.toLowerCase()}">
  <h3>${escapeHtml(section.title)}</h3>
  <dl>
    <dt>Finding ID</dt><dd><code>${escapeHtml(section.id)}</code></dd>
    <dt>Severity</dt><dd>${escapeHtml(section.severity)}</dd>
    <dt>Reported status</dt><dd>${escapeHtml(section.reported_status)}</dd>
    <dt>Confidence</dt><dd>${section.confidence.value ?? 'n/a'} (${escapeHtml(section.confidence.level ?? 'n/a')}) — confidence is NOT severity</dd>
    ${section.affected_endpoints.length ? `<dt>Affected endpoints</dt><dd>${section.affected_endpoints.map((e) => `<code>${escapeHtml(e)}</code>`).join(', ')}</dd>` : ''}
  </dl>
  <p><strong>Summary.</strong> ${escapeHtml(section.summary)}</p>
  <p><strong>Technical details.</strong> ${escapeHtml(section.technical_details)}</p>
  <p><strong>Expected behavior.</strong> ${escapeHtml(section.expected_behavior)}</p>
  <p><strong>Observed behavior.</strong> ${escapeHtml(section.observed_behavior)}</p>
  ${evidenceItems ? `<h4>Evidence (relevant excerpts, redacted)</h4><ul class="evidence">${evidenceItems}</ul>` : ''}
  ${reproduction ? `<h4>Reproduction (controlled steps)</h4><ul>${reproduction}</ul>` : ''}
  ${section.remediation ? `<h4>Remediation (${escapeHtml(section.remediation.priority)})</h4><p>${escapeHtml(section.remediation.remediation)}</p>` : ''}
  <h4>Verification</h4>
  <p>Status: ${escapeHtml(section.verification.status)}; reproduced: ${section.verification.reproduced}.</p>
  ${alternatives ? `<ul>${alternatives}</ul>` : ''}
  <p class="mono small">${escapeHtml(section.verification.reasoning_summary.slice(0, 2000))}</p>
</article>`;
      })
      .join('');
    sections.push(`<section id="technical"><h2>Technical Findings</h2>${findingSections}</section>`);
  }

  const machineList = input.findings
    .map(
      (f) =>
        `<li><code>${escapeHtml(f.id)}</code> ${escapeHtml(f.title)} — ${escapeHtml(f.severity)}/${escapeHtml(f.reported_status)}${f.cvss ? `, CVSS ${f.cvss.base_score}` : ''}</li>`,
    )
    .join('');

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${escapeHtml(input.title)}</title>
<style>
  :root { color-scheme: light; }
  body { font-family: -apple-system, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; margin: 0 auto; max-width: 900px; padding: 2rem; color: #1a1a2e; line-height: 1.55; }
  h1 { border-bottom: 3px solid #16213e; padding-bottom: .4rem; }
  h2 { margin-top: 2rem; color: #16213e; }
  h3 { margin-bottom: .2rem; }
  h4 { margin: 1rem 0 .2rem; }
  code { background: #f2f4f8; padding: .1rem .3rem; border-radius: 3px; font-size: .9em; }
  pre { background: #f7f8fa; border: 1px solid #e2e5ec; padding: .6rem; overflow-x: auto; font-size: .8rem; }
  table { border-collapse: collapse; margin: .8rem 0; }
  th, td { border: 1px solid #d7dbe4; padding: .35rem .7rem; text-align: left; }
  dt { font-weight: 600; margin-top: .4rem; }
  dd { margin: 0 0 0 1rem; }
  .finding { border: 1px solid #e2e5ec; border-left-width: 5px; border-radius: 6px; padding: .2rem 1rem; margin: 1.2rem 0; }
  .severity-critical { border-left-color: #b3261e; }
  .severity-high { border-left-color: #e8710a; }
  .severity-medium { border-left-color: #f9ab00; }
  .severity-low { border-left-color: #1e8e3e; }
  .risk { font-weight: 700; padding: .5rem .8rem; border-radius: 4px; display: inline-block; }
  .risk-critical { background: #fce8e6; color: #b3261e; }
  .risk-high { background: #fef7e0; color: #b06000; }
  .risk-moderate { background: #fef7e0; color: #8a6100; }
  .risk-low, .risk-none { background: #e6f4ea; color: #137333; }
  .note { color: #5f6368; font-style: italic; }
  .mono { font-family: ui-monospace, 'Cascadia Code', Menlo, Consolas, monospace; font-size: .85rem; }
  .small { font-size: .82rem; }
  header p { color: #5f6368; }
</style>
</head>
<body>
<header>
  <h1>${escapeHtml(input.title)}</h1>
  <p>Engagement: ${escapeHtml(input.engagement.name)} (<code>${escapeHtml(input.engagement.id)}</code>) · Mode: ${escapeHtml(input.engagement.mode)} · Generated: ${escapeHtml(input.generatedAt)}${reportId ? ` · Report: <code>${escapeHtml(reportId)}</code>` : ''}</p>
</header>
${sections.join('\n')}
<section id="machine">
  <h2>Machine-Readable Findings</h2>
  <ul>${machineList}</ul>
</section>
${
  input.manifest
    ? `<footer><p>Report integrity (§66): hash <code>${escapeHtml(input.manifest.report_hash)}</code>, ${Object.keys(input.manifest.evidence_hashes).length} evidence artifact(s) covered.</p></footer>`
    : ''
}
</body>
</html>`;
}
