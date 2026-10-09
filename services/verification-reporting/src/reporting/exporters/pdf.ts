/**
 * PDF exporter (spec Part 7 §63).
 *
 * Dependency-free PDF 1.4 writer: built-in Helvetica/Helvetica-Bold fonts,
 * Latin-1 text encoding with strict escaping, automatic pagination, and a
 * correct xref table. Content is derived from the structured report (the
 * same data the Markdown exporter renders).
 */
import type { ExportInput } from './markdown.js';

const PAGE_WIDTH = 595.28; // A4 in points
const PAGE_HEIGHT = 841.89;
const MARGIN = 56;
const FONT_SIZE = 9.5;
const LINE_HEIGHT = 13.5;
const MAX_CHARS = 96;

interface TextLine {
  text: string;
  bold: boolean;
  size: number;
}

/** Render the structured report into plain text lines (with emphasis). */
export function reportToLines(input: ExportInput): TextLine[] {
  const lines: TextLine[] = [];
  const push = (text: string, bold = false, size = FONT_SIZE) => lines.push({ text, bold, size });

  push(input.title, true, 16);
  push(`Engagement: ${input.engagement.name} (${input.engagement.id}) — mode ${input.engagement.mode}`);
  push(`Generated: ${input.generatedAt} — report type: ${input.type}`);
  push('');

  if (input.executive) {
    const e = input.executive;
    push('EXECUTIVE SUMMARY', true, 13);
    push(`Overall risk: ${e.overall_risk}`, true);
    push(`Scope: ${e.scope_summary}`);
    push(
      `Findings: ${e.finding_counts.verified} verified, ${e.finding_counts.rejected} rejected, ${e.finding_counts.inconclusive} inconclusive, ${e.finding_counts.duplicates} duplicates.`,
    );
    push(`Severity: ${Object.entries(e.severity_distribution).map(([s, c]) => `${s}=${c}`).join('  ')}`);
    push('');
    for (const impact of e.major_impacts) push(`- ${impact}`);
    for (const rec of e.priority_recommendations) push(`* ${rec.priority}: ${rec.recommendation}`);
    push('');
  }

  if (input.technical) {
    for (const section of input.technical.finding_sections) {
      push(section.title, true, 12);
      push(`Finding ${section.id} | Severity ${section.severity} | Reported ${section.reported_status}`);
      if (section.affected_endpoints.length > 0) {
        push(`Affected endpoints: ${section.affected_endpoints.join(', ')}`);
      }
      push(`Confidence: ${section.confidence.value ?? 'n/a'} (${section.confidence.level ?? 'n/a'}) — confidence is NOT severity (§16)`);
      push('');
      push(`Summary: ${section.summary}`);
      push(`Technical details: ${section.technical_details}`);
      push(`Expected behavior: ${section.expected_behavior}`);
      push(`Observed behavior: ${section.observed_behavior}`);
      push('');
      for (const evidence of section.evidence) {
        push(`  evidence ${evidence.evidence_reference} [${evidence.type}, ${evidence.quality}]`, false, 8.5);
        if (evidence.request) push(`    request: ${evidence.request.method} ${evidence.request.url}`, false, 8.5);
        if (evidence.response) {
          push(`    response: ${evidence.response.status ?? 'n/a'}${evidence.response.truncated ? ' (truncated)' : ''}`, false, 8.5);
          for (const body of evidence.response.excerpt.split('\n').slice(0, 8)) {
            if (body.trim().length > 0) push(`      ${body.slice(0, 100)}`, false, 8);
          }
        }
      }
      push('');
      for (const step of section.reproduction.steps) push(`  repro: ${step}`);
      if (section.remediation) {
        push(`Remediation (${section.remediation.priority}): ${section.remediation.remediation}`);
      }
      push(`Verification: ${section.verification.status}; reproduced=${section.verification.reproduced}`);
      for (const alt of section.verification.alternative_explanations) {
        push(`  alternative: ${alt.label} — ${alt.refuted ? 'refuted' : 'SURVIVING (blocks confirmation)'}`);
      }
      push(`  reasoning: ${section.verification.reasoning_summary.slice(0, 700)}`);
      push('');
      push('----------------------------------------------------------------', false, 8);
      push('');
    }
  }

  push('MACHINE-READABLE FINDINGS', true, 12);
  for (const finding of input.findings) {
    push(
      `${finding.id}  ${finding.title}  ${finding.severity}/${finding.reported_status}${finding.cvss ? `  CVSS ${finding.cvss.base_score}` : ''}`,
    );
  }
  if (input.manifest) {
    push('');
    push(`Report integrity (§66): hash ${input.manifest.report_hash}`, false, 8.5);
    push(`Evidence artifacts covered: ${Object.keys(input.manifest.evidence_hashes).length}`, false, 8.5);
  }
  return lines;
}

/** Wrap a line to MAX_CHARS monospace-ish width. */
function wrap(line: TextLine): TextLine[] {
  if (line.text.length <= MAX_CHARS) return [line];
  const words = line.text.split(' ');
  const out: TextLine[] = [];
  let current = '';
  for (const word of words) {
    if ((current + (current ? ' ' : '') + word).length > MAX_CHARS) {
      if (current) out.push({ ...line, text: current });
      current = word.length > MAX_CHARS ? word.slice(0, MAX_CHARS) : word;
    } else {
      current += (current ? ' ' : '') + word;
    }
  }
  if (current) out.push({ ...line, text: current });
  return out;
}

function escapePdfText(text: string): string {
  return text.replace(/\\/g, '\\\\').replace(/\(/g, '\\(').replace(/\)/g, '\\)');
}

function toLatin1(text: string): string {
  let out = '';
  for (const char of text) {
    const code = char.codePointAt(0) ?? 63;
    out += code <= 255 ? char : '?';
  }
  return out;
}

const LINES_PER_PAGE = Math.floor((PAGE_HEIGHT - 2 * MARGIN) / LINE_HEIGHT);

/** Build the PDF bytes (multi-page, Helvetica/Helvetica-Bold). */
export function renderPdf(input: ExportInput): Buffer {
  const wrapped = reportToLines(input).flatMap(wrap);
  const pages: TextLine[][] = [];
  for (let i = 0; i < wrapped.length; i += LINES_PER_PAGE) {
    pages.push(wrapped.slice(i, i + LINES_PER_PAGE));
  }
  if (pages.length === 0) pages.push([{ text: '(empty report)', bold: false, size: FONT_SIZE }]);

  // Object layout: 1 catalog, 2 pages tree, 3 font regular, 4 font bold,
  // then per page: page object + content stream.
  const objects: Array<{ id: number; body: Buffer }> = [];
  const pageCount = pages.length;
  const firstPageObj = 5;
  const pageObjectIds = pages.map((_, index) => firstPageObj + index * 2);

  const kids = pageObjectIds.map((id) => `${id} 0 R`).join(' ');
  objects.push({
    id: 1,
    body: Buffer.from('<< /Type /Catalog /Pages 2 0 R >>'),
  });
  objects.push({
    id: 2,
    body: Buffer.from(`<< /Type /Pages /Kids [${kids}] /Count ${pageCount} >>`),
  });
  objects.push({
    id: 3,
    body: Buffer.from('<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>'),
  });
  objects.push({
    id: 4,
    body: Buffer.from('<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold /Encoding /WinAnsiEncoding >>'),
  });

  pages.forEach((lines, pageIndex) => {
    const pageId = pageObjectIds[pageIndex]!;
    const contentId = pageId + 1;
    const contentParts: string[] = [];
    let y = PAGE_HEIGHT - MARGIN;
    for (const line of lines) {
      const font = line.bold ? '/F2' : '/F1';
      const size = line.size;
      contentParts.push(
        `BT ${font} ${size} Tf 1 0 0 1 ${MARGIN} ${y.toFixed(2)} Tm (${escapePdfText(toLatin1(line.text))}) Tj ET`,
      );
      y -= LINE_HEIGHT;
    }
    const stream = contentParts.join('\n');
    objects.push({
      id: pageId,
      body: Buffer.from(
        `<< /Type /Page /Parent 2 0 R /MediaBox [0 0 ${PAGE_WIDTH} ${PAGE_HEIGHT}] /Resources << /Font << /F1 3 0 R /F2 4 0 R >> >> /Contents ${contentId} 0 R >>`,
      ),
    });
    const streamBody = Buffer.from(`<< /Length ${Buffer.byteLength(stream, 'latin1')} >>\nstream\n${stream}\nendstream`);
    objects.push({ id: contentId, body: streamBody });
  });

  // Serialize with correct xref offsets.
  const header = Buffer.from('%PDF-1.4\n%\xE2\xE3\xCF\xD3\n');
  const chunks: Buffer[] = [header];
  const offsets: number[] = [];
  let position = header.length;
  const maxId = Math.max(...objects.map((o) => o.id));
  const sorted = objects.slice().sort((a, b) => a.id - b.id);
  for (const object of sorted) {
    offsets[object.id] = position;
    const serialized = Buffer.concat([Buffer.from(`${object.id} 0 obj\n`), object.body, Buffer.from('\nendobj\n')]);
    chunks.push(serialized);
    position += serialized.length;
  }

  const xrefStart = position;
  let xref = `xref\n0 ${maxId + 1}\n0000000000 65535 f \n`;
  for (let id = 1; id <= maxId; id++) {
    const offset = offsets[id] ?? 0;
    xref += `${String(offset).padStart(10, '0')} 00000 n \n`;
  }
  chunks.push(Buffer.from(xref));
  chunks.push(Buffer.from(`trailer\n<< /Size ${maxId + 1} /Root 1 0 R >>\nstartxref\n${xrefStart}\n%%EOF\n`));

  return Buffer.concat(chunks);
}
