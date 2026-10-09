/** Exporter registry (spec Part 7 §63): JSON / HTML / Markdown / PDF. */
export { renderMarkdown, type ExportInput } from './markdown.js';
export { renderJson, type JsonReportDocument } from './json.js';
export { renderHtml } from './html.js';
export { renderPdf, reportToLines } from './pdf.js';
