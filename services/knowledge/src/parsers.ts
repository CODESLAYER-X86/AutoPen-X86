/**
 * Content parsers (spec Part 5 §49-§56).
 *
 * Every parser converts a raw document into STRUCTURED BLOCKS:
 *
 *   { kind: 'heading'|'text'|'code'|'table'|'list', level?, language?, content }
 *
 * The chunker then assembles blocks into semantic chunks (§9-§10).
 *
 * Sanitization principles (§49-§52):
 *  - scripts/styles are REMOVED, never executed — scripts are data at most
 *  - code examples are PRESERVED as code blocks (§51)
 *  - headings and structure are retained
 *  - visible text is extracted; encoding normalized
 *  - prompt-injection-looking content is stored as content, not deleted
 *    (§49: "Do not blindly delete every suspicious string")
 */

export interface ContentBlock {
  kind: 'heading' | 'text' | 'code' | 'table' | 'list';
  /** Heading level 1-6 for headings. */
  level?: number;
  /** Language for code blocks. */
  language?: string | null;
  content: string;
}

export interface ParsedDocument {
  blocks: ContentBlock[];
  title: string | null;
  /** Raw meta extracted by the parser (title tag, JSON fields, ...). */
  meta: Record<string, string>;
}

// ---------------------------------------------------------------------------
// HTML (§51-§52).
// ---------------------------------------------------------------------------

const HTML_SCRIPT = /<script\b[^>]*>[\s\S]*?<\/script>/gi;
const HTML_STYLE = /<style\b[^>]*>[\s\S]*?<\/style>/gi;
const HTML_COMMENT = /<!--[\s\S]*?-->/g;
const HTML_HEAD = /<head\b[^>]*>[\s\S]*?<\/head>/gi;

/** Extract a meta tag content attribute. */
function metaContent(html: string, name: string): string | null {
  const re = new RegExp(
    `<meta[^>]+(?:name|property)\\s*=\\s*["']${name}["'][^>]*content\\s*=\\s*["']([^"']{0,500})["']`,
    'i',
  );
  const alt = new RegExp(
    `<meta[^>]+content\\s*=\\s*["']([^"']{0,500})["'][^>]*(?:name|property)\\s*=\\s*["']${name}["']`,
    'i',
  );
  return re.exec(html)?.[1] ?? alt.exec(html)?.[1] ?? null;
}

function decodeEntities(text: string): string {
  return text
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"')
    .replace(/&#39;|&apos;/g, "'")
    .replace(/&nbsp;/g, ' ')
    .replace(/&amp;/g, '&');
}

function collapse(text: string): string {
  return text.replace(/\s+/g, ' ').trim();
}

/**
 * HTML → structured blocks. Sanitization (§49/§51): scripts, styles and
 * comments are removed entirely; everything else becomes visible text with
 * heading/table/list/code structure retained. <pre> and <code> survive as
 * code blocks so technical examples remain retrievable (§56).
 */
export function parseHtml(raw: string): ParsedDocument {
  const meta: Record<string, string> = {};
  const headMatch = /<head\b[^>]*>[\s\S]*?<\/head>/i.exec(raw);
  const head = headMatch?.[0] ?? '';
  const titleMatch = /<title\b[^>]*>([\s\S]{0,500}?)<\/title>/i.exec(raw);
  if (titleMatch) meta['title'] = collapse(decodeEntities(titleMatch[1]!));

  const body = raw
    .replace(HTML_HEAD, '')
    .replace(HTML_SCRIPT, ' ')
    .replace(HTML_STYLE, ' ')
    .replace(HTML_COMMENT, ' ');

  const blocks: ContentBlock[] = [];
  // Split on structural tags while remembering what each was.
  const marker = /<(h[1-6])\b[^>]*>|<\/(h[1-6])>|<(p)\b[^>]*>|<(pre)\b[^>]*>|<(table)\b[^>]*>|<(ul|ol)\b[^>]*>|<(div)\b[^>]*>|<(br|hr)\b[^?]?\/?>/gi;
  let cursor = 0;
  const plainStack: string[] = [];
  let lastMatch: RegExpExecArray | null;
  while ((lastMatch = marker.exec(body)) !== null) {
    const plain = body.slice(cursor, lastMatch.index);
    if (plain.trim()) plainStack.push(decodeEntities(plain));
    const tag = lastMatch[0].toLowerCase();
    cursor = lastMatch.index + lastMatch[0].length;
    const flushText = () => {
      const joined = plainStack.join(' ');
      plainStack.length = 0;
      // Closing/inline tags accumulate with the plain text — strip them so
      // only visible text remains.
      const collapsed = collapse(decodeEntities(stripTags(joined)));
      if (collapsed) blocks.push({ kind: 'text', content: collapsed });
    };
    if (/^<h[1-6]/.test(tag)) {
      const level = Number(tag[2]);
      const close = new RegExp(`</h${level}\\s*>`, 'i');
      close.lastIndex = 0;
      const rest = close.exec(body.slice(cursor));
      const end = rest ? cursor + rest.index : body.length;
      const headingText = body.slice(cursor, end);
      const text = collapse(decodeEntities(stripTags(headingText)));
      if (text) blocks.push({ kind: 'heading', level, content: text });
      cursor = rest ? cursor + rest.index + rest[0].length : body.length;
    } else if (tag.startsWith('<pre')) {
      flushText();
      const close = /<\/pre\s*>/i;
      const rest = close.exec(body.slice(cursor));
      const end = rest ? cursor + rest.index : body.length;
      const code = body.slice(cursor, end);
      const text = code.replace(/<[^>]+>/g, '').trim();
      if (text) blocks.push({ kind: 'code', language: null, content: text });
      cursor = rest ? cursor + rest.index + rest[0].length : body.length;
    } else if (tag.startsWith('<table')) {
      flushText();
      const rest = /<\/table\s*>/i.exec(body.slice(cursor));
      const end = rest ? cursor + rest.index : body.length;
      const rows = extractTableRows(body.slice(cursor, end));
      if (rows.length > 0) blocks.push({ kind: 'table', content: rows.join('\n') });
      cursor = rest ? cursor + rest.index + rest[0].length : body.length;
    } else if (/^<(ul|ol)/.test(tag)) {
      flushText();
      const listTag = lastMatch[0].toLowerCase().startsWith('<ul') ? 'ul' : 'ol';
      const rest = new RegExp(`</${listTag}\\s*>`, 'i').exec(body.slice(cursor));
      const end = rest ? cursor + rest.index : body.length;
      const items = [...body.slice(cursor, end).matchAll(/<li\b[^>]*>([\s\S]*?)<\/li>/gi)].map((m) =>
        collapse(decodeEntities(stripTags(m[1]!))),
      );
      if (items.length > 0) {
        blocks.push({ kind: 'list', content: items.map((item, i) => `${i + 1}. ${item}`).join('\n') });
      }
      cursor = rest ? cursor + rest.index + rest[0].length : body.length;
    } else if (tag.startsWith('<p') || tag.startsWith('<div') || tag === '<br>' || tag === '<hr>') {
      flushText();
    }
  }
  const tail = body.slice(cursor);
  if (tail.trim()) {
    const collapsed = collapse(decodeEntities(stripTags(tail)));
    if (collapsed) blocks.push({ kind: 'text', content: collapsed });
  }

  const title = meta['title'] ?? blocks.find((b) => b.kind === 'heading')?.content ?? null;
  const author = metaContent(head, 'author') ?? metaContent(raw, 'author');
  if (author) meta['author'] = author;
  const date = metaContent(head, 'date') ?? metaContent(raw, 'article:published_time');
  if (date) meta['date'] = date;
  const lang = /<html[^>]+lang\s*=\s*["']([a-zA-Z-]{2,16})["']/i.exec(raw)?.[1];
  if (lang) meta['lang'] = lang;
  return { blocks, title, meta };
}

function stripTags(html: string): string {
  return html.replace(/<[^>]+>/g, ' ');
}

function extractTableRows(tableHtml: string): string[] {
  const rows: string[] = [];
  for (const rowMatch of tableHtml.matchAll(/<tr\b[^>]*>([\s\S]*?)<\/tr>/gi)) {
    const cells = [...rowMatch[1]!.matchAll(/<(?:td|th)\b[^>]*>([\s\S]*?)<\/(?:td|th)>/gi)].map((c) =>
      collapse(decodeEntities(stripTags(c[1]!))),
    );
    if (cells.length > 0) rows.push(cells.join(' | '));
  }
  return rows;
}

// ---------------------------------------------------------------------------
// Markdown.
// ---------------------------------------------------------------------------

export function parseMarkdown(raw: string): ParsedDocument {
  const lines = raw.split(/\r?\n/);
  const blocks: ContentBlock[] = [];
  let title: string | null = null;
  let inCode = false;
  let codeLanguage: string | null = null;
  let codeBuffer: string[] = [];
  let textBuffer: string[] = [];
  let tableBuffer: string[] = [];
  let listBuffer: string[] = [];

  const flushText = () => {
    const joined = textBuffer.join('\n').trim();
    if (joined) blocks.push({ kind: 'text', content: joined });
    textBuffer = [];
  };
  const flushList = () => {
    if (listBuffer.length > 0) {
      blocks.push({
        kind: 'list',
        content: listBuffer.map((item, i) => `${i + 1}. ${item}`).join('\n'),
      });
      listBuffer = [];
    }
  };
  const flushTable = () => {
    if (tableBuffer.length > 0) {
      const rows = tableBuffer
        .map((row) => row.replace(/^\|/, '').replace(/\|$/, '').split('|').map((c) => c.trim()).join(' | '))
        .filter((row) => !/^[ :-]+\|/.test(row) && !/^\|?[-: |]+\|?$/.test(row));
      if (rows.length > 0) blocks.push({ kind: 'table', content: rows.join('\n') });
      tableBuffer = [];
    }
  };

  for (const line of lines) {
    if (line.trim().startsWith('```')) {
      if (inCode) {
        flushText();
        flushList();
        flushTable();
        blocks.push({ kind: 'code', language: codeLanguage, content: codeBuffer.join('\n') });
        codeBuffer = [];
        codeLanguage = null;
        inCode = false;
      } else {
        flushText();
        flushList();
        flushTable();
        inCode = true;
        codeLanguage = line.trim().slice(3).trim() || null;
      }
      continue;
    }
    if (inCode) {
      codeBuffer.push(line);
      continue;
    }
    if (line.trim().startsWith('|')) {
      flushText();
      flushList();
      tableBuffer.push(line.trim());
      continue;
    }
    flushTable();
    const heading = /^(#{1,6})\s+(.*)$/.exec(line);
    if (heading) {
      flushText();
      flushList();
      const content = heading[2]!.trim();
      if (!title && heading[1]!.length === 1) title = content;
      blocks.push({ kind: 'heading', level: heading[1]!.length, content });
      continue;
    }
    const bullet = /^\s*(?:[-*+]|\d+[.)])\s+/.test(line);
    if (bullet) {
      flushText();
      listBuffer.push(line.trim().replace(/^\s*(?:[-*+]|\d+[.)])\s+/, ''));
      continue;
    }
    flushList();
    textBuffer.push(line);
  }
  if (inCode && codeBuffer.length > 0) {
    blocks.push({ kind: 'code', language: codeLanguage, content: codeBuffer.join('\n') });
  }
  flushText();
  flushList();
  flushTable();
  return { blocks, title, meta: title ? { title } : {} };
}

// ---------------------------------------------------------------------------
// Plain text / JSON / XML.
// ---------------------------------------------------------------------------

export function parseText(raw: string): ParsedDocument {
  // Paragraph-group extraction: blank-line separated groups.
  const groups = raw.split(/\n\s*\n/).map((g) => g.replace(/\s+/g, ' ').trim()).filter(Boolean);
  return {
    blocks: groups.map((content) => ({ kind: 'text' as const, content })),
    title: null,
    meta: {},
  };
}

export function parseJson(raw: string): ParsedDocument {
  let value: unknown;
  try {
    value = JSON.parse(raw);
  } catch {
    // Unparseable JSON degrades to text (§116: never lose the source).
    return parseText(raw);
  }
  const lines: string[] = [];
  const walk = (node: unknown, path: string, depth: number) => {
    if (depth > 6) return;
    if (Array.isArray(node)) {
      lines.push(`${path} (array, ${node.length} items)`);
      node.slice(0, 20).forEach((item, i) => walk(item, `${path}[${i}]`, depth + 1));
    } else if (node !== null && typeof node === 'object') {
      for (const [key, child] of Object.entries(node as Record<string, unknown>)) {
        const childPath = path ? `${path}.${key}` : key;
        if (child !== null && typeof child === 'object') {
          walk(child, childPath, depth + 1);
        } else {
          const rendered = typeof child === 'string' ? child.slice(0, 300) : String(child);
          lines.push(`${childPath} = ${rendered}`);
        }
      }
    } else {
      lines.push(`${path} = ${String(node)}`);
    }
  };
  walk(value, '', 0);
  const title = (value as { title?: unknown })?.title;
  return {
    blocks: [{ kind: 'text', content: lines.join('\n') }],
    title: typeof title === 'string' ? title : null,
    meta: typeof title === 'string' ? { title } : {},
  };
}

export function parseXml(raw: string): ParsedDocument {
  // Structural extraction: tags become headings, text nodes become blocks.
  const blocks: ContentBlock[] = [];
  const cleaned = raw.replace(/<\?[\s\S]*?\?>/g, ' ').replace(/<!--[\s\S]*?-->/g, ' ');
  const parts = cleaned.split(/(<[^>]+>)/);
  let title: string | null = null;
  let currentTag: string | null = null;
  const buffer: string[] = [];
  const flush = () => {
    const text = buffer.join(' ').replace(/\s+/g, ' ').trim();
    buffer.length = 0;
    if (!text) return;
    if (currentTag && /^(title|heading|h[1-6]|section|chapter)$/i.test(currentTag)) {
      if (!title && currentTag.toLowerCase() === 'title') title = text;
      blocks.push({ kind: 'heading', level: 2, content: text });
    } else {
      blocks.push({ kind: 'text', content: text });
    }
  };
  for (const part of parts) {
    if (part.startsWith('<') && part.endsWith('>')) {
      flush();
      const name = part.slice(1, -1).split(/[\s>]/)[0]?.replace('/', '') ?? '';
      currentTag = name || null;
    } else if (part.trim()) {
      buffer.push(part.trim());
    }
  }
  flush();
  return { blocks, title, meta: title ? { title } : {} };
}

// ---------------------------------------------------------------------------
// Content-type detection (§26: identify content type).
// ---------------------------------------------------------------------------

export type DocumentKind = 'HTML' | 'MARKDOWN' | 'TXT' | 'JSON' | 'XML' | 'PDF';

/** Detect document kind from content-type header + body sniffing. */
export function detectDocumentKind(contentType: string | null, body: string): DocumentKind {
  const ct = (contentType ?? '').toLowerCase();
  if (ct.includes('pdf')) return 'PDF';
  if (ct.includes('html')) return 'HTML';
  if (ct.includes('json')) return 'JSON';
  if (ct.includes('xml')) return 'XML';
  if (ct.includes('markdown')) return 'MARKDOWN';
  const trimmed = body.slice(0, 2048).trim();
  if (!trimmed) return 'TXT';
  if (trimmed.startsWith('%PDF')) return 'PDF';
  if (/^<!doctype html|^<html[\s>]/i.test(trimmed)) return 'HTML';
  if (/^<\?xml|^<[a-z][\w:.-]*[\s\S]*>/i.test(trimmed) && trimmed.startsWith('<')) return 'XML';
  if (/^[[{]/.test(trimmed)) {
    try {
      JSON.parse(trimmed);
      return 'JSON';
    } catch {
      /* fall through */
    }
  }
  if (/^#{1,6}\s+\S/m.test(trimmed) || /\n```/.test(trimmed)) return 'MARKDOWN';
  return 'TXT';
}

/** Parse a document by kind; unknown content degrades to text (§116). */
export function parseByKind(kind: DocumentKind, raw: string): ParsedDocument {
  switch (kind) {
    case 'HTML':
      return parseHtml(raw);
    case 'MARKDOWN':
      return parseMarkdown(raw);
    case 'JSON':
      return parseJson(raw);
    case 'XML':
      return parseXml(raw);
    case 'PDF':
      // PDF bytes are handled by the pdf module (binary path); when text
      // reaches here it is already extracted text.
      return parseText(raw);
    default:
      return parseText(raw);
  }
}
