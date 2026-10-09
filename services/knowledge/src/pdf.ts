/**
 * Minimal PDF text extraction (spec Part 5 §55).
 *
 * A compact, dependency-free extractor for text-based PDFs:
 *  - locates content streams (`stream ... endstream`)
 *  - inflates FlateDecode streams (node:zlib)
 *  - extracts text from Tj / TJ / ' / " operators
 *  - counts pages via `/Type /Page` objects
 *  - preserves approximate page references (§55)
 *
 * Honest limitations: encrypted PDFs and documents relying on font remapping
 * without ToUnicode tables degrade to partial text. When extraction yields
 * no text the document is still retained as a raw artifact with an
 * ingestion warning (§116: parser failure never loses the source).
 */
import { inflateSync, inflateRawSync } from 'node:zlib';
import type { ContentBlock } from './parsers.js';
import { estimateTokens } from './util.js';

export interface PdfExtraction {
  blocks: ContentBlock[];
  title: string | null;
  pageCount: number;
  pageMarkers: number[];
  truncated: boolean;
}

/** Extract text from one decoded content stream. */
function extractTextOperators(content: string): string {
  const out: string[] = [];
  // Track text positioning enough to insert line breaks after Td/T*/TJ arrays.
  const tokenRe = /\((?:\\.|[^\\()])*\)|<[0-9A-Fa-f\s]+>|\bT[dDmJbB]\b|\bT\*\b|\bET\b|\bBT\b|'|"|;/g;
  let pendingLine: string[] = [];
  let match: RegExpExecArray | null;
  while ((match = tokenRe.exec(content)) !== null) {
    const token = match[0];
    if (token.startsWith('(') && token.endsWith(')')) {
      pendingLine.push(decodePdfString(token.slice(1, -1)));
    } else if (token.startsWith('<') && token.endsWith('>')) {
      // Hex string: decode as UTF-16BE when it looks like it, else Latin-1.
      const hex = token.slice(1, -1).replace(/\s+/g, '');
      const bytes: number[] = [];
      for (let i = 0; i + 1 < hex.length; i += 2) {
        bytes.push(Number.parseInt(hex.slice(i, i + 2), 16) || 0);
      }
      pendingLine.push(decodePdfHex(bytes));
    } else if (token === 'Td' || token === 'TD' || token === 'T*' || token === 'Tm') {
      if (pendingLine.length > 0) {
        out.push(pendingLine.join(''));
        pendingLine = [];
      }
    } else if (token === "'" || token === '"') {
      if (pendingLine.length > 0) {
        out.push(pendingLine.join(''));
        pendingLine = [];
      }
    }
  }
  if (pendingLine.length > 0) out.push(pendingLine.join(''));
  return out.join('\n');
}

function decodePdfString(raw: string): string {
  let out = '';
  for (let i = 0; i < raw.length; i += 1) {
    const ch = raw[i]!;
    if (ch === '\\') {
      const next = raw[i + 1];
      i += 1;
      switch (next) {
        case 'n':
          out += '\n';
          break;
        case 'r':
          out += '\r';
          break;
        case 't':
          out += '\t';
          break;
        case 'b':
        case 'f':
          out += ' ';
          break;
        case '(':
        case ')':
        case '\\':
          out += next;
          break;
        default:
          if (next && /[0-7]/.test(next)) {
            // Up to three octal digits.
            let octal = next;
            while (i + 1 < raw.length && octal.length < 3 && /[0-7]/.test(raw[i + 1]!)) {
              i += 1;
              octal += raw[i]!;
            }
            out += String.fromCharCode(Number.parseInt(octal, 8));
          } else if (next) {
            out += next;
          }
      }
    } else {
      out += ch;
    }
  }
  return out;
}

function decodePdfHex(bytes: number[]): string {
  if (bytes.length >= 2 && bytes[0] === 0xfe && bytes[1] === 0xff) {
    let out = '';
    for (let i = 2; i + 1 < bytes.length; i += 2) out += String.fromCharCode((bytes[i]! << 8) | bytes[i + 1]!);
    return out;
  }
  return bytes.map((b) => String.fromCharCode(b)).join('');
}

function tryInflate(data: Buffer): Buffer | null {
  for (const fn of [inflateSync, inflateRawSync]) {
    try {
      return fn(data);
    } catch {
      /* try next */
    }
  }
  return null;
}

const MAX_STREAM_BYTES = 8 * 1024 * 1024;
const MAX_OUTPUT_CHARS = 400_000;

/**
 * Extract text blocks from PDF bytes. Page references are approximated by
 * ordering (§55); complex layouts degrade gracefully.
 */
export function extractPdf(bytes: Uint8Array): PdfExtraction {
  const buf = Buffer.from(bytes);
  const latin = buf.toString('latin1');
  const pageCount = Math.max(1, (latin.match(/\/Type\s*\/Page[^s]/g) ?? []).length);
  const title = /\/Title\s*\((?:\\.|[^\\()]){1,300}\)/.exec(latin)?.[0]
    ?.replace(/^\/Title\s*\(/, '')
    .replace(/\)$/, '');
  const blocks: ContentBlock[] = [];
  const pageMarkers: number[] = [];
  let truncated = false;
  let totalChars = 0;

  // Walk over stream sections in order.
  const streamRe = /stream\r?\n?/g;
  let match: RegExpExecArray | null;
  while ((match = streamRe.exec(latin)) !== null) {
    const end = latin.indexOf('endstream', match.index + match[0].length);
    if (end === -1) break;
    const start = match.index + match[0].length;
    const length = end - start;
    if (length <= 0 || length > MAX_STREAM_BYTES) continue;
    const rawStream = buf.subarray(start, end);
    const inflated = tryInflate(rawStream) ?? rawStream;
    const content = inflated.toString('latin1');
    if (!/(?:\(|TJ|Tj|BT)/.test(content)) continue;
    const text = extractTextOperators(content).replace(/[ \t]+/g, ' ').replace(/\n{2,}/g, '\n').trim();
    if (!text) continue;
    // A stream containing BT/ET marks roughly marks a new page of content.
    if (/\/Type\s*\/Page[^s]/.test(latin.slice(Math.max(0, match.index - 400), match.index))) {
      pageMarkers.push(blocks.length);
    }
    if (totalChars + text.length > MAX_OUTPUT_CHARS) {
      truncated = true;
      break;
    }
    totalChars += text.length;
    // Split long extracted streams into paragraph-ish chunks.
    const paragraphs = text.split('\n').filter((p) => p.trim().length > 0);
    for (const paragraph of paragraphs) {
      const trimmed = paragraph.trim();
      if (!trimmed) continue;
      blocks.push({ kind: 'text', content: trimmed.slice(0, 4000) });
    }
  }

  return { blocks, title: title ?? null, pageCount, pageMarkers, truncated };
}

/** Token estimate of the extraction for budget purposes. */
export function pdfTokenEstimate(extraction: PdfExtraction): number {
  return estimateTokens(extraction.blocks.map((b) => b.content).join('\n'));
}
