/**
 * Semantic chunker (spec Part 5 §9-§12, §56).
 *
 * Chunks are built AROUND semantic boundaries — headings, paragraph groups,
 * procedures, tables and code examples — never arbitrary fixed-size cuts
 * (§9: "Do not use arbitrary fixed-size chunks only").
 *
 *  - target size is configurable (§11, default 300-800 tokens)
 *  - every chunk keeps its heading path (§12: parent-child retrieval)
 *  - code blocks stay separate chunks (§56)
 *  - PROCEDURE chunks are detected from enumerated steps
 *  - a chunk exceeding the max is split at paragraph boundaries with the
 *    heading retained in the continuation
 */
import { contentHash, estimateTokens } from './util.js';
import type { ContentBlock } from './parsers.js';

export interface ChunkInput {
  documentId: string;
  blocks: ContentBlock[];
  minTokens: number;
  maxTokens: number;
}

export interface ChunkedPiece {
  documentId: string;
  heading: string | null;
  headingPath: string[];
  section: string | null;
  content: string;
  tokenEstimate: number;
  kind: 'TEXT' | 'CODE' | 'TABLE' | 'PROCEDURE' | 'EXAMPLE';
  codeLanguage: string | null;
  contentHash: string;
  parentChunkId: string | null;
  /** Sequence number within the document. */
  sequence: number;
}

export interface ChunkerResult {
  chunks: ChunkedPiece[];
  /** How many oversized chunks had to be split. */
  splitCount: number;
}

/** Detect enumerated procedure steps (§10: procedure sections). */
function isProcedureList(content: string): boolean {
  const lines = content.split('\n').filter((l) => l.trim().length > 0);
  if (lines.length < 3) return false;
  const numbered = lines.filter((l) => /^\d+[.)]\s+\S/.test(l.trim())).length;
  return numbered / lines.length >= 0.6;
}

/** Detect example blocks (§10: examples). */
function isExample(content: string): boolean {
  return /\bfor example\b|\be\.g\.|\bexample:\b|\bsample (?:request|response|code)\b/i.test(content);
}

/**
 * Assemble blocks into semantic chunks. The heading path is maintained so a
 * retrieved chunk can pull its parent context (§12).
 */
export function chunkDocument(input: ChunkInput): ChunkerResult {
  const { documentId, blocks, minTokens, maxTokens } = input;
  const chunks: ChunkedPiece[] = [];
  let headingPath: string[] = [];
  let section: string | null = null;
  let buffer: string[] = [];
  let bufferKind: 'TEXT' | null = null;
  let bufferTokens = 0;
  let splitCount = 0;
  let sequence = 0;

  const flush = () => {
    // The special block that follows carries its own kind; the buffered
    // TEXT always flushes as text (never mislabelled).
    const content = buffer.join('\n').trim();
    if (!content) {
      buffer = [];
      bufferKind = null;
      bufferTokens = 0;
      return;
    }
    const kind: ChunkedPiece['kind'] = (bufferKind ?? 'TEXT') as ChunkedPiece['kind'];
    let pieces: string[];
    if (estimateTokens(content) > maxTokens && kind !== 'CODE') {
      // Split at paragraph boundaries, retaining heading context (§9).
      pieces = splitContent(content, maxTokens);
      splitCount += pieces.length - 1;
    } else if (kind === 'CODE' && estimateTokens(content) > maxTokens * 2) {
      // Very long code is truncated to a bounded excerpt — the full source
      // remains in the raw artifact (§94).
      pieces = [content.slice(0, maxTokens * 4)];
      splitCount += 1;
    } else {
      pieces = [content];
    }
    for (const piece of pieces) {
      const trimmed = piece.trim();
      if (!trimmed) continue;
      const detectedKind =
        kind === 'TEXT' && isProcedureList(trimmed)
          ? 'PROCEDURE'
          : kind === 'TEXT' && isExample(trimmed)
            ? 'EXAMPLE'
            : kind;
      chunks.push({
        documentId,
        heading: headingPath.at(-1) ?? null,
        headingPath: [...headingPath],
        section,
        content: trimmed,
        tokenEstimate: estimateTokens(trimmed),
        kind: detectedKind,
        codeLanguage: null,
        contentHash: contentHash(trimmed),
        parentChunkId: null,
        sequence: sequence++,
      });
    }
    buffer = [];
    bufferKind = null;
    bufferTokens = 0;
  };

  for (const block of blocks) {
    if (block.kind === 'heading') {
      flush();
      const level = block.level ?? 2;
      headingPath = headingPath.slice(0, Math.max(0, level - 1));
      headingPath[level - 1] = block.content.slice(0, 256);
      headingPath = headingPath.slice(0, level);
      if (level <= 2) section = block.content.slice(0, 256);
      continue;
    }
    if (block.kind === 'code') {
      // Code never merges with prose (§56).
      flush();
      chunks.push({
        documentId,
        heading: headingPath.at(-1) ?? null,
        headingPath: [...headingPath],
        section,
        content: block.content,
        tokenEstimate: estimateTokens(block.content),
        kind: 'CODE',
        codeLanguage: block.language ?? guessLanguage(block.content),
        contentHash: contentHash(block.content),
        parentChunkId: null,
        sequence: sequence++,
      });
      continue;
    }
    if (block.kind === 'table') {
      flush();
      chunks.push({
        documentId,
        heading: headingPath.at(-1) ?? null,
        headingPath: [...headingPath],
        section,
        content: block.content,
        tokenEstimate: estimateTokens(block.content),
        kind: 'TABLE',
        codeLanguage: null,
        contentHash: contentHash(block.content),
        parentChunkId: null,
        sequence: sequence++,
      });
      continue;
    }
    // text | list — accumulate into the current semantic group.
    if (bufferKind !== null && bufferKind !== 'TEXT') flush();
    bufferKind = 'TEXT';
    buffer.push(block.content);
    bufferTokens += estimateTokens(block.content);
    // Merge small paragraphs until the target size is reached (§11).
    if (bufferTokens >= maxTokens) flush();
  }
  flush();

  // Merge trailing/leading micro-chunks below the minimum size when they
  // share the same heading (keeps related concepts together, §10).
  const merged: ChunkedPiece[] = [];
  for (const chunk of chunks) {
    const previous = merged.at(-1);
    if (
      previous &&
      previous.kind === chunk.kind &&
      previous.heading === chunk.heading &&
      previous.tokenEstimate + chunk.tokenEstimate < minTokens * 2 &&
      previous.tokenEstimate < minTokens
    ) {
      previous.content = `${previous.content}\n${chunk.content}`;
      previous.tokenEstimate += chunk.tokenEstimate;
      previous.contentHash = contentHash(previous.content);
    } else {
      merged.push({ ...chunk });
    }
  }
  return { chunks: merged, splitCount };
}

function splitContent(content: string, maxTokens: number): string[] {
  const paragraphs = content.split('\n');
  const pieces: string[] = [];
  let current: string[] = [];
  let currentTokens = 0;
  for (const paragraph of paragraphs) {
    const tokens = estimateTokens(paragraph);
    if (currentTokens + tokens > maxTokens && current.length > 0) {
      pieces.push(current.join('\n'));
      current = [];
      currentTokens = 0;
    }
    if (tokens > maxTokens) {
      // Single oversized paragraph: hard split at sentence boundaries.
      const sentences = paragraph.split(/(?<=[.!?])\s+/);
      let sentenceBuffer: string[] = [];
      let sentenceTokens = 0;
      for (const sentence of sentences) {
        const sentenceTokensNext = estimateTokens(sentence);
        if (sentenceTokens + sentenceTokensNext > maxTokens && sentenceBuffer.length > 0) {
          pieces.push(sentenceBuffer.join(' '));
          sentenceBuffer = [];
          sentenceTokens = 0;
        }
        sentenceBuffer.push(sentence);
        sentenceTokens += sentenceTokensNext;
      }
      if (sentenceBuffer.length > 0) pieces.push(sentenceBuffer.join(' '));
      continue;
    }
    current.push(paragraph);
    currentTokens += tokens;
  }
  if (current.length > 0) pieces.push(current.join('\n'));
  return pieces.filter((p) => p.trim().length > 0);
}

function guessLanguage(code: string): string | null {
  if (/^\s*(?:const|let|var|function|=>|require\(|import\s)/m.test(code)) return 'javascript';
  if (/^\s*(?:def|class\s+\w+\s*\(|import\s+\w+$|print\()/m.test(code)) return 'python';
  if (/^\s*(?:SELECT|INSERT|UPDATE|DELETE)\b/im.test(code)) return 'sql';
  if (/^\s*(?:package|func\s|:=)/m.test(code)) return 'go';
  if (/^\s*<\?xml|^\s*<[a-z]+[\s>]/m.test(code)) return 'xml';
  if (/^\s*[{[][\s\S]*[}\]]$/.test(code.trim()) && /"\s*:/.test(code)) return 'json';
  if (/^\s*curl\s|^\s*(?:GET|POST|PUT|DELETE)\s+\/\S+\s+HTTP\//m.test(code)) return 'http';
  return null;
}
