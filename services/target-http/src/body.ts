/**
 * Request body serialization (spec Part 3 §67-§68).
 *
 * Workers never construct raw multipart boundaries — they provide the
 * structured body input and this module serializes deterministically.
 * Parsed representations are kept alongside raw bytes so evidence can
 * reference both (§67: "Preserve raw representation where evidence
 * requires it. Provide parsed representation separately.").
 */
import { createHash } from 'node:crypto';
import type { HttpBodyInput } from '@aegis/contracts';

export interface SerializedBody {
  bytes: Uint8Array;
  contentType: string | null;
  parsed: unknown;
  byteLength: number;
  sha256: string;
}

const textEncoder = new TextEncoder();

export function serializeBody(input: HttpBodyInput): SerializedBody {
  switch (input.body_type) {
    case 'JSON':
      return serializeJson(input.data);
    case 'FORM_URLENCODED':
      return serializeForm(input.fields);
    case 'MULTIPART':
      return serializeMultipart(input.fields, input.files ?? []);
    case 'TEXT':
      return serializeText(input.text, null);
    case 'XML':
      return serializeText(input.text, 'application/xml');
    case 'BINARY':
      return serializeBinary(input.content_b64, input.content_type);
    case 'EMPTY':
      return empty();
    default: {
      const exhaustive: never = input;
      throw new Error(`Unknown body type: ${String((exhaustive as { body_type: string }).body_type)}`);
    }
  }
}

function finish(bytes: Uint8Array, contentType: string | null, parsed: unknown): SerializedBody {
  return {
    bytes,
    contentType,
    parsed,
    byteLength: bytes.byteLength,
    sha256: createHash('sha256').update(bytes).digest('hex'),
  };
}

function serializeJson(data: unknown): SerializedBody {
  const canonical = JSON.stringify(data ?? null);
  return finish(textEncoder.encode(canonical), 'application/json', data ?? null);
}

function serializeForm(fields: Array<{ name: string; value: string }>): SerializedBody {
  const encoded = fields.map((f) => `${encodeURIComponent(f.name)}=${encodeURIComponent(f.value)}`).join('&');
  return finish(
    textEncoder.encode(encoded),
    'application/x-www-form-urlencoded',
    fields.map((f) => ({ name: f.name, value: f.value })),
  );
}

/** Deterministic multipart serialization (§68) — the engine owns boundaries. */
function serializeMultipart(
  fields: Array<{ name: string; value: string }>,
  files: Array<{ name: string; filename: string; content_b64: string }>,
): SerializedBody {
  // Content-derived boundary keeps serialization deterministic for the
  // same input while guaranteeing no collision with content.
  const boundary = `----aegis-${createHash('sha256')
    .update(JSON.stringify({ fields, files }))
    .digest('hex')
    .slice(0, 24)}`;
  const chunks: Uint8Array[] = [];
  const push = (s: string): void => {
    chunks.push(textEncoder.encode(s));
  };

  for (const field of fields) {
    push(`--${boundary}\r\n`);
    push(`Content-Disposition: form-data; name="${escapeQuotes(field.name)}"\r\n\r\n`);
    push(`${field.value}\r\n`);
  }
  for (const file of files) {
    push(`--${boundary}\r\n`);
    push(`Content-Disposition: form-data; name="${escapeQuotes(file.name)}"; filename="${escapeQuotes(file.filename)}"\r\n`);
    push('Content-Type: application/octet-stream\r\n\r\n');
    chunks.push(Buffer.from(file.content_b64, 'base64'));
    push('\r\n');
  }
  push(`--${boundary}--\r\n`);

  const total = chunks.reduce((sum, c) => sum + c.byteLength, 0);
  const merged = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    merged.set(chunk, offset);
    offset += chunk.byteLength;
  }

  return finish(merged, `multipart/form-data; boundary=${boundary}`, {
    fields: fields.map((f) => ({ name: f.name, value: f.value })),
    files: files.map((f) => ({ name: f.name, filename: f.filename, bytes: byteLengthOfB64(f.content_b64) })),
  });
}

function byteLengthOfB64(b64: string): number {
  const padding = b64.endsWith('==') ? 2 : b64.endsWith('=') ? 1 : 0;
  return Math.max(0, Math.floor((b64.length * 3) / 4) - padding);
}

function serializeText(text: string, contentType: string | null): SerializedBody {
  return finish(textEncoder.encode(text), contentType, { text });
}

function serializeBinary(contentB64: string, contentType?: string): SerializedBody {
  const bytes = new Uint8Array(Buffer.from(contentB64, 'base64'));
  return finish(bytes, contentType ?? 'application/octet-stream', null);
}

function empty(): SerializedBody {
  return finish(new Uint8Array(0), null, null);
}

function escapeQuotes(value: string): string {
  return value.replace(/["\\]/g, (c) => `\\${c}`);
}

// ---------------------------------------------------------------------------
// Response body parsing (§17: never assume every response is text).
// ---------------------------------------------------------------------------

export interface ParsedResponseBody {
  kind: 'JSON' | 'HTML' | 'XML' | 'TEXT' | 'BINARY' | 'IMAGE' | 'FILE' | 'UNKNOWN';
  parsed: unknown;
  /** Truncated text preview, safe for model context. */
  textPreview: string | null;
}

export function parseResponseBody(bytes: Uint8Array, contentType: string | null): ParsedResponseBody {
  const kind = classify(contentType);
  if (kind === 'JSON') {
    try {
      const text = decodeText(bytes);
      return { kind, parsed: JSON.parse(text) as unknown, textPreview: preview(text) };
    } catch {
      return { kind: 'TEXT', parsed: null, textPreview: preview(decodeText(bytes)) };
    }
  }
  if (kind === 'HTML' || kind === 'XML' || kind === 'TEXT') {
    const text = decodeText(bytes);
    return { kind, parsed: null, textPreview: preview(text) };
  }
  return { kind, parsed: null, textPreview: null };
}

function decodeText(bytes: Uint8Array): string {
  return new TextDecoder('utf-8', { fatal: false }).decode(bytes);
}

function preview(text: string): string {
  const MAX = 2048;
  return text.length > MAX ? `${text.slice(0, MAX)}…[truncated]` : text;
}

function classify(contentType: string | null): ParsedResponseBody['kind'] {
  const ct = (contentType ?? '').toLowerCase();
  if (ct.includes('application/json') || ct.includes('+json')) return 'JSON';
  if (ct.includes('text/html')) return 'HTML';
  if (ct.includes('text/xml') || ct.includes('application/xml') || ct.includes('+xml')) return 'XML';
  if (ct.startsWith('text/')) return 'TEXT';
  if (ct === '') return 'UNKNOWN';
  return 'BINARY';
}
