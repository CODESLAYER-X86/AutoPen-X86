/**
 * Differential testing engine (spec §24-§28, §61, §100-§101, §114).
 *
 * Semantic comparison — never byte-only: JSON structural diff, HTML
 * structural diff, text token diff, binary hash equality. Volatile values
 * are MARKED, not deleted (§27). Similarity is a deterministic signal, not
 * a vulnerability indicator (§28).
 */
import { createHash } from 'node:crypto';

const VOLATILE_NAME_RE =
  /timestamp|(^|[^a-z])time([^a-z]|$)|created|updated|expires|nonce|request_?id|trace|trace_?id|correlation|token|csrf|session_?id|etag|age|signature|generated_?at/i;

const VOLATILE_HEADERS = new Set([
  'date',
  'etag',
  'age',
  'content-length',
  'set-cookie',
  'server-timing',
  'x-request-id',
  'x-trace-id',
  'x-correlation-id',
  'last-modified',
  'vary',
]);

export interface ComparisonResponse {
  status: number | null;
  headers: Array<{ name: string; value: string }>;
  contentType: string | null;
  contentKind: string;
  bodyPreview: string | null;
  bodySha256: string | null;
  contentLength: number;
  truncated: boolean;
  timingMs: number;
  redirectTo: string | null;
}

export interface DifferentialSummary {
  status_changed: boolean;
  status_baseline: number | null;
  status_candidate: number | null;
  headers_changed: string[];
  schema_changed: boolean;
  fields_added: string[];
  fields_removed: string[];
  values_changed: Array<{ path: string; baseline: string; candidate: string; volatile: boolean }>;
  body_similarity: number;
  redirect_changed: boolean;
  timing_changed: boolean;
  volatile_fields: string[];
}

export interface DifferentialOutcome {
  summary: DifferentialSummary;
  detail: Record<string, unknown>;
}

const MAX_COMPARISON_CHARS = 65_536;

/** Compare two response records semantically (§25). */
export function compareResponses(baseline: ComparisonResponse, candidate: ComparisonResponse): DifferentialOutcome {
  const statusChanged = baseline.status !== candidate.status;
  const headersChanged = compareHeaders(baseline.headers, candidate.headers);
  const redirectChanged =
    (baseline.redirectTo ?? null) !== (candidate.redirectTo ?? null) &&
    (baseline.redirectTo !== null || candidate.redirectTo !== null);

  const timingChanged =
    baseline.timingMs > 0 &&
    candidate.timingMs > 0 &&
    Math.abs(baseline.timingMs - candidate.timingMs) / Math.max(baseline.timingMs, candidate.timingMs) > 0.5;

  const bodyComparison = compareBodies(baseline, candidate);

  const summary: DifferentialSummary = {
    status_changed: statusChanged,
    status_baseline: baseline.status,
    status_candidate: candidate.status,
    headers_changed: headersChanged,
    schema_changed: bodyComparison.schemaChanged,
    fields_added: bodyComparison.fieldsAdded,
    fields_removed: bodyComparison.fieldsRemoved,
    values_changed: bodyComparison.valuesChanged,
    body_similarity: bodyComparison.similarity,
    redirect_changed: redirectChanged,
    timing_changed: timingChanged,
    volatile_fields: [...bodyComparison.volatileFields],
  };

  return {
    summary,
    detail: {
      content_kind_baseline: baseline.contentKind,
      content_kind_candidate: candidate.contentKind,
      content_length_baseline: baseline.contentLength,
      content_length_candidate: candidate.contentLength,
      binary_equal:
        baseline.contentKind === 'BINARY' && candidate.contentKind === 'BINARY'
          ? baseline.bodySha256 === candidate.bodySha256
          : null,
      truncated_baseline: baseline.truncated,
      truncated_candidate: candidate.truncated,
    },
  };
}

function compareHeaders(
  baseline: Array<{ name: string; value: string }>,
  candidate: Array<{ name: string; value: string }>,
): string[] {
  const changed: string[] = [];
  const baselineMap = new Map(baseline.map((header) => [header.name.toLowerCase(), header.value]));
  const candidateMap = new Map(candidate.map((header) => [header.name.toLowerCase(), header.value]));
  for (const [name, value] of candidateMap) {
    if (VOLATILE_HEADERS.has(name)) continue;
    const other = baselineMap.get(name);
    if (other === undefined || other !== value) changed.push(name);
  }
  for (const [name] of baselineMap) {
    if (VOLATILE_HEADERS.has(name)) continue;
    if (!candidateMap.has(name)) changed.push(`-${name}`);
  }
  return changed.slice(0, 64);
}

interface BodyComparison {
  schemaChanged: boolean;
  fieldsAdded: string[];
  fieldsRemoved: string[];
  valuesChanged: Array<{ path: string; baseline: string; candidate: string; volatile: boolean }>;
  volatileFields: string[];
  similarity: number;
}

function compareBodies(baseline: ComparisonResponse, candidate: ComparisonResponse): BodyComparison {
  const a = boundedPreview(baseline.bodyPreview);
  const b = boundedPreview(candidate.bodyPreview);

  if (baseline.contentKind === 'JSON' || candidate.contentKind === 'JSON') {
    return compareJsonBodies(a, b);
  }
  if (baseline.contentKind === 'HTML' || candidate.contentKind === 'HTML') {
    return compareHtmlBodies(a, b);
  }
  if (baseline.bodySha256 && candidate.bodySha256 && baseline.contentKind === 'BINARY') {
    return {
      schemaChanged: false,
      fieldsAdded: [],
      fieldsRemoved: [],
      valuesChanged: [],
      volatileFields: [],
      similarity: baseline.bodySha256 === candidate.bodySha256 ? 1 : 0,
    };
  }
  return compareTextBodies(a, b);
}

function boundedPreview(preview: string | null): string {
  if (preview === null) return '';
  return preview.slice(0, MAX_COMPARISON_CHARS);
}

/** JSON structural diff (§26): recursive path walk. */
function compareJsonBodies(a: string, b: string): BodyComparison {
  const parsedA = tryParseJson(a);
  const parsedB = tryParseJson(b);
  if (parsedA === undefined || parsedB === undefined) {
    return compareTextBodies(a, b);
  }
  const pathsA = new Map<string, unknown>();
  const pathsB = new Map<string, unknown>();
  flatten(parsedA, '', pathsA);
  flatten(parsedB, '', pathsB);

  const fieldsAdded: string[] = [];
  const fieldsRemoved: string[] = [];
  const valuesChanged: Array<{ path: string; baseline: string; candidate: string; volatile: boolean }> = [];
  const volatileFields: string[] = [];

  for (const [path] of pathsB) {
    if (!pathsA.has(path)) fieldsAdded.push(path);
  }
  for (const [path, valueA] of pathsA) {
    if (!pathsB.has(path)) {
      fieldsRemoved.push(path);
      continue;
    }
    const valueB = pathsB.get(path);
    const leafA = isLeaf(valueA);
    const leafB = isLeaf(valueB);
    if (leafA && leafB && !jsonEqual(valueA, valueB)) {
      const volatile = isVolatileField(path, valueA, valueB);
      if (volatile) volatileFields.push(path);
      valuesChanged.push({
        path,
        baseline: stringifyBounded(valueA),
        candidate: stringifyBounded(valueB),
        volatile,
      });
    } else if (leafA !== leafB) {
      // type structure change at this path (scalar -> container)
      fieldsAdded.push(leafB ? `${path}` : `${path}.*`);
    }
  }

  const changedCount = valuesChanged.length;
  const volatileCount = valuesChanged.filter((change) => change.volatile).length;
  const structuralCount = fieldsAdded.length + fieldsRemoved.length;
  const totalCount = Math.max(pathsA.size, pathsB.size, 1);
  // Volatile changes count almost nothing; structural changes count fully (§27-§28).
  const difference = (structuralCount + (changedCount - volatileCount) + volatileCount * 0.1) / totalCount;
  return {
    schemaChanged: fieldsAdded.length > 0 || fieldsRemoved.length > 0,
    fieldsAdded: fieldsAdded.slice(0, 64),
    fieldsRemoved: fieldsRemoved.slice(0, 64),
    valuesChanged: valuesChanged.slice(0, 128),
    volatileFields: volatileFields.slice(0, 64),
    similarity: clamp01(1 - difference),
  };
}

function stringifyBounded(value: unknown): string {
  if (value === null) return 'null';
  if (typeof value === 'object') return JSON.stringify(value)?.slice(0, 256) ?? '';
  return String(value).slice(0, 256);
}

/** HTML structural diff (§26): tag/attribute signatures. */
function compareHtmlBodies(a: string, b: string): BodyComparison {
  const tagsA = htmlSignature(a);
  const tagsB = htmlSignature(b);
  let intersection = 0;
  for (const [tag, count] of tagsA) {
    intersection += Math.min(count, tagsB.get(tag) ?? 0);
  }
  const total = sumCounts(tagsA) + sumCounts(tagsB);
  const similarity = total === 0 ? 1 : clamp01((2 * intersection) / total);

  const valuesChanged: Array<{ path: string; baseline: string; candidate: string; volatile: boolean }> = [];
  const formA = formSignature(a);
  const formB = formSignature(b);
  if (formA !== formB) {
    valuesChanged.push({ path: 'form.structure', baseline: formA, candidate: formB, volatile: false });
  }
  return {
    schemaChanged: formA !== formB,
    fieldsAdded: [],
    fieldsRemoved: [],
    valuesChanged,
    volatileFields: [],
    similarity,
  };
}

function compareTextBodies(a: string, b: string): BodyComparison {
  const tokensA = tokenMultiset(a);
  const tokensB = tokenMultiset(b);
  let intersection = 0;
  for (const [token, count] of tokensA) {
    intersection += Math.min(count, tokensB.get(token) ?? 0);
  }
  const total = tokensA.size + tokensB.size;
  const similarity = total === 0 ? 1 : clamp01((2 * intersection) / total);
  return {
    schemaChanged: false,
    fieldsAdded: [],
    fieldsRemoved: [],
    valuesChanged: a === b ? [] : [{ path: 'body.text', baseline: a.slice(0, 128), candidate: b.slice(0, 128), volatile: false }],
    volatileFields: [],
    similarity,
  };
}

function tryParseJson(text: string): unknown | undefined {
  if (text.length === 0) return undefined;
  try {
    return JSON.parse(text) as unknown;
  } catch {
    return undefined;
  }
}

function flatten(value: unknown, prefix: string, out: Map<string, unknown>, depth = 0): void {
  if (depth > 5) return;
  if (Array.isArray(value)) {
    out.set(prefix ? `${prefix}[]` : '[]', value.length);
    value.slice(0, 16).forEach((item, index) => flatten(item, `${prefix}[${index}]`, out, depth + 1));
    return;
  }
  if (value !== null && typeof value === 'object') {
    for (const [key, child] of Object.entries(value as Record<string, unknown>).slice(0, 64)) {
      flatten(child, prefix ? `${prefix}.${key}` : key, out, depth + 1);
    }
    return;
  }
  out.set(prefix, value);
}

function isLeaf(value: unknown): boolean {
  return value === null || typeof value !== 'object';
}

function jsonEqual(a: unknown, b: unknown): boolean {
  return JSON.stringify(a) === JSON.stringify(b);
}

/**
 * Volatile-field detection (§27): by name pattern or by both values looking
 * like timestamps. Baseline repetition (§101) is handled by the processor
 * comparing repeated baselines; this heuristic covers the common cases.
 */
export function isVolatileField(path: string, valueA: unknown, valueB: unknown): boolean {
  const leaf = path.split('.').pop() ?? path;
  if (VOLATILE_NAME_RE.test(leaf) || VOLATILE_NAME_RE.test(path)) return true;
  const textA = typeof valueA === 'string' ? valueA : String(valueA);
  const textB = typeof valueB === 'string' ? valueB : String(valueB);
  if (/^\d{10}$|^\d{13}$/.test(textA) && /^\d{10}$|^\d{13}$/.test(textB)) {
    const secondsA = Number(textA.length === 13 ? textA.slice(0, 10) : textA);
    const secondsB = Number(textB.length === 13 ? textB.slice(0, 10) : textB);
    if (Math.abs(secondsA - secondsB) <= 3600 * 24) return true; // near-in-time values
  }
  return false;
}

function htmlSignature(html: string): Map<string, number> {
  const counts = new Map<string, number>();
  const tagRe = /<\s*(\/?)([a-zA-Z][a-zA-Z0-9]*)[^>]*>/g;
  let match: RegExpExecArray | null;
  while ((match = tagRe.exec(html)) !== null) {
    const tag = match[2]!.toLowerCase();
    if (['br', 'b', 'i', 'em', 'strong', 'span'].includes(tag)) continue; // presentational noise
    counts.set(tag, (counts.get(tag) ?? 0) + 1);
  }
  // Input names matter for forms (§26 structural, not byte).
  const inputRe = /<input[^>]*name=["']([^"']+)["']/gi;
  while ((match = inputRe.exec(html)) !== null) {
    const key = `input:${match[1]!.toLowerCase()}`;
    counts.set(key, (counts.get(key) ?? 0) + 1);
  }
  return counts;
}

function formSignature(html: string): string {
  const inputs: string[] = [];
  const inputRe = /<input[^>]*name=["']([^"']+)["'][^>]*type=["']([^"']+)["']/gi;
  const inputRe2 = /<input[^>]*type=["']([^"']+)["'][^>]*name=["']([^"']+)["']/gi;
  let match: RegExpExecArray | null;
  while ((match = inputRe.exec(html)) !== null) inputs.push(`${match[1]}:${match[2]!.toLowerCase()}`);
  while ((match = inputRe2.exec(html)) !== null) inputs.push(`${match[2]}:${match[1]!.toLowerCase()}`);
  return [...new Set(inputs)].sort().join(',');
}

function tokenMultiset(text: string): Map<string, number> {
  const counts = new Map<string, number>();
  for (const token of text.toLowerCase().split(/\s+/).slice(0, 20_000)) {
    if (token.length === 0 || token.length > 64) continue;
    counts.set(token, (counts.get(token) ?? 0) + 1);
  }
  return counts;
}

function sumCounts(map: Map<string, number>): number {
  let total = 0;
  for (const count of map.values()) total += count;
  return total;
}

function clamp01(value: number): number {
  return Math.max(0, Math.min(1, value));
}

/** Deterministic fingerprint for deduplicating differential records. */
export function differentialFingerprint(baselineRequestId: string, candidateRequestId: string): string {
  return createHash('sha256')
    .update(`${baselineRequestId}|${candidateRequestId}`)
    .digest('hex')
    .slice(0, 40);
}

/** Map an http_responses DB row into the comparison shape. */
export function responseRowToComparison(row: Record<string, unknown>): ComparisonResponse {
  return {
    status: typeof row.status === 'number' ? row.status : null,
    headers: (row.headers as Array<{ name: string; value: string }>) ?? [],
    contentType: (row.content_type as string | null) ?? null,
    contentKind: (row.content_kind as string) ?? 'UNKNOWN',
    bodyPreview: (row.body_preview as string | null) ?? null,
    bodySha256: (row.body_sha256 as string | null) ?? null,
    contentLength: typeof row.content_length === 'number' ? row.content_length : 0,
    truncated: Boolean(row.truncated),
    timingMs: typeof row.timing_ms === 'number' ? row.timing_ms : 0,
    redirectTo: (row.redirect_to as string | null) ?? null,
  };
}

/** Reflection detection (§65): does the input value appear in the response? */
export function findReflection(
  inputValues: Array<{ name: string; value: string }>,
  response: ComparisonResponse,
): Array<{ name: string; value: string; location: string; excerpt: string }> {
  const reflections: Array<{ name: string; value: string; location: string; excerpt: string }> = [];
  const preview = (response.bodyPreview ?? '').slice(0, MAX_COMPARISON_CHARS);
  if (preview.length === 0) return [];
  for (const { name, value } of inputValues.slice(0, 32)) {
    if (value.length < 3 || value === '«redacted»' || /^[\d.]+$/.test(value)) continue;
    const index = preview.indexOf(value);
    if (index >= 0) {
      const start = Math.max(0, index - 40);
      reflections.push({
        name,
        value,
        location: 'response_body',
        excerpt: preview.slice(start, Math.min(preview.length, index + value.length + 40)).replace(/\s+/g, ' ').slice(0, 200),
      });
      continue;
    }
    // Client/server separation (§66): check whether reflection is DOM-only
    // via redirect Location carrying the value.
    if (response.redirectTo && response.redirectTo.includes(value)) {
      reflections.push({ name, value, location: 'redirect', excerpt: response.redirectTo.slice(0, 200) });
    }
  }
  return reflections.slice(0, 16);
}
