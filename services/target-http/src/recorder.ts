/**
 * Traffic recorder (spec Part 3 §12-§14, §16-§17, §57, §58, §66).
 *
 * Persists every significant HTTP exchange (engine-driven OR browser-
 * captured) into the shared normalized request/response records and the
 * evidence store:
 *
 *  - the DATABASE row carries the REDACTED, structured representation
 *    (parsed body, non-sensitive headers, metadata) — no credential
 *    material lands in SQL (§66);
 *  - the RAW request/response bundle (including sensitive headers) is
 *    sealed in the immutable, hash-verified evidence store (§57 RAW /
 *    NETWORK classification);
 *  - bodies beyond the inline limit live in the artifact store and are
 *    referenced, never inlined (§12, §64).
 *
 * Browser traffic is promoted into the SAME records (§14) so the HTTP
 * worker can replay/mutate captured requests.
 */
import type { HttpExchange } from './engine.js';
import { HttpRequestRecordSchema, HttpResponseRecordSchema, type HttpRequestRecord, type HttpResponseRecord, type HttpBodyInput } from '@aegis/contracts';
import { generateId, type HttpBodyType, type HttpRequestSource, type HttpProvenanceSource } from '@aegis/shared';
import {
  buildNormalizedParts,
  fingerprintNormalized,
  parseQuery,
  redactHeaders,
  redactParsedBody,
  redactFormFields,
  classifyContent,
  type PlainHeader,
} from './normalize.js';
import { serializeBody } from './body.js';

/** Inline body limit: larger bodies go to artifact storage (§12). */
export const INLINE_BODY_LIMIT = 8_192;

export interface HttpTrafficRepositorySurface {
  insertRequest(input: {
    id: string;
    engagementId: string;
    taskId: string | null;
    identityId: string | null;
    method: string;
    url: string;
    normalizedUrl: string;
    normalizedFingerprint: string;
    headers: PlainHeader[];
    query: PlainHeader[];
    bodyType: HttpBodyType | null;
    bodyParsed: unknown;
    bodyArtifactRef: string | null;
    bodySha256: string | null;
    bodyBytes: number;
    source: HttpRequestSource;
    provenanceSource: HttpProvenanceSource;
    provenanceParentTaskId: string | null;
    provenanceHypothesisId: string | null;
    provenanceTestId: string | null;
    provenanceReason: string | null;
    parentRequestId: string | null;
    browserContextId: string | null;
    browserPageId: string | null;
    correlationId: string | null;
  }): Promise<Record<string, unknown>>;
  insertResponse(input: {
    id: string;
    requestId: string;
    engagementId: string;
    status: number;
    headers: PlainHeader[];
    contentType: string | null;
    contentKind: string;
    bodyArtifactRef: string | null;
    bodySha256: string | null;
    bodyPreview: string | null;
    contentLength: number;
    truncated: boolean;
    timingMs: number;
    redirectTo: string | null;
  }): Promise<Record<string, unknown>>;
  findRequestById(id: string): Promise<Record<string, unknown> | null>;
  listRequestsByEngagement(engagementId: string, limit: number, offset: number): Promise<Record<string, unknown>[]>;
  countRequestsByEngagement(engagementId: string): Promise<number>;
}

export interface EvidenceServiceSurface {
  store(input: {
    engagement_id: string;
    type: string;
    source: string;
    content: Uint8Array | string;
    task_id?: string | null;
    metadata?: Record<string, unknown>;
  }): Promise<{ id: string; sha256: string; content_reference?: string }>;
}

export interface EventBusSurface {
  publish(event: import('@aegis/contracts').PlatformEvent): Promise<void>;
}

export interface RecordExchangeInput {
  engagementId: string;
  taskId: string | null;
  identityId: string | null;
  exchange: HttpExchange;
  source: HttpRequestSource;
  provenance: {
    source: HttpProvenanceSource;
    parentTaskId: string | null;
    hypothesisId: string | null;
    testId: string | null;
    reason: string | null;
  };
  parentRequestId: string | null;
  browserContextId: string | null;
  browserPageId: string | null;
  correlationId: string | null;
  /** Pre-assigned request id (browser correlation, §13). */
  requestId?: string;
}

export interface RecordedExchange {
  request: HttpRequestRecord;
  response: HttpResponseRecord | null;
  evidenceId: string;
}

const generateRequest = (): string => generateId('REQ');
const generateResponse = (): string => generateId('RSP');

export class HttpTrafficRecorder {
  constructor(
    private readonly deps: {
      repository: HttpTrafficRepositorySurface;
      evidence: EvidenceServiceSurface;
      eventBus: EventBusSurface;
    },
  ) {}

  /**
   * Persist one exchange (request + response + raw evidence bundle).
   * Returns the contract-shaped records for API/tool consumption.
   */
  async recordExchange(input: RecordExchangeInput): Promise<RecordedExchange> {
    const { exchange } = input;
    const requestId = input.requestId ?? generateRequest();
    const responseId = generateResponse();

    // --- Request record ---------------------------------------------------
    const bodyInput = exchange.request.body
      ? engineBodyToContractBody(exchange.request.body)
      : null;
    const storageBodyKind = bodyInput ? bodyInput.body_type : null;

    const normalizedParts = buildNormalizedParts({
      method: exchange.request.method,
      url: exchange.request.url,
      headers: exchange.request.headers,
      bodyCanonical: exchange.request.body
        ? canonicalBody(exchange.request.body.parsed)
        : null,
    });
    const fingerprint = fingerprintNormalized(normalizedParts);

    // Raw bundle → evidence (RAW classification, immutable).
    const rawBundle = JSON.stringify(
      {
        kind: 'http-exchange-raw',
        request: {
          method: exchange.request.method,
          url: exchange.request.url,
          headers: exchange.request.sentHeaders,
          body_b64: exchange.request.body ? Buffer.from(exchange.request.body.bytes).toString('base64') : null,
        },
        response: {
          status: exchange.response.status,
          headers: exchange.response.headers,
          body_b64: exchange.redirects.length > 0 || exchange.response.bodyBytes.byteLength > 0
            ? Buffer.from(exchange.response.bodyBytes).toString('base64')
            : null,
        },
        redirects: exchange.redirects,
      },
      null,
      0,
    );
    const evidence = await this.deps.evidence.store({
      engagement_id: input.engagementId,
      type: 'NETWORK',
      source: input.source === 'BROWSER' ? 'browser-capture' : 'http-engine',
      content: rawBundle,
      task_id: input.taskId,
      metadata: {
        classification: 'RAW',
        request_id: requestId,
        response_id: responseId,
        url: exchange.request.url,
        method: exchange.request.method,
        status: exchange.response.status,
        timing_ms: exchange.response.timingMs,
      },
    });

    // Large request bodies → artifact evidence; inline otherwise.
    let bodyArtifactRef: string | null = null;
    const bodySha256: string | null = exchange.request.body?.sha256 ?? null;
    let bodyParsed: unknown = exchange.request.body?.parsed ?? null;
    if (exchange.request.body && exchange.request.body.byteLength > INLINE_BODY_LIMIT) {
      const bodyEvidence = await this.deps.evidence.store({
        engagement_id: input.engagementId,
        type: 'NETWORK',
        source: 'request-body',
        content: Buffer.from(exchange.request.body.bytes),
        task_id: input.taskId,
        metadata: { classification: 'RAW', request_id: requestId },
      });
      bodyArtifactRef = bodyEvidence.id;
      bodyParsed = summarizeParsed(exchange.request.body.parsed);
    }

    // Redact credential material from the SQL representation (§66).
    const redactedHeaders = redactHeaders(exchange.request.headers);
    const redactedQuery = parseQuery(exchange.request.url).map((q) => ({ name: q.name, value: q.value }));

    const requestRow = await this.deps.repository.insertRequest({
      id: requestId,
      engagementId: input.engagementId,
      taskId: input.taskId,
      identityId: input.identityId,
      method: normalizedParts.method,
      url: exchange.request.url,
      normalizedUrl: normalizedParts.url,
      normalizedFingerprint: fingerprint,
      headers: redactedHeaders,
      query: redactedQuery,
      bodyType: storageBodyKind,
      bodyParsed: redactParsedForStorage(bodyParsed),
      bodyArtifactRef,
      bodySha256,
      bodyBytes: exchange.request.body?.byteLength ?? 0,
      source: input.source,
      provenanceSource: input.provenance.source,
      provenanceParentTaskId: input.provenance.parentTaskId,
      provenanceHypothesisId: input.provenance.hypothesisId,
      provenanceTestId: input.provenance.testId,
      provenanceReason: input.provenance.reason,
      parentRequestId: input.parentRequestId,
      browserContextId: input.browserContextId,
      browserPageId: input.browserPageId,
      correlationId: input.correlationId,
    });

    // --- Response record --------------------------------------------------
    let response: HttpResponseRecord | null = null;
    let bodyEvidenceRef: string | null = null;
    let bodySha = null as string | null;
    if (exchange.response.bodyBytes.byteLength > 0) {
      const sha = await sha256Hex(exchange.response.bodyBytes);
      bodySha = sha;
      if (exchange.response.bodyBytes.byteLength > INLINE_BODY_LIMIT) {
        const respBodyEvidence = await this.deps.evidence.store({
          engagement_id: input.engagementId,
          type: 'NETWORK',
          source: 'response-body',
          content: Buffer.from(exchange.response.bodyBytes),
          task_id: input.taskId,
          metadata: { classification: 'RAW', request_id: requestId, content_type: exchange.response.contentType },
        });
        bodyEvidenceRef = respBodyEvidence.id;
      }
    }

    if (!isHead(exchange.request.method)) {
      const responseRow = await this.deps.repository.insertResponse({
        id: responseId,
        requestId,
        engagementId: input.engagementId,
        status: exchange.response.status,
        headers: redactHeaders(exchange.response.headers),
        contentType: exchange.response.contentType,
        contentKind: classifyContent(exchange.response.contentType),
        bodyArtifactRef: bodyEvidenceRef,
        bodySha256: bodySha,
        bodyPreview: exchange.response.parsed.textPreview,
        contentLength: exchange.response.bodyBytes.byteLength,
        truncated: exchange.response.truncated,
        timingMs: exchange.response.timingMs,
        redirectTo: exchange.response.redirectTo,
      });
      response = mapResponseRow(responseRow);
    }

    // --- Events (§58 observation interface) ---------------------------------
    await this.deps.eventBus.publish({
      type: 'HTTP_REQUEST_RECORDED',
      engagement_id: input.engagementId,
      task_id: input.taskId,
      trace_id: input.correlationId ?? requestId,
      actor_id: null,
      payload: {
        request_id: requestId,
        method: normalizedParts.method,
        url: normalizedParts.url,
        source: input.source,
        provenance: input.provenance.source,
      },
      occurred_at: new Date().toISOString(),
      dedup_key: `http-request-recorded:${requestId}`,
    });
    if (response) {
      await this.deps.eventBus.publish({
        type: 'HTTP_RESPONSE_RECORDED',
        engagement_id: input.engagementId,
        task_id: input.taskId,
        trace_id: input.correlationId ?? requestId,
        actor_id: null,
        payload: {
          request_id: requestId,
          response_id: responseId,
          status: response.status,
          content_kind: response.content_kind,
          length: response.content_length,
          truncated: response.truncated,
        },
        occurred_at: new Date().toISOString(),
        dedup_key: `http-response-recorded:${responseId}`,
      });
    }

    const requestRecord = mapRequestRow(requestRow);
    return { request: requestRecord, response, evidenceId: evidence.id };
  }
}

// ---------------------------------------------------------------------------
// Mappers (DB row -> contract record)
// ---------------------------------------------------------------------------

export function mapRequestRow(row: Record<string, unknown>): HttpRequestRecord {
  const record = {
    id: row.id as string,
    engagement_id: row.engagement_id as string,
    task_id: (row.task_id as string | null) ?? null,
    identity_id: (row.identity_id as string | null) ?? null,
    method: row.method as string,
    url: row.url as string,
    normalized_url: row.normalized_url as string,
    headers: (row.headers ?? []) as PlainHeader[],
    query: (row.query ?? []) as PlainHeader[],
    body: (row.body_parsed !== null && row.body_parsed !== undefined
      ? {
          body_type: row.body_type as string,
          parsed: row.body_parsed,
          artifact_ref: (row.body_artifact_ref as string | null) ?? null,
          sha256: (row.body_sha256 as string | null) ?? null,
          byte_length: (row.body_bytes as number) ?? 0,
        }
      : null),
    source: row.source as string,
    provenance: {
      source: row.provenance_source as string,
      parent_task_id: (row.provenance_parent_task_id as string | null) ?? null,
      hypothesis_id: (row.provenance_hypothesis_id as string | null) ?? null,
      test_id: (row.provenance_test_id as string | null) ?? null,
      ...(row.provenance_reason ? { reason: row.provenance_reason as string } : {}),
    },
    parent_request_id: (row.parent_request_id as string | null) ?? null,
    browser_context_id: (row.browser_context_id as string | null) ?? null,
    browser_page_id: (row.browser_page_id as string | null) ?? null,
    correlation_id: (row.correlation_id as string | null) ?? null,
    created_at: (row.created_at as Date).toISOString(),
  };
  const parsed = HttpRequestRecordSchema.safeParse(record);
  if (!parsed.success) {
    throw new Error(`Recorded request row failed its contract: ${parsed.error.issues[0]?.message}`);
  }
  return parsed.data;
}

export function mapResponseRow(row: Record<string, unknown>): HttpResponseRecord {
  const record = {
    id: row.id as string,
    request_id: row.request_id as string,
    status: row.status as number,
    headers: (row.headers ?? []) as PlainHeader[],
    content_type: (row.content_type as string | null) ?? null,
    content_kind: (row.content_kind as string) ?? 'UNKNOWN',
    body_artifact_ref: (row.body_artifact_ref as string | null) ?? null,
    body_sha256: (row.body_sha256 as string | null) ?? null,
    content_length: (row.content_length as number) ?? 0,
    truncated: (row.truncated as boolean) ?? false,
    timing_ms: (row.timing_ms as number) ?? 0,
    redirect_to: (row.redirect_to as string | null) ?? null,
    created_at: (row.created_at as Date).toISOString(),
  };
  const parsed = HttpResponseRecordSchema.safeParse(record);
  if (!parsed.success) {
    throw new Error(`Recorded response row failed its contract: ${parsed.error.issues[0]?.message}`);
  }
  return parsed.data;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function engineBodyToContractBody(body: HttpExchange['request']['body'] & object): HttpBodyInput {
  if (body.contentType?.includes('application/json')) return { body_type: 'JSON', data: body.parsed };
  if (body.contentType?.includes('application/x-www-form-urlencoded')) {
    return {
      body_type: 'FORM_URLENCODED',
      fields: Array.isArray(body.parsed) ? (body.parsed as Array<{ name: string; value: string }>) : [],
    };
  }
  if (body.contentType?.includes('text/')) {
    return { body_type: 'TEXT', text: new TextDecoder().decode(body.bytes) };
  }
  return { body_type: 'BINARY', content_b64: Buffer.from(body.bytes).toString('base64') };
}

function canonicalBody(parsed: unknown): string | null {
  if (parsed === null || parsed === undefined) return null;
  try {
    return JSON.stringify(parsed);
  } catch {
    return null;
  }
}

function summarizeParsed(parsed: unknown): unknown {
  if (parsed === null || parsed === undefined) return null;
  if (typeof parsed === 'string') {
    return { summary: `text body, ${parsed.length} chars`, preview: parsed.slice(0, 256) };
  }
  if (typeof parsed === 'object') {
    const keys = Array.isArray(parsed) ? { entries: parsed.length } : { fields: Object.keys(parsed).length };
    return { summary: `structured body`, counts: keys };
  }
  return parsed;
}

function redactParsedForStorage(parsed: unknown): unknown {
  if (Array.isArray(parsed) && parsed.every((p) => p && typeof p === 'object' && 'name' in p && 'value' in p)) {
    return redactFormFields(parsed as PlainHeader[]);
  }
  return redactParsedBody(parsed);
}

function isHead(method: string): boolean {
  return method.toUpperCase() === 'HEAD';
}

async function sha256Hex(bytes: Uint8Array): Promise<string> {
  const { createHash } = await import('node:crypto');
  return createHash('sha256').update(bytes).digest('hex');
}

export { serializeBody };
