/**
 * Part 3 repositories — HTTP traffic records (spec §16-§18).
 *
 * The insert surface mirrors the traffic-recorder contract (camelCase);
 * returned rows are snake_case DB rows mapped by the recorder layer.
 * Rows store the REDACTED normalized representation; raw bundles are
 * sealed in the evidence store.
 */
import type { Pool } from 'pg';

/** Local structural type (keeps packages independent of services). */
export interface PlainHeader {
  name: string;
  value: string;
}

export interface InsertHttpRequestInput {
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
  bodyType: string | null;
  bodyParsed: unknown;
  bodyArtifactRef: string | null;
  bodySha256: string | null;
  bodyBytes: number;
  source: string;
  provenanceSource: string;
  provenanceParentTaskId: string | null;
  provenanceHypothesisId: string | null;
  provenanceTestId: string | null;
  provenanceReason: string | null;
  parentRequestId: string | null;
  browserContextId: string | null;
  browserPageId: string | null;
  correlationId: string | null;
}

const HTTP_REQUEST_COLUMNS = `id, engagement_id, task_id, identity_id, method, url, normalized_url,
  normalized_fingerprint, headers, query, body_type, body_parsed, body_artifact_ref, body_sha256,
  body_bytes, source, provenance_source, provenance_parent_task_id, provenance_hypothesis_id,
  provenance_test_id, provenance_reason, parent_request_id, browser_context_id, browser_page_id,
  correlation_id, created_at`;

export class HttpRequestsRepository {
  constructor(readonly pool: Pool) {}

  async insert(input: InsertHttpRequestInput): Promise<Record<string, unknown>> {
    const result = await this.pool.query(
      `INSERT INTO http_requests (
         id, engagement_id, task_id, identity_id, method, url, normalized_url, normalized_fingerprint,
         headers, query, body_type, body_parsed, body_artifact_ref, body_sha256, body_bytes, source,
         provenance_source, provenance_parent_task_id, provenance_hypothesis_id, provenance_test_id,
         provenance_reason, parent_request_id, browser_context_id, browser_page_id, correlation_id, created_at
       ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9::jsonb,$10::jsonb,$11,$12::jsonb,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25,now())
       RETURNING ${HTTP_REQUEST_COLUMNS}`,
      [
        input.id,
        input.engagementId,
        input.taskId,
        input.identityId,
        input.method,
        input.url,
        input.normalizedUrl,
        input.normalizedFingerprint,
        JSON.stringify(input.headers ?? []),
        JSON.stringify(input.query ?? []),
        input.bodyType,
        JSON.stringify(input.bodyParsed ?? null),
        input.bodyArtifactRef,
        input.bodySha256,
        input.bodyBytes,
        input.source,
        input.provenanceSource,
        input.provenanceParentTaskId,
        input.provenanceHypothesisId,
        input.provenanceTestId,
        input.provenanceReason,
        input.parentRequestId,
        input.browserContextId,
        input.browserPageId,
        input.correlationId,
      ],
    );
    return result.rows[0] as Record<string, unknown>;
  }

  async findById(id: string): Promise<Record<string, unknown> | null> {
    const result = await this.pool.query(
      `SELECT ${HTTP_REQUEST_COLUMNS} FROM http_requests WHERE id = $1`,
      [id],
    );
    return (result.rows[0] as Record<string, unknown>) ?? null;
  }

  async listByEngagement(engagementId: string, limit = 100, offset = 0): Promise<Record<string, unknown>[]> {
    const result = await this.pool.query(
      `SELECT ${HTTP_REQUEST_COLUMNS} FROM http_requests
       WHERE engagement_id = $1 ORDER BY created_at DESC LIMIT $2 OFFSET $3`,
      [engagementId, Math.min(Math.max(limit, 1), 500), Math.max(offset, 0)],
    );
    return result.rows as Record<string, unknown>[];
  }

  async countByEngagement(engagementId: string): Promise<number> {
    const result = await this.pool.query<{ n: number }>(
      'SELECT count(*)::int AS n FROM http_requests WHERE engagement_id = $1',
      [engagementId],
    );
    return result.rows[0]!.n;
  }
}

export interface InsertHttpResponseInput {
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
}

export class HttpResponsesRepository {
  constructor(readonly pool: Pool) {}

  async insert(input: InsertHttpResponseInput): Promise<Record<string, unknown>> {
    const result = await this.pool.query(
      `INSERT INTO http_responses (
         id, request_id, engagement_id, status, headers, content_type, content_kind,
         body_artifact_ref, body_sha256, body_preview, content_length, truncated, timing_ms, redirect_to
       ) VALUES ($1,$2,$3,$4,$5::jsonb,$6,$7,$8,$9,$10,$11,$12,$13,$14)
       RETURNING id, request_id, engagement_id, status, headers, content_type, content_kind,
                 body_artifact_ref, body_sha256, body_preview, content_length, truncated, timing_ms, redirect_to, created_at`,
      [
        input.id,
        input.requestId,
        input.engagementId,
        input.status,
        JSON.stringify(input.headers ?? []),
        input.contentType,
        input.contentKind,
        input.bodyArtifactRef,
        input.bodySha256,
        input.bodyPreview,
        input.contentLength,
        input.truncated,
        input.timingMs,
        input.redirectTo,
      ],
    );
    return result.rows[0] as Record<string, unknown>;
  }

  async findByRequestId(requestId: string): Promise<Record<string, unknown> | null> {
    const result = await this.pool.query(
      `SELECT id, request_id, engagement_id, status, headers, content_type, content_kind,
              body_artifact_ref, body_sha256, body_preview, content_length, truncated, timing_ms, redirect_to, created_at
       FROM http_responses WHERE request_id = $1 ORDER BY created_at DESC LIMIT 1`,
      [requestId],
    );
    return (result.rows[0] as Record<string, unknown>) ?? null;
  }

  async listByEngagement(engagementId: string, limit = 100): Promise<Record<string, unknown>[]> {
    const result = await this.pool.query(
      `SELECT r.id, r.request_id, r.engagement_id, r.status, r.headers, r.content_type, r.content_kind,
              r.body_artifact_ref, r.body_sha256, r.body_preview, r.content_length, r.truncated, r.timing_ms, r.redirect_to, r.created_at
       FROM http_responses r WHERE r.engagement_id = $1 ORDER BY r.created_at DESC LIMIT $2`,
      [engagementId, Math.min(Math.max(limit, 1), 500)],
    );
    return result.rows as Record<string, unknown>[];
  }

  /**
   * Part 8 §59: retention sweep for stored HTTP responses (bodies live in
   * object storage; row deletion is the index of record).
   */
  async deleteOlderThan(days: number, limit: number): Promise<number> {
    const result = await this.pool.query(
      `DELETE FROM http_responses WHERE id IN (
         SELECT id FROM http_responses WHERE created_at < now() - ($1 || ' days')::interval LIMIT $2
       )`,
      [String(days), Math.min(Math.max(limit, 1), 5000)],
    );
    return result.rowCount ?? 0;
  }
}
