/**
 * Part 3 repositories — browser interaction records (spec §3-§11, §23-§39).
 */
import type { Pool } from 'pg';
import { generateId, type BrowserContextStatus, type WsMessageDirection } from '@aegis/shared';

// -- Browser contexts (§5) --------------------------------------------------

export class BrowserContextsRepository {
  constructor(readonly pool: Pool) {}

  async insert(input: {
    id: string;
    engagementId: string;
    identityId: string | null;
    status: BrowserContextStatus;
    securityPolicy: Record<string, unknown>;
    createdAt: string;
  }): Promise<Record<string, unknown>> {
    const result = await this.pool.query(
      `INSERT INTO browser_contexts (id, engagement_id, identity_id, status, security_policy, created_at)
       VALUES ($1, $2, $3, $4, $5::jsonb, $6)
       RETURNING id, engagement_id, identity_id, status, security_policy, created_at, closed_at`,
      [input.id, input.engagementId, input.identityId, input.status, JSON.stringify(input.securityPolicy), input.createdAt],
    );
    return result.rows[0] as Record<string, unknown>;
  }

  async updateStatus(id: string, status: BrowserContextStatus): Promise<void> {
    await this.pool.query(
      `UPDATE browser_contexts SET status = $1,
         closed_at = CASE WHEN $1 IN ('CLOSED','FAILED','EXPIRED') THEN now() ELSE closed_at END
       WHERE id = $2`,
      [status, id],
    );
  }

  async findById(id: string): Promise<Record<string, unknown> | null> {
    const result = await this.pool.query(
      'SELECT id, engagement_id, identity_id, status, security_policy, created_at, closed_at FROM browser_contexts WHERE id = $1',
      [id],
    );
    return (result.rows[0] as Record<string, unknown>) ?? null;
  }

  async listByEngagement(engagementId: string): Promise<Record<string, unknown>[]> {
    const result = await this.pool.query(
      'SELECT id, engagement_id, identity_id, status, security_policy, created_at, closed_at FROM browser_contexts WHERE engagement_id = $1 ORDER BY created_at DESC',
      [engagementId],
    );
    return result.rows as Record<string, unknown>[];
  }
}

// -- Browser pages (§3, §74) --------------------------------------------------

export class BrowserPagesRepository {
  constructor(readonly pool: Pool) {}

  async insert(input: { id: string; contextId: string; createdAt: string; closedAt: string | null }): Promise<void> {
    await this.pool.query(
      'INSERT INTO browser_pages (id, context_id, created_at, closed_at) VALUES ($1, $2, $3, $4)',
      [input.id, input.contextId, input.createdAt, input.closedAt],
    );
  }

  async markClosed(id: string): Promise<void> {
    await this.pool.query('UPDATE browser_pages SET closed_at = now() WHERE id = $1', [id]);
  }
}

// -- Browser events (§11) ------------------------------------------------------

export class BrowserEventsRepository {
  constructor(readonly pool: Pool) {}

  async insert(event: {
    id: string;
    engagement_id: string;
    context_id: string;
    page_id: string | null;
    event_type: string;
    url: string | null;
    payload: Record<string, unknown>;
    occurred_at: string;
  }): Promise<void> {
    await this.pool.query(
      `INSERT INTO browser_events (id, engagement_id, context_id, page_id, event_type, url, payload, occurred_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb, $8)`,
      [event.id, event.engagement_id, event.context_id, event.page_id, event.event_type, event.url, JSON.stringify(event.payload), event.occurred_at],
    );
  }

  async listByContext(contextId: string, limit = 200): Promise<Record<string, unknown>[]> {
    const result = await this.pool.query(
      'SELECT id, engagement_id, context_id, page_id, event_type, url, payload, occurred_at FROM browser_events WHERE context_id = $1 ORDER BY occurred_at DESC LIMIT $2',
      [contextId, Math.min(Math.max(limit, 1), 1000)],
    );
    return result.rows as Record<string, unknown>[];
  }

  async listByEngagement(engagementId: string, limit = 500): Promise<Record<string, unknown>[]> {
    const result = await this.pool.query(
      'SELECT id, engagement_id, context_id, page_id, event_type, url, payload, occurred_at FROM browser_events WHERE engagement_id = $1 ORDER BY occurred_at DESC LIMIT $2',
      [engagementId, Math.min(Math.max(limit, 1), 2000)],
    );
    return result.rows as Record<string, unknown>[];
  }
}

// -- Cookies (§23) --------------------------------------------------------------

export class CookiesRepository {
  constructor(readonly pool: Pool) {}

  async upsert(input: {
    id: string;
    engagementId: string;
    contextId: string;
    identityId: string | null;
    name: string;
    domain: string;
    path: string;
    secure: boolean;
    httpOnly: boolean;
    sameSite: string | null;
    expiration: string | null;
    secretReference: string;
  }): Promise<void> {
    await this.pool.query(
      `INSERT INTO cookies (id, engagement_id, context_id, identity_id, name, domain, path, secure, http_only, same_site, expiration, secret_reference)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
       ON CONFLICT (id) DO NOTHING`,
      [
        input.id, input.engagementId, input.contextId, input.identityId, input.name,
        input.domain, input.path, input.secure, input.httpOnly, input.sameSite, input.expiration, input.secretReference,
      ],
    );
  }

  async listByContext(contextId: string): Promise<Record<string, unknown>[]> {
    const result = await this.pool.query(
      'SELECT id, engagement_id, context_id, identity_id, name, domain, path, secure, http_only, same_site, expiration, secret_reference, created_at FROM cookies WHERE context_id = $1 ORDER BY created_at DESC',
      [contextId],
    );
    return result.rows as Record<string, unknown>[];
  }

  async listByEngagement(engagementId: string): Promise<Record<string, unknown>[]> {
    const result = await this.pool.query(
      'SELECT id, engagement_id, context_id, identity_id, name, domain, path, secure, http_only, same_site, expiration, secret_reference, created_at FROM cookies WHERE engagement_id = $1 ORDER BY created_at DESC',
      [engagementId],
    );
    return result.rows as Record<string, unknown>[];
  }
}

// -- Storage entries (§24) --------------------------------------------------------

export class StorageEntriesRepository {
  constructor(readonly pool: Pool) {}

  async upsert(input: {
    id: string;
    engagementId: string;
    contextId: string;
    identityId: string | null;
    origin: string;
    area: 'LOCAL' | 'SESSION';
    key: string;
    valueRedacted: string;
    isSensitive: boolean;
    secretReference: string | null;
  }): Promise<void> {
    await this.pool.query(
      `INSERT INTO storage_entries (id, engagement_id, context_id, identity_id, origin, area, key, value_redacted, is_sensitive, secret_reference)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
       ON CONFLICT (id) DO NOTHING`,
      [
        input.id, input.engagementId, input.contextId, input.identityId, input.origin,
        input.area, input.key, input.valueRedacted, input.isSensitive, input.secretReference,
      ],
    );
  }

  async listByContext(contextId: string): Promise<Record<string, unknown>[]> {
    const result = await this.pool.query(
      'SELECT id, engagement_id, context_id, identity_id, origin, area, key, value_redacted, is_sensitive, secret_reference, created_at FROM storage_entries WHERE context_id = $1',
      [contextId],
    );
    return result.rows as Record<string, unknown>[];
  }
}

// -- DOM snapshots (§32) -------------------------------------------------------------

export class DomSnapshotsRepository {
  constructor(readonly pool: Pool) {}

  async insert(input: {
    id: string;
    engagementId: string;
    contextId: string;
    pageId: string;
    url: string;
    title: string | null;
    snapshot: Record<string, unknown>;
    evidenceId: string;
    createdAt: string;
  }): Promise<void> {
    await this.pool.query(
      `INSERT INTO dom_snapshots (id, engagement_id, context_id, page_id, url, title, snapshot, evidence_id, created_at)
       VALUES ($1,$2,$3,$4,$5,$6,$7::jsonb,$8,$9)`,
      [input.id, input.engagementId, input.contextId, input.pageId, input.url, input.title, JSON.stringify(input.snapshot), input.evidenceId, input.createdAt],
    );
  }

  async listByEngagement(engagementId: string, limit = 100): Promise<Record<string, unknown>[]> {
    const result = await this.pool.query(
      'SELECT id, engagement_id, context_id, page_id, url, title, snapshot, evidence_id, created_at FROM dom_snapshots WHERE engagement_id = $1 ORDER BY created_at DESC LIMIT $2',
      [engagementId, Math.min(Math.max(limit, 1), 500)],
    );
    return result.rows as Record<string, unknown>[];
  }
}

// -- Downloads (§37) -------------------------------------------------------------------

export class DownloadsRepository {
  constructor(readonly pool: Pool) {}

  async insert(input: {
    id: string;
    engagementId: string;
    contextId: string;
    pageId: string | null;
    url: string;
    filename: string;
    contentType: string | null;
    size: number;
    sha256: string;
    evidenceId: string;
  }): Promise<void> {
    await this.pool.query(
      `INSERT INTO downloads (id, engagement_id, context_id, page_id, url, filename, content_type, size, sha256, evidence_id)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
      [input.id, input.engagementId, input.contextId, input.pageId, input.url, input.filename, input.contentType, input.size, input.sha256, input.evidenceId],
    );
  }

  async listByEngagement(engagementId: string): Promise<Record<string, unknown>[]> {
    const result = await this.pool.query(
      'SELECT id, engagement_id, context_id, page_id, url, filename, content_type, size, sha256, evidence_id, created_at FROM downloads WHERE engagement_id = $1 ORDER BY created_at DESC',
      [engagementId],
    );
    return result.rows as Record<string, unknown>[];
  }
}

// -- WebSockets (§36) ---------------------------------------------------------------------

export class WebSocketsRepository {
  constructor(readonly pool: Pool) {}

  async insertConnection(input: {
    id: string;
    engagementId: string;
    contextId: string;
    pageId: string | null;
    url: string;
    origin: string | null;
    openedAt: string;
    closedAt: string | null;
    closeCode: number | null;
  }): Promise<void> {
    await this.pool.query(
      `INSERT INTO websocket_connections (id, engagement_id, context_id, page_id, url, origin, opened_at, closed_at, close_code)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
       ON CONFLICT (id) DO NOTHING`,
      [input.id, input.engagementId, input.contextId, input.pageId, input.url, input.origin, input.openedAt, input.closedAt, input.closeCode],
    );
  }

  async insertMessage(input: {
    id: string;
    connectionId: string;
    direction: WsMessageDirection;
    isBinary: boolean;
    payloadArtifactRef: string | null;
    payloadPreview: string | null;
    byteSize: number;
    truncated: boolean;
  }): Promise<void> {
    await this.pool.query(
      `INSERT INTO websocket_messages (id, connection_id, direction, is_binary, payload_artifact_ref, payload_preview, byte_size, truncated)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
      [input.id, input.connectionId, input.direction, input.isBinary, input.payloadArtifactRef, input.payloadPreview, input.byteSize, input.truncated],
    );
  }

  async listConnections(engagementId: string): Promise<Record<string, unknown>[]> {
    const result = await this.pool.query(
      'SELECT id, engagement_id, context_id, page_id, url, origin, opened_at, closed_at, close_code FROM websocket_connections WHERE engagement_id = $1 ORDER BY opened_at DESC',
      [engagementId],
    );
    return result.rows as Record<string, unknown>[];
  }

  async listMessages(connectionId: string, limit = 200): Promise<Record<string, unknown>[]> {
    const result = await this.pool.query(
      'SELECT id, connection_id, direction, is_binary, payload_artifact_ref, payload_preview, byte_size, truncated, created_at FROM websocket_messages WHERE connection_id = $1 ORDER BY created_at ASC LIMIT $2',
      [connectionId, Math.min(Math.max(limit, 1), 1000)],
    );
    return result.rows as Record<string, unknown>[];
  }
}

// -- Tool executions (§44-§45, §78) ----------------------------------------------------------

export class ToolExecutionsRepository {
  constructor(readonly pool: Pool) {}

  async insert(input: {
    id: string;
    engagementId: string;
    taskId: string | null;
    identityId: string | null;
    toolName: string;
    toolVersion: string;
    configurationVersion: string;
    correlationId: string | null;
    status: 'SUCCEEDED' | 'FAILED';
    inputRedacted: unknown;
    outputSummary: unknown;
    error: unknown;
    durationMs: number;
    deadlineMs: number;
  }): Promise<Record<string, unknown>> {
    const id = input.id || generateId('TEX');
    const result = await this.pool.query(
      `INSERT INTO tool_executions (id, engagement_id, task_id, identity_id, tool_name, tool_version, configuration_version, correlation_id, status, input_redacted, output_summary, error, duration_ms, deadline_ms)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10::jsonb,$11::jsonb,$12::jsonb,$13,$14)
       RETURNING id, engagement_id, task_id, identity_id, tool_name, tool_version, configuration_version, correlation_id, status, input_redacted, output_summary, error, duration_ms, deadline_ms, created_at`,
      [
        id, input.engagementId, input.taskId, input.identityId, input.toolName, input.toolVersion,
        input.configurationVersion, input.correlationId, input.status,
        JSON.stringify(input.inputRedacted ?? null), JSON.stringify(input.outputSummary ?? null),
        JSON.stringify(input.error ?? null), input.durationMs, input.deadlineMs,
      ],
    );
    return result.rows[0] as Record<string, unknown>;
  }

  async listByEngagement(engagementId: string, limit = 200): Promise<Record<string, unknown>[]> {
    const result = await this.pool.query(
      'SELECT id, engagement_id, task_id, identity_id, tool_name, tool_version, configuration_version, correlation_id, status, input_redacted, output_summary, error, duration_ms, deadline_ms, created_at FROM tool_executions WHERE engagement_id = $1 ORDER BY created_at DESC LIMIT $2',
      [engagementId, Math.min(Math.max(limit, 1), 1000)],
    );
    return result.rows as Record<string, unknown>[];
  }
}

// -- Authentication workflows (§28) --------------------------------------------------------------

export class AuthWorkflowsRepository {
  constructor(readonly pool: Pool) {}

  async insert(input: {
    id: string;
    engagementId: string;
    identityId: string;
    steps: Array<{ action: string; detail: string; success: boolean }>;
    sessionId: string | null;
    evidenceIds: string[];
  }): Promise<{ id: string; created_at: Date }> {
    const id = input.id || generateId('AWF');
    const result = await this.pool.query(
      `INSERT INTO auth_workflows (id, engagement_id, identity_id, steps, session_id, evidence_ids)
       VALUES ($1,$2,$3,$4::jsonb,$5,$6::jsonb)
       RETURNING id, created_at`,
      [id, input.engagementId, input.identityId, JSON.stringify(input.steps), input.sessionId, JSON.stringify(input.evidenceIds)],
    );
    return result.rows[0] as { id: string; created_at: Date };
  }

  async listByEngagement(engagementId: string): Promise<Record<string, unknown>[]> {
    const result = await this.pool.query(
      'SELECT id, engagement_id, identity_id, steps, session_id, evidence_ids, created_at FROM auth_workflows WHERE engagement_id = $1 ORDER BY created_at DESC',
      [engagementId],
    );
    return result.rows as Record<string, unknown>[];
  }
}
