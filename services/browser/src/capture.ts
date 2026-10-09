/**
 * Downloads (§37) + WebSocket observation (§36) + screenshots (§38) + traces (§39).
 *
 * Downloaded content is UNTRUSTED: stored as evidence with sha256, never
 * executed. WebSocket frames are captured as structured records with
 * direction and size; binary/large payloads go to artifact storage.
 */
import type { Download, WebSocket } from 'playwright-core';
import { createHash } from 'node:crypto';
import { generateId, type WsMessageDirection } from '@aegis/shared';

export interface DownloadRepositorySurface {
  insert(input: {
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
  }): Promise<void>;
  listByEngagement(engagementId: string): Promise<Array<Record<string, unknown>>>;
}

export interface EvidenceSurface {
  store(input: {
    engagement_id: string;
    type: string;
    source: string;
    content: Uint8Array | string;
    task_id?: string | null;
    metadata?: Record<string, unknown>;
  }): Promise<{ id: string; sha256: string; content_reference?: string }>;
}

export interface DownloadCaptureLimits {
  maxBytes: number;
}

export interface CapturedDownload {
  id: string;
  url: string;
  filename: string;
  size: number;
  sha256: string;
  evidenceId: string;
  truncated: boolean;
}

export async function captureDownload(
  download: Download,
  input: {
    engagementId: string;
    contextId: string;
    pageId: string | null;
    repository: DownloadRepositorySurface;
    evidence: EvidenceSurface;
    limits: DownloadCaptureLimits;
  },
): Promise<CapturedDownload> {
  const url = download.url();
  const filename = (download.suggestedFilename() || 'download').slice(0, 512);

  let bytes = new Uint8Array(0);
  let truncated = false;
  try {
    const path = await download.path();
    if (path) {
      const { readFile } = await import('node:fs/promises');
      const raw = new Uint8Array(await readFile(path));
      if (raw.byteLength > input.limits.maxBytes) {
        bytes = raw.slice(0, input.limits.maxBytes);
        truncated = true;
      } else {
        bytes = raw;
      }
    }
  } catch {
    // Download failed mid-flight — record the event with zero bytes.
  }

  const sha256 = createHash('sha256').update(bytes).digest('hex');
  const evidence = await input.evidence.store({
    engagement_id: input.engagementId,
    type: 'RAW',
    source: 'browser-download',
    content: bytes,
    metadata: { classification: 'RAW', url, filename, truncated, untrusted: true },
  });

  const id = generateId('DLD');
  await input.repository.insert({
    id,
    engagementId: input.engagementId,
    contextId: input.contextId,
    pageId: input.pageId,
    url,
    filename,
    contentType: null,
    size: bytes.byteLength,
    sha256,
    evidenceId: evidence.id,
  });

  return { id, url, filename, size: bytes.byteLength, sha256, evidenceId: evidence.id, truncated };
}

// ---------------------------------------------------------------------------
// WebSockets (§36)
// ---------------------------------------------------------------------------

export interface WebSocketRepositorySurface {
  insertConnection(input: {
    id: string;
    engagementId: string;
    contextId: string;
    pageId: string | null;
    url: string;
    origin: string | null;
    openedAt: string;
    closedAt: string | null;
    closeCode: number | null;
  }): Promise<void>;
  insertMessage(input: {
    id: string;
    connectionId: string;
    direction: WsMessageDirection;
    isBinary: boolean;
    payloadArtifactRef: string | null;
    payloadPreview: string | null;
    byteSize: number;
    truncated: boolean;
  }): Promise<void>;
  listConnections(engagementId: string): Promise<Array<Record<string, unknown>>>;
  listMessages(connectionId: string, limit: number): Promise<Array<Record<string, unknown>>>;
}

export interface WsCaptureLimits {
  maxMessageBytes: number;
}

export interface WsMessageRecord {
  direction: WsMessageDirection;
  isBinary: boolean;
  payload: string;
  byteSize: number;
}

/**
 * WebSocket observation: attach listeners for one WS connection. Messages
 * are buffered and flushed via `drain()`.
 */
export class WebSocketObserver {
  private readonly messages: WsMessageRecord[] = [];
  private closedAt: string | null = null;
  private closeCode: number | null = null;

  constructor(
    public readonly id: string,
    public readonly url: string,
    public readonly origin: string | null,
    private readonly limits: WsCaptureLimits,
    private readonly onMessage: (record: WsMessageRecord) => void,
  ) {}

  attach(ws: WebSocket): void {
    ws.on('framesent', (frame) => {
      this.record('CLIENT_TO_SERVER', frame.payload);
    });
    ws.on('framereceived', (frame) => {
      this.record('SERVER_TO_CLIENT', frame.payload);
    });
    ws.on('close', () => {
      this.closedAt = new Date().toISOString();
    });
  }

  get connectionClosed(): boolean {
    return this.closedAt !== null;
  }

  private record(direction: WsMessageDirection, payload: unknown): void {
    let text: string;
    let isBinary = false;
    let byteSize: number;
    if (typeof payload === 'string') {
      text = payload;
      byteSize = Buffer.byteLength(payload, 'utf8');
    } else {
      isBinary = true;
      const buf = Buffer.isBuffer(payload) ? payload : Buffer.from(String(payload));
      byteSize = buf.byteLength;
      text = buf.toString('base64');
    }
    const truncated = byteSize > this.limits.maxMessageBytes;
    if (truncated) {
      text = text.slice(0, this.limits.maxMessageBytes);
    }
    const record: WsMessageRecord = { direction, isBinary, payload: text, byteSize };
    this.messages.push(record);
    this.onMessage(record);
  }

  drain(
    persist: (message: WsMessageRecord) => Promise<void>,
  ): Promise<void> {
    const batch = this.messages.splice(0, this.messages.length);
    let chain = Promise.resolve();
    for (const message of batch) {
      chain = chain.then(() => persist(message));
    }
    return chain;
  }

  get messageCount(): number {
    return this.messages.length;
  }

  get closeInfo(): { closedAt: string | null; closeCode: number | null } {
    return { closedAt: this.closedAt, closeCode: this.closeCode };
  }
}

export function createWebSocketObserver(
  ws: WebSocket,
  limits: WsCaptureLimits,
  onMessage: (record: WsMessageRecord) => void,
): WebSocketObserver {
  const url = ws.url();
  let origin: string | null = null;
  try {
    origin = new URL(url).origin;
  } catch {
    origin = null;
  }
  const observer = new WebSocketObserver(generateId('WSC'), url, origin, limits, onMessage);
  observer.attach(ws);
  return observer;
}
