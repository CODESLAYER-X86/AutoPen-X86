/**
 * Structured browser event stream (spec Part 3 §11).
 *
 * Every significant browser action produces STRUCTURED observations, not
 * natural-language descriptions. Events flow: page/context listeners ->
 * in-memory buffer -> durable sink (browser_events table) + event bus.
 *
 * Honesty rule (§11): events the runtime cannot observe passively are
 * emitted from the deterministic action layer (CLICK, INPUT, FORM_SUBMIT,
 * NAVIGATION_STARTED) or from explicit capture passes (COOKIE_CHANGED,
 * STORAGE_CHANGED). Nothing is fabricated.
 */
import { generateId, type BrowserEventType } from '@aegis/shared';

export interface BrowserEventRecord {
  id: string;
  engagement_id: string;
  context_id: string;
  page_id: string | null;
  event_type: BrowserEventType;
  url: string | null;
  payload: Record<string, unknown>;
  occurred_at: string;
}

export interface BrowserEventSink {
  insert(event: BrowserEventRecord): Promise<void>;
  listByContext(contextId: string, limit: number): Promise<Array<Record<string, unknown>>>;
  listByEngagement(engagementId: string, limit: number): Promise<Array<Record<string, unknown>>>;
}

const MAX_EVENTS_PER_CONTEXT = 2000;

export class BrowserEventBuffer {
  private readonly events: BrowserEventRecord[] = [];
  private dropped = 0;

  constructor(
    private readonly engagementId: string,
    private readonly contextId: string,
  ) {}

  emit(
    eventType: BrowserEventType,
    payload: Record<string, unknown>,
    meta: { pageId: string | null; url: string | null },
  ): BrowserEventRecord {
    const event: BrowserEventRecord = {
      id: generateId('BEV'),
      engagement_id: this.engagementId,
      context_id: this.contextId,
      page_id: meta.pageId,
      event_type: eventType,
      url: meta.url,
      payload,
      occurred_at: new Date().toISOString(),
    };
    if (this.events.length >= MAX_EVENTS_PER_CONTEXT) {
      this.dropped += 1;
    } else {
      this.events.push(event);
    }
    return event;
  }

  /** Persist buffered events (called at action boundaries, §75). */
  async flush(sink: BrowserEventSink): Promise<number> {
    if (this.events.length === 0) return 0;
    const batch = this.events.splice(0, this.events.length);
    for (const event of batch) {
      await sink.insert(event);
    }
    return batch.length;
  }

  get size(): number {
    return this.events.length;
  }

  get overflowDropped(): number {
    return this.dropped;
  }
}

/** Convert a Playwright console message type to a bounded payload. */
export function consolePayload(type: string, text: string): Record<string, unknown> {
  return {
    level: type.slice(0, 32),
    text: text.slice(0, 2048),
  };
}
