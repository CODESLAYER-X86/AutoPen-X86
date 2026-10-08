/**
 * Event bus abstraction (spec §14).
 *
 * `InMemoryEventBus` provides synchronous fan-out with error isolation.
 * `PersistingEventBus` composes persistence (database event log) with
 * fan-out. The persistence function is injected so this package stays
 * independent of the database package.
 */
import type { PlatformEvent } from '@aegis/contracts';

export type EventHandler = (event: PlatformEvent) => void | Promise<void>;

export interface EventBus {
  publish(event: PlatformEvent): Promise<void>;
  subscribe(handler: EventHandler): () => void;
}

export class InMemoryEventBus implements EventBus {
  private readonly handlers = new Set<EventHandler>();

  subscribe(handler: EventHandler): () => void {
    this.handlers.add(handler);
    return () => this.handlers.delete(handler);
  }

  async publish(event: PlatformEvent): Promise<void> {
    for (const handler of this.handlers) {
      try {
        await handler(event);
      } catch {
        // A faulty subscriber must never break the publisher.
      }
    }
  }
}

export type PersistFn = (event: PlatformEvent) => Promise<unknown>;

/**
 * Persists the event first (the event log is the durable record), then
 * fans out to subscribers. Persistence failures propagate to the caller —
 * losing events silently is worse than failing the operation.
 */
export class PersistingEventBus implements EventBus {
  private readonly inner: EventBus;
  private readonly persist: PersistFn;

  constructor(inner: EventBus, persist: PersistFn) {
    this.inner = inner;
    this.persist = persist;
  }

  subscribe(handler: EventHandler): () => void {
    return this.inner.subscribe(handler);
  }

  async publish(event: PlatformEvent): Promise<void> {
    await this.persist(event);
    await this.inner.publish(event);
  }
}

export function createEventBus(persist?: PersistFn): EventBus {
  const inner = new InMemoryEventBus();
  return persist ? new PersistingEventBus(inner, persist) : inner;
}
