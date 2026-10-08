import { describe, expect, it } from 'vitest';
import { InMemoryEventBus, PersistingEventBus, type EventBus } from '@aegis/events';
import type { PlatformEvent } from '@aegis/contracts';

function sampleEvent(type: PlatformEvent['type'] = 'TARGET_ADDED'): PlatformEvent {
  return {
    type,
    engagement_id: 'ENG_TEST',
    payload: { target: 'http://localhost:8080' },
    occurred_at: new Date().toISOString(),
  };
}

describe('event bus abstraction (spec §14)', () => {
  it('delivers events to all subscribers', async () => {
    const bus: EventBus = new InMemoryEventBus();
    const seen: string[] = [];
    bus.subscribe((event) => void seen.push(event.type));
    bus.subscribe((event) => void seen.push(`${event.type}#2`));
    await bus.publish(sampleEvent());
    expect(seen).toEqual(['TARGET_ADDED', 'TARGET_ADDED#2']);
  });

  it('isolates faulty subscribers from the publisher', async () => {
    const bus: EventBus = new InMemoryEventBus();
    let delivered = false;
    bus.subscribe(() => {
      throw new Error('subscriber bug');
    });
    bus.subscribe(() => {
      delivered = true;
    });
    await expect(bus.publish(sampleEvent())).resolves.toBeUndefined();
    expect(delivered).toBe(true);
  });

  it('unsubscribe stops delivery', async () => {
    const bus: EventBus = new InMemoryEventBus();
    const seen: string[] = [];
    const unsubscribe = bus.subscribe((event) => void seen.push(event.type));
    await bus.publish(sampleEvent('SCOPE_UPDATED'));
    unsubscribe();
    await bus.publish(sampleEvent('TARGET_ADDED'));
    expect(seen).toEqual(['SCOPE_UPDATED']);
  });

  it('persisting bus persists first, then fans out', async () => {
    const order: string[] = [];
    const persisted: PlatformEvent[] = [];
    const bus = new PersistingEventBus(
      new InMemoryEventBus(),
      async (event) => {
        order.push('persist');
        persisted.push(event);
      },
    );
    bus.subscribe(() => void order.push('fanout'));
    await bus.publish(sampleEvent('ENGAGEMENT_STARTED'));
    expect(order).toEqual(['persist', 'fanout']);
    expect(persisted).toHaveLength(1);
    expect(persisted[0]?.type).toBe('ENGAGEMENT_STARTED');
  });

  it('persisting bus propagates persistence failures (no silent loss)', async () => {
    const bus = new PersistingEventBus(
      new InMemoryEventBus(),
      async () => {
        throw new Error('database down');
      },
    );
    await expect(bus.publish(sampleEvent())).rejects.toThrowError('database down');
  });
});
