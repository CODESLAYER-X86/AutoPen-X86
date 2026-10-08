import { createHash } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { createLogger, createMemorySink } from '@aegis/logging';
import { EvidenceError, NotFoundError } from '@aegis/shared';
import { EvidenceService, InMemoryObjectStore, type EvidenceRepositorySurface } from '@aegis/evidence';
import type { EvidenceRecord } from '@aegis/database';

/** Minimal in-memory evidence repository for unit testing the service. */
function fakeRepository(): EvidenceRepositorySurface & {
  rows: Map<string, EvidenceRecord>;
} {
  const rows = new Map<string, EvidenceRecord>();
  return {
    rows,
    async insert(input): Promise<EvidenceRecord> {
      const record: EvidenceRecord = {
        id: `EVD_${String(rows.size + 1).padStart(16, 'X')}`,
        engagement_id: input.engagementId,
        type: input.type,
        source: input.source,
        content_reference: input.contentReference,
        sha256: input.sha256,
        parent_id: input.parentId ?? null,
        task_id: input.taskId ?? null,
        metadata: input.metadata ?? {},
        created_at: new Date().toISOString(),
      };
      rows.set(record.id, record);
      return record;
    },
    async findById(id: string): Promise<EvidenceRecord | null> {
      return rows.get(id) ?? null;
    },
    async findBySha(engagementId: string, sha256: string): Promise<EvidenceRecord | null> {
      for (const record of rows.values()) {
        if (record.engagement_id === engagementId && record.sha256 === sha256) return record;
      }
      return null;
    },
    async listByEngagement(engagementId: string): Promise<EvidenceRecord[]> {
      return [...rows.values()].filter((record) => record.engagement_id === engagementId);
    },
  };
}

function sha256(content: string): string {
  return createHash('sha256').update(content).digest('hex');
}

describe('evidence service (spec §22, §33: evidence hashing)', () => {
  it('stores content hash-addressed and returns metadata only', async () => {
    const repository = fakeRepository();
    const service = new EvidenceService({
      repository,
      objectStore: new InMemoryObjectStore(),
      logger: createLogger({ sink: createMemorySink().sink }),
    });
    const record = await service.store({
      engagement_id: 'ENG_1',
      type: 'HTTP_RESPONSE',
      source: 'http.request',
      content: 'HTTP/1.1 200 OK\nX-Header: value',
    });
    expect(record.sha256).toBe(sha256('HTTP/1.1 200 OK\nX-Header: value'));
    expect(record.content_reference).toBe(record.sha256);
    expect(record.metadata.bytes).toBeGreaterThan(0);
  });

  it('is idempotent for identical content within an engagement', async () => {
    const repository = fakeRepository();
    const service = new EvidenceService({
      repository,
      objectStore: new InMemoryObjectStore(),
      logger: createLogger({ sink: createMemorySink().sink }),
    });
    const first = await service.store({
      engagement_id: 'ENG_1',
      type: 'NOTE',
      source: 'test',
      content: 'same bytes',
    });
    const second = await service.store({
      engagement_id: 'ENG_1',
      type: 'NOTE',
      source: 'test',
      content: 'same bytes',
    });
    expect(second.id).toBe(first.id);
    expect(repository.rows.size).toBe(1);
  });

  it('verify() detects tampering of stored content', async () => {
    // Tampered store: hashes keys correctly but stores different content.
    const tampered = new Map<string, Uint8Array>();
    const lyingStore = {
      put: async (content: Uint8Array) => {
        const key = createHash('sha256').update(content).digest('hex');
        tampered.set(key, new TextEncoder().encode('TAMPERED CONTENT'));
        return { key, existed: false };
      },
      get: async (key: string) => {
        const content = tampered.get(key);
        if (content === undefined) throw new Error('missing');
        return content;
      },
      has: async (key: string) => tampered.has(key),
    };
    const repository = fakeRepository();
    const service = new EvidenceService({
      repository,
      objectStore: lyingStore,
      logger: createLogger({ sink: createMemorySink().sink }),
    });
    const record = await service.store({
      engagement_id: 'ENG_1',
      type: 'HTTP_RESPONSE',
      source: 'test',
      content: 'original bytes',
    });
    const verification = await service.verify(record.id);
    expect(verification.verified).toBe(false);
    expect(verification.reason).toMatch(/mismatch/i);
  });

  it('verify() confirms intact evidence', async () => {
    const repository = fakeRepository();
    const service = new EvidenceService({
      repository,
      objectStore: new InMemoryObjectStore(),
      logger: createLogger({ sink: createMemorySink().sink }),
    });
    const record = await service.store({
      engagement_id: 'ENG_1',
      type: 'SCREENSHOT',
      source: 'browser.snapshot',
      content: new Uint8Array([1, 2, 3, 4, 5]),
    });
    const verification = await service.verify(record.id);
    expect(verification.verified).toBe(true);
  });

  it('derived evidence must reference an existing parent', async () => {
    const repository = fakeRepository();
    const service = new EvidenceService({
      repository,
      objectStore: new InMemoryObjectStore(),
      logger: createLogger({ sink: createMemorySink().sink }),
    });
    await expect(
      service.derive({ parent_id: 'EVD_MISSING', type: 'DIFF', source: 'diff', content: 'x' }),
    ).rejects.toThrowError(NotFoundError);
  });

  it('derived evidence links to its parent', async () => {
    const repository = fakeRepository();
    const service = new EvidenceService({
      repository,
      objectStore: new InMemoryObjectStore(),
      logger: createLogger({ sink: createMemorySink().sink }),
    });
    const parent = await service.store({
      engagement_id: 'ENG_1',
      type: 'HTTP_RESPONSE',
      source: 'http.request',
      content: 'parent content',
    });
    const derived = await service.derive({
      parent_id: parent.id,
      type: 'DERIVED_ANALYSIS',
      source: 'diff.response',
      content: 'derived content',
    });
    expect(derived.parent_id).toBe(parent.id);
    expect(derived.metadata.derived_from).toBe(parent.id);
    expect(derived.engagement_id).toBe(parent.engagement_id);
  });

  it('readContent fails closed on hash mismatch', async () => {
    // Store real evidence, then swap in a store whose get() lies about content.
    const objectStore = new InMemoryObjectStore();
    const repository = fakeRepository();
    const service = new EvidenceService({
      repository,
      objectStore,
      logger: createLogger({ sink: createMemorySink().sink }),
    });
    const record = await service.store({
      engagement_id: 'ENG_1',
      type: 'X',
      source: 'test',
      content: 'original',
    });
    const lyingStore = {
      put: (content: Uint8Array) => objectStore.put(content),
      get: async (key: string) => {
        const real = await objectStore.get(key);
        // Return different bytes than what was stored.
        return new Uint8Array([...real.slice(0, -1), real[real.length - 1]! ^ 0xff]);
      },
      has: (key: string) => objectStore.has(key),
    };
    const tamperedService = new EvidenceService({
      repository,
      objectStore: lyingStore,
      logger: createLogger({ sink: createMemorySink().sink }),
    });
    await expect(tamperedService.readContent(record.id)).rejects.toThrowError(EvidenceError);
  });
});
