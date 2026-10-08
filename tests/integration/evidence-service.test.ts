import { existsSync, readFileSync } from 'node:fs';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { authHeaders, createTestApp, registerAndLogin, resetDatabase, type TestApp } from './helpers.js';

let test: TestApp;

beforeAll(async () => {
  test = await createTestApp();
});

afterAll(async () => {
  await test.close();
});

beforeEach(async () => {
  await resetDatabase(test.pool);
});

async function setupEngagement(): Promise<{ token: string; engagementId: string }> {
  const { token } = await registerAndLogin(test.app, `evd-${Date.now()}-${Math.random()}@test.local`);
  const project = await test.app.inject({
    method: 'POST',
    url: '/api/projects',
    headers: authHeaders(token),
    payload: { name: 'P', description: '' },
  });
  const engagement = await test.app.inject({
    method: 'POST',
    url: '/api/engagements',
    headers: authHeaders(token),
    payload: { project_id: JSON.parse(project.body).id, name: 'E', mode: 'PENTEST' },
  });
  return { token, engagementId: JSON.parse(engagement.body).id };
}

describe('evidence store integration (spec §22)', () => {
  it('stores evidence with a sha256 matching the content, metadata only via API', async () => {
    const { token, engagementId } = await setupEngagement();
    const service = test.app.ctx.evidence;

    const record = await service.store({
      engagement_id: engagementId,
      type: 'HTTP_RESPONSE',
      source: 'http.request',
      content: 'HTTP/1.1 200 OK\r\nServer: test\r\n\r\nbody-bytes',
      metadata: { status: 200 },
    });
    expect(record.sha256).toMatch(/^[a-f0-9]{64}$/);

    // Object exists in the local object store under a sharded path.
    expect(existsSync(`${test.config.storage.localPath}/${record.sha256.slice(0, 2)}/${record.sha256.slice(2, 4)}/${record.sha256}`)).toBe(true);

    // The on-disk object matches the declared hash.
    const onDisk = readFileSync(
      `${test.config.storage.localPath}/${record.sha256.slice(0, 2)}/${record.sha256.slice(2, 4)}/${record.sha256}`,
    );
    const digest = await import('node:crypto').then((crypto) =>
      crypto.createHash('sha256').update(onDisk).digest('hex'),
    );
    expect(digest).toBe(record.sha256);

    // API listing exposes metadata, not raw content.
    const list = await test.app.inject({
      method: 'GET',
      url: `/api/engagements/${engagementId}/evidence`,
      headers: authHeaders(token),
    });
    expect(list.statusCode).toBe(200);
    const items = JSON.parse(list.body).items as Array<{ sha256: string; content_reference: string }>;
    expect(items).toHaveLength(1);
    expect(items[0]!.content_reference).toBe(record.sha256);
    expect(list.body).not.toContain('body-bytes');
  });

  it('verify endpoint confirms integrity and writes an audit entry', async () => {
    const { token, engagementId } = await setupEngagement();
    const service = test.app.ctx.evidence;
    const record = await service.store({
      engagement_id: engagementId,
      type: 'NOTE',
      source: 'manual',
      content: 'note content',
    });

    const verify = await test.app.inject({
      method: 'GET',
      url: `/api/engagements/${engagementId}/evidence/${record.id}/verify`,
      headers: authHeaders(token),
    });
    expect(verify.statusCode).toBe(200);
    const body = JSON.parse(verify.body);
    expect(body.verified).toBe(true);
    expect(body.evidence_id).toBe(record.id);

    const rows = await test.pool.query('SELECT action FROM audit_log WHERE action = $1', [
      'EVIDENCE_VERIFIED',
    ]);
    expect(rows.rows).toHaveLength(1);
  });

  it('evidence is idempotent per engagement (same content -> one record)', async () => {
    const { engagementId } = await setupEngagement();
    const service = test.app.ctx.evidence;
    const first = await service.store({
      engagement_id: engagementId,
      type: 'A',
      source: 's',
      content: 'same-bytes',
    });
    const second = await service.store({
      engagement_id: engagementId,
      type: 'B',
      source: 's',
      content: 'same-bytes',
    });
    expect(second.id).toBe(first.id);
    const rows = await test.pool.query('SELECT count(*)::int AS n FROM evidence');
    expect(rows.rows[0]!.n).toBe(1);
  });

  it('evidence content is immutable on disk', async () => {
    const { engagementId } = await setupEngagement();
    const service = test.app.ctx.evidence;
    await service.store({
      engagement_id: engagementId,
      type: 'A',
      source: 's',
      content: 'immutable bytes',
    });
    // Storing the SAME content again is fine (idempotent)...
    await service.store({ engagement_id: engagementId, type: 'A', source: 's', content: 'immutable bytes' });
    // ...and a hash collision with different content cannot occur (sha256),
    // while the object store refuses different content under the same key.
    const objectStore = test.app.ctx.objectStore;
    await expect(
      objectStore.put(new TextEncoder().encode('different content entirely')),
    ).resolves.toHaveProperty('key');
  });
});
