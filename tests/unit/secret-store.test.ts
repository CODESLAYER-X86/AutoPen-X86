import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { createInMemorySecretStore, EncryptedFileSecretStore } from '@aegis/security';

const tempDirs: string[] = [];

function tempStore(options: { masterKey?: string } = {}): {
  store: EncryptedFileSecretStore;
  path: string;
} {
  const dir = mkdtempSync(join(tmpdir(), 'secret-store-'));
  tempDirs.push(dir);
  const path = join(dir, 'secrets.json');
  return { store: new EncryptedFileSecretStore({ filePath: path, ...options }), path };
}

afterEach(() => {
  for (const dir of tempDirs.splice(0)) rmSync(dir, { recursive: true, force: true });
});

describe('encrypted secret store (spec §7, §13)', () => {
  it('round-trips a secret through an opaque reference', async () => {
    const { store } = tempStore();
    const reference = await store.store('SESSIONID=abc123; HttpOnly');
    expect(reference).toMatch(/^SEC_[A-Z2-7]{16,32}$/);
    expect(await store.resolve(reference)).toBe('SESSIONID=abc123; HttpOnly');
  });

  it('never writes plaintext to disk', async () => {
    const { store, path } = tempStore();
    const plaintext = 'JWT_SECRET_plaintext_value_9f8e7d6c';
    await store.store(plaintext);
    const onDisk = readFileSync(path, 'utf8');
    expect(onDisk).not.toContain(plaintext);
    expect(onDisk).not.toContain('plaintext_value');
  });

  it('rejects decryption with the wrong master key', async () => {
    const keyA = Buffer.from('a'.repeat(32)).toString('base64');
    const keyB = Buffer.from('b'.repeat(32)).toString('base64');
    const dir = mkdtempSync(join(tmpdir(), 'secret-store-'));
    tempDirs.push(dir);
    const path = join(dir, 'secrets.json');

    const storeA = new EncryptedFileSecretStore({ filePath: path, masterKey: keyA });
    const reference = await storeA.store('top secret material');

    const storeB = new EncryptedFileSecretStore({ filePath: path, masterKey: keyB });
    await expect(storeB.resolve(reference)).rejects.toThrowError(/decrypt/i);
  });

  it('persists across store instances (same key)', async () => {
    const key = Buffer.from('k'.repeat(32)).toString('base64');
    const dir = mkdtempSync(join(tmpdir(), 'secret-store-'));
    tempDirs.push(dir);
    const path = join(dir, 'secrets.json');

    const first = new EncryptedFileSecretStore({ filePath: path, masterKey: key });
    const reference = await first.store('persistent secret');

    const second = new EncryptedFileSecretStore({ filePath: path, masterKey: key });
    expect(await second.resolve(reference)).toBe('persistent secret');
  });

  it('rejects invalid master key sizes at construction', () => {
    const shortKey = Buffer.from('short').toString('base64');
    expect(
      () => new EncryptedFileSecretStore({ filePath: '/tmp/never.json', masterKey: shortKey }),
    ).toThrowError(/32 bytes/);
  });

  it('rejects malformed references and unknown refs', async () => {
    const { store } = tempStore();
    await expect(store.resolve('NOT_A_REFERENCE')).rejects.toThrowError(/reference/i);
    await expect(store.resolve('SEC_AAAAAAAAAAAAAAAA')).rejects.toThrowError(/unknown/i);
  });

  it('generates a development master key file on first use', async () => {
    const { store, path } = tempStore();
    await store.store('dev secret');
    const keyPath = `${path}.key`;
    const key = readFileSync(keyPath, 'utf8').trim();
    expect(Buffer.from(key, 'base64').length).toBe(32);
    // And the key works across restarts of the store instance.
    const reopened = new EncryptedFileSecretStore({ filePath: path });
    const reference = await reopened.store('another secret');
    expect(await reopened.resolve(reference)).toBe('another secret');
  });

  it('detects a corrupt store file', async () => {
    const { store, path } = tempStore();
    await store.store('secret');
    writeFileSync(path, '{ not json', 'utf8');
    await expect(store.store('another')).rejects.toThrowError(/corrupt/i);
  });

  it('in-memory implementation works for tests', async () => {
    const store = createInMemorySecretStore();
    const ref = await store.store('x');
    expect(await store.resolve(ref)).toBe('x');
  });
});
