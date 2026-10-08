/**
 * Object storage abstraction (spec §4: "Object/blob storage should own
 * large artifacts"). Part 1 ships the local-filesystem implementation.
 * Keys are SHA-256 hex digests — content-addressed and immutable.
 */
import { createHash } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { EvidenceError } from '@aegis/shared';

export interface ObjectStore {
  /** Writes content once; returns the content-addressed key (sha256 hex). */
  put(content: Uint8Array): Promise<{ key: string; existed: boolean }>;
  /** Reads content back by key. */
  get(key: string): Promise<Uint8Array>;
  has(key: string): Promise<boolean>;
}

const KEY_PATTERN = /^[a-f0-9]{64}$/;

export class LocalFileSystemObjectStore implements ObjectStore {
  private readonly root: string;

  constructor(root: string) {
    this.root = root;
    mkdirSync(root, { recursive: true });
  }

  private pathFor(key: string): string {
    return join(this.root, key.slice(0, 2), key.slice(2, 4), key);
  }

  private assertKey(key: string): void {
    if (!KEY_PATTERN.test(key)) {
      throw new EvidenceError('Object store keys must be 64-char sha256 hex digests', 'OBJECT_KEY_INVALID');
    }
  }

  async put(content: Uint8Array): Promise<{ key: string; existed: boolean }> {
    const key = createHash('sha256').update(content).digest('hex');
    this.assertKey(key);
    const path = this.pathFor(key);
    if (existsSync(path)) {
      // Immutability: same key must map to identical content (verify by hash).
      const existingHash = createHash('sha256').update(readFileSync(path)).digest('hex');
      if (existingHash !== key) {
        throw new EvidenceError(
          'Hash collision or tampering: existing object does not match new content',
          'EVIDENCE_IMMUTABILITY',
        );
      }
      return { key, existed: true };
    }
    mkdirSync(join(path, '..'), { recursive: true });
    writeFileSync(path, content, { mode: 0o640 });
    return { key, existed: false };
  }

  async get(key: string): Promise<Uint8Array> {
    this.assertKey(key);
    const path = this.pathFor(key);
    if (!existsSync(path)) {
      throw new EvidenceError(`Object '${key}' not found`, 'OBJECT_NOT_FOUND');
    }
    return readFileSync(path);
  }

  async has(key: string): Promise<boolean> {
    if (!KEY_PATTERN.test(key)) return false;
    return existsSync(this.pathFor(key));
  }
}

/** In-memory implementation for unit tests. */
export class InMemoryObjectStore implements ObjectStore {
  private readonly objects = new Map<string, Uint8Array>();

  async put(content: Uint8Array): Promise<{ key: string; existed: boolean }> {
    const key = createHash('sha256').update(content).digest('hex');
    const existed = this.objects.has(key);
    this.objects.set(key, content);
    return { key, existed };
  }

  async get(key: string): Promise<Uint8Array> {
    const content = this.objects.get(key);
    if (content === undefined) {
      throw new EvidenceError(`Object '${key}' not found`, 'OBJECT_NOT_FOUND');
    }
    return content;
  }

  async has(key: string): Promise<boolean> {
    return this.objects.has(key);
  }
}
