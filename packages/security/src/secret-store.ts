/**
 * Encrypted secret store (spec §7, §13).
 *
 * Credential material (target cookies, JWTs, API keys, passwords) is NEVER
 * stored in ordinary model context, the database, or logs. The database
 * holds only an opaque reference (e.g. `SEC_2F9A7CD1AB01EF46`) which is
 * resolved through this store at the point of use.
 *
 * Storage format: a single JSON file where each entry is
 *   { "iv", "tag", "data" }  — AES-256-GCM ciphertext.
 * The master key is either provided via SECRET_STORE_MASTER_KEY (base64,
 * 32 bytes) or generated once for development at <path>.key.
 *
 * Plaintext never touches disk.
 */
import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { ConfigurationError, PlatformError, generateId } from '@aegis/shared';

export interface SecretStore {
  /** Stores plaintext, returns an opaque secret reference. */
  store(plaintext: string): Promise<string>;
  /** Resolves a reference back to plaintext. Throws if unknown/corrupt. */
  resolve(reference: string): Promise<string>;
}

export interface EncryptedFileSecretStoreOptions {
  filePath: string;
  /** Base64-encoded 32-byte key. If omitted, a dev key file is used. */
  masterKey?: string;
  onDevKey?: (keyPath: string) => void;
}

interface StoredSecret {
  iv: string;
  tag: string;
  data: string;
}

interface StoreFile {
  version: 1;
  secrets: Record<string, StoredSecret>;
}

function isReference(reference: string): boolean {
  return /^SEC_[A-Z2-7]{16,32}$/.test(reference);
}

export class EncryptedFileSecretStore implements SecretStore {
  private readonly filePath: string;
  private readonly keyPath: string;
  private key: Buffer | null = null;
  private onDevKey?: (keyPath: string) => void;

  constructor(options: EncryptedFileSecretStoreOptions) {
    this.filePath = options.filePath;
    this.keyPath = `${options.filePath}.key`;
    this.onDevKey = options.onDevKey;
    if (options.masterKey) {
      const key = Buffer.from(options.masterKey, 'base64');
      if (key.length !== 32) {
        throw new ConfigurationError(
          'SECRET_STORE_MASTER_KEY must be base64 encoding exactly 32 bytes',
          undefined,
          'SECRET_MASTER_KEY_INVALID',
        );
      }
      this.key = key;
    }
  }

  private ensureKey(): Buffer {
    if (this.key) return this.key;
    if (existsSync(this.keyPath)) {
      const key = Buffer.from(readFileSync(this.keyPath, 'utf8').trim(), 'base64');
      if (key.length !== 32) {
        throw new ConfigurationError(
          'Corrupt secret store master key file',
          undefined,
          'SECRET_MASTER_KEY_INVALID',
        );
      }
      this.key = key;
      return key;
    }
    // Development convenience: generate and persist a random key.
    const key = randomBytes(32);
    mkdirSync(dirname(this.keyPath), { recursive: true });
    writeFileSync(this.keyPath, `${key.toString('base64')}\n`, { mode: 0o600 });
    this.key = key;
    this.onDevKey?.(this.keyPath);
    return key;
  }

  private loadFile(): StoreFile {
    if (!existsSync(this.filePath)) return { version: 1, secrets: {} };
    try {
      const parsed = JSON.parse(readFileSync(this.filePath, 'utf8')) as StoreFile;
      if (parsed?.version !== 1 || typeof parsed.secrets !== 'object' || parsed.secrets === null) {
        throw new Error('bad shape');
      }
      return parsed;
    } catch {
      throw new ConfigurationError('Secret store file is corrupt', undefined, 'SECRET_STORE_CORRUPT');
    }
  }

  private persist(file: StoreFile): void {
    mkdirSync(dirname(this.filePath), { recursive: true });
    const tmp = `${this.filePath}.tmp`;
    writeFileSync(tmp, `${JSON.stringify(file)}\n`, { mode: 0o600 });
    renameSync(tmp, this.filePath);
  }

  async store(plaintext: string): Promise<string> {
    if (typeof plaintext !== 'string' || plaintext.length === 0 || plaintext.length > 65536) {
      throw new PlatformError('Secret payload must be a non-empty string <= 64KiB', {
        code: 'SECRET_PAYLOAD_INVALID',
        category: 'VALIDATION',
        statusCode: 400,
      });
    }
    const key = this.ensureKey();
    const iv = randomBytes(12);
    const cipher = createCipheriv('aes-256-gcm', key, iv);
    const data = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
    const file = this.loadFile();
    const reference = generateId('SEC');
    file.secrets[reference] = {
      iv: iv.toString('base64'),
      tag: cipher.getAuthTag().toString('base64'),
      data: data.toString('base64'),
    };
    this.persist(file);
    return reference;
  }

  async resolve(reference: string): Promise<string> {
    if (!isReference(reference)) {
      throw new PlatformError('Invalid secret reference', {
        code: 'SECRET_REFERENCE_INVALID',
        category: 'VALIDATION',
        statusCode: 400,
      });
    }
    const key = this.ensureKey();
    const file = this.loadFile();
    const entry = file.secrets[reference];
    if (!entry) {
      throw new PlatformError('Unknown secret reference', {
        code: 'SECRET_REFERENCE_UNKNOWN',
        category: 'AUTHORIZATION',
        statusCode: 404,
      });
    }
    try {
      const decipher = createDecipheriv('aes-256-gcm', key, Buffer.from(entry.iv, 'base64'));
      decipher.setAuthTag(Buffer.from(entry.tag, 'base64'));
      const plaintext = Buffer.concat([
        decipher.update(Buffer.from(entry.data, 'base64')),
        decipher.final(),
      ]);
      return plaintext.toString('utf8');
    } catch (cause) {
      // Auth-tag failure = wrong master key or tampered store.
      throw new PlatformError(
        'Secret could not be decrypted (wrong master key or tampering)',
        {
          code: 'SECRET_DECRYPT_FAILED',
          category: 'INTERNAL',
          statusCode: 500,
          cause,
        },
      );
    }
  }
}

export function createSecretStore(
  options: EncryptedFileSecretStoreOptions,
): SecretStore {
  return new EncryptedFileSecretStore(options);
}

/** Test helper: deterministic store in a temp path. */
export function createInMemorySecretStore(): SecretStore & { snapshot(): string } {
  const secrets = new Map<string, string>();
  return {
    async store(plaintext: string): Promise<string> {
      const ref = generateId('SEC');
      secrets.set(ref, plaintext);
      return ref;
    },
    async resolve(reference: string): Promise<string> {
      const value = secrets.get(reference);
      if (value === undefined) {
        throw new PlatformError('Unknown secret reference', {
          code: 'SECRET_REFERENCE_UNKNOWN',
          category: 'AUTHORIZATION',
          statusCode: 404,
        });
      }
      return value;
    },
    snapshot(): string {
      return JSON.stringify([...secrets.entries()]);
    },
  };
}
