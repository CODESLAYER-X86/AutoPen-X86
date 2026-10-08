/**
 * Evidence service (spec §22).
 *
 * Guarantees:
 *  - Content is hashed (SHA-256) BEFORE storage; the database row carries
 *    the hash and an opaque content reference, never raw bytes.
 *  - Stored evidence is immutable: the object store refuses to overwrite a
 *    key with different content, and there is no update path in the API.
 *  - Derived evidence MUST reference its parent record.
 *  - `verify()` re-hashes stored content and compares — tamper detection.
 */
import { createHash } from 'node:crypto';
import type { Logger } from '@aegis/logging';
import {
  EvidenceError,
  NotFoundError,
  generateId,
} from '@aegis/shared';
import type { EvidenceRepository, EvidenceRecord } from '@aegis/database';
import type { ObjectStore } from './object-store.js';

export interface EvidenceStoreInput {
  engagement_id: string;
  type: string;
  source: string;
  content: Uint8Array | string;
  task_id?: string | null;
  metadata?: Record<string, unknown>;
}

export interface EvidenceDeriveInput extends Omit<EvidenceStoreInput, 'engagement_id'> {
  parent_id: string;
}

export interface VerificationResult {
  evidence_id: string;
  verified: boolean;
  reason?: string;
}

export interface EvidenceServiceDeps {
  repository: EvidenceRepository;
  objectStore: ObjectStore;
  logger: Logger;
}

export class EvidenceService {
  private readonly deps: EvidenceServiceDeps;

  constructor(deps: EvidenceServiceDeps) {
    this.deps = deps;
  }

  async store(input: EvidenceStoreInput): Promise<EvidenceRecord> {
    const content =
      typeof input.content === 'string' ? new TextEncoder().encode(input.content) : input.content;

    const { key } = await this.deps.objectStore.put(content);

    // Idempotency: identical content in the same engagement is one record.
    const existing = await this.deps.repository.findBySha(input.engagement_id, key);
    if (existing) return existing;

    const record = await this.deps.repository.insert({
      engagementId: input.engagement_id,
      type: input.type,
      source: input.source,
      contentReference: key,
      sha256: key,
      parentId: null,
      taskId: input.task_id ?? null,
      metadata: {
        ...(input.metadata ?? {}),
        bytes: content.byteLength,
      },
    });

    this.deps.logger.info('evidence.stored', {
      engagement_id: input.engagement_id,
      evidence_id: record.id,
      sha256: key,
      bytes: content.byteLength,
    });

    return record;
  }

  async derive(input: EvidenceDeriveInput): Promise<EvidenceRecord> {
    const parent = await this.deps.repository.findById(input.parent_id);
    if (!parent) {
      throw new NotFoundError('EVIDENCE');
    }

    const content =
      typeof input.content === 'string' ? new TextEncoder().encode(input.content) : input.content;
    const { key } = await this.deps.objectStore.put(content);

    const record = await this.deps.repository.insert({
      engagementId: parent.engagement_id,
      type: input.type,
      source: input.source,
      contentReference: key,
      sha256: key,
      parentId: parent.id,
      taskId: input.task_id ?? parent.task_id ?? null,
      metadata: {
        ...(input.metadata ?? {}),
        bytes: content.byteLength,
        derived_from: parent.id,
      },
    });

    this.deps.logger.info('evidence.derived', {
      engagement_id: parent.engagement_id,
      evidence_id: record.id,
      parent_id: parent.id,
      sha256: key,
    });

    return record;
  }

  async verify(evidenceId: string): Promise<VerificationResult> {
    const record = await this.deps.repository.findById(evidenceId);
    if (!record) throw new NotFoundError('EVIDENCE');

    let content: Uint8Array;
    try {
      content = await this.deps.objectStore.get(record.content_reference);
    } catch {
      return { evidence_id: evidenceId, verified: false, reason: 'content object missing from store' };
    }

    const actual = createHash('sha256').update(content).digest('hex');
    if (actual !== record.sha256) {
      return { evidence_id: evidenceId, verified: false, reason: 'content hash mismatch (tampered or corrupted)' };
    }
    return { evidence_id: evidenceId, verified: true };
  }

  async get(evidenceId: string): Promise<EvidenceRecord> {
    const record = await this.deps.repository.findById(evidenceId);
    if (!record) throw new NotFoundError('EVIDENCE');
    return record;
  }

  async list(engagementId: string): Promise<EvidenceRecord[]> {
    return this.deps.repository.listByEngagement(engagementId);
  }

  /** Read raw evidence content (audited at the API layer). */
  async readContent(evidenceId: string): Promise<Uint8Array> {
    const record = await this.get(evidenceId);
    const content = await this.deps.objectStore.get(record.content_reference);
    const actual = createHash('sha256').update(content).digest('hex');
    if (actual !== record.sha256) {
      throw new EvidenceError(
        'Evidence content failed hash verification on read',
        'EVIDENCE_HASH_MISMATCH',
      );
    }
    return content;
  }

  /** Generates a fresh evidence id (used by tests and future tools). */
  static newEvidenceId(): string {
    return generateId('EVD');
  }
}
