/**
 * Knowledge retrieval interface (spec §3 — Knowledge).
 *
 * Part 1 defines the contract only. Part 5 implements write-up retrieval,
 * vulnerability references and CTF knowledge search.
 */
import { NotImplementedError } from '@aegis/shared';

export interface KnowledgeHit {
  ref: string;
  title: string;
  snippet: string;
  source: string;
}

export interface KnowledgeService {
  search(query: string, limit?: number): Promise<KnowledgeHit[]>;
  fetch(ref: string): Promise<{ title: string; content: string }>;
}

export function createNotImplementedKnowledgeService(): KnowledgeService {
  return {
    async search(): Promise<KnowledgeHit[]> {
      throw new NotImplementedError(
        'Knowledge retrieval is not implemented in Part 1; it is the subject of Part 5',
        'KNOWLEDGE_NOT_IMPLEMENTED',
      );
    },
    async fetch(): Promise<{ title: string; content: string }> {
      throw new NotImplementedError(
        'Knowledge retrieval is not implemented in Part 1; it is the subject of Part 5',
        'KNOWLEDGE_NOT_IMPLEMENTED',
      );
    },
  };
}
