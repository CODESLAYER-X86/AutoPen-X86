/**
 * Embedding providers (spec Part 5 §14, §95, §107).
 *
 * The embedding model is CONFIGURABLE and versioned: every vector row
 * records model + version + dimension, so switching models is an explicit
 * reindex — never a silent vector mix (§95). Model identifiers are never
 * hard-coded (§107).
 *
 * Providers:
 *  - HashingEmbeddingProvider (default): fully deterministic, offline
 *    hashed bag-of-n-grams, L2-normalized. Gives real local semantic-ish
 *    retrieval with zero external dependency.
 *  - GoogleEmbeddingProvider: optional external REST provider.
 *  - NoneEmbeddingProvider: keyword-only mode (§116: embedding failure
 *    keeps documents keyword-searchable).
 */
import { createHash } from 'node:crypto';

export interface EmbeddingProvider {
  readonly id: string;
  readonly model: string;
  readonly version: number;
  readonly dimension: number;
  embed(texts: string[]): Promise<number[][]>;
}

/** Murmur-style 32-bit string hash — deterministic across runs. */
function hash32(input: string, seed: number): number {
  let h = seed >>> 0;
  for (let i = 0; i < input.length; i += 1) {
    h ^= input.charCodeAt(i);
    h = Math.imul(h, 0x01000193) >>> 0;
  }
  h ^= h >>> 16;
  return h >>> 0;
}

function tokenize(text: string): string[] {
  return text
    .toLowerCase()
    .replace(/[^a-z0-9\s+#.-]/g, ' ')
    .split(/\s+/)
    .filter((t) => t.length > 1 && t.length < 40);
}

/**
 * Deterministic hashing embedding: unigrams + bigrams are hashed into a
 * fixed-dimension space with signed accumulation, then L2-normalized.
 * Cosine similarity approximates lexical-semantic similarity; exact
 * terminology is already covered by the keyword index (§16 hybrid).
 */
export class HashingEmbeddingProvider implements EmbeddingProvider {
  readonly id = 'hash';
  readonly version = 1;

  constructor(readonly model: string = 'aegis-hash-256-v1', readonly dimension: number = 256) {}

  async embed(texts: string[]): Promise<number[][]> {
    return texts.map((text) => this.embedOne(text));
  }

  embedOne(text: string): number[] {
    const vector = new Float64Array(this.dimension);
    const tokens = tokenize(text);
    const counts = new Map<string, number>();
    for (let i = 0; i < tokens.length; i += 1) {
      counts.set(tokens[i]!, (counts.get(tokens[i]!) ?? 0) + 1);
      if (i + 1 < tokens.length) {
        const bigram = `${tokens[i]}_${tokens[i + 1]}`;
        counts.set(bigram, (counts.get(bigram) ?? 0) + 1);
      }
    }
    for (const [term, count] of counts) {
      // Sublinear term frequency keeps long chunks from dominating.
      const weight = 1 + Math.log(count);
      const idx = hash32(term, 0x9747b28c) % this.dimension;
      const sign = hash32(term, 0x85ebca6b) % 2 === 0 ? 1 : -1;
      vector[idx] = (vector[idx] ?? 0) + sign * weight;
    }
    let norm = 0;
    for (const value of vector) norm += value * value;
    norm = Math.sqrt(norm);
    const output = new Array<number>(this.dimension);
    for (let i = 0; i < this.dimension; i += 1) {
      output[i] = norm > 0 ? vector[i]! / norm : 0;
    }
    return output;
  }
}

/** No-op provider: keyword-only retrieval (§116). */
export class NoneEmbeddingProvider implements EmbeddingProvider {
  readonly id = 'none';
  readonly model = 'none';
  readonly version = 0;
  readonly dimension = 0;

  async embed(): Promise<number[][]> {
    return [];
  }
}

export interface GoogleEmbeddingOptions {
  apiKey: string;
  model?: string;
  dimension?: number;
  timeoutMs?: number;
  /** Injectable fetch for tests. */
  fetchImpl?: typeof fetch;
}

/**
 * Google generativelanguage embeddings (optional). Configuration never
 * hard-codes identifiers (§107); the API key flows from the environment to
 * the provider only.
 */
export class GoogleEmbeddingProvider implements EmbeddingProvider {
  readonly id = 'google';
  readonly model: string;
  readonly version = 1;
  readonly dimension: number;
  private readonly apiKey: string;
  private readonly timeoutMs: number;
  private readonly fetchImpl: typeof fetch;

  constructor(options: GoogleEmbeddingOptions) {
    this.apiKey = options.apiKey;
    this.model = options.model ?? 'text-embedding-004';
    this.dimension = options.dimension ?? 768;
    this.timeoutMs = options.timeoutMs ?? 30_000;
    this.fetchImpl = options.fetchImpl ?? fetch;
  }

  async embed(texts: string[]): Promise<number[][]> {
    if (texts.length === 0) return [];
    const response = await this.fetchImpl(
      `https://generativelanguage.googleapis.com/v1beta/models/${this.model}:batchEmbedContents?key=${this.apiKey}`,
      {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({
          requests: texts.slice(0, 100).map((text) => ({
            model: `models/${this.model}`,
            content: { parts: [{ text: text.slice(0, 8000) }] },
          })),
        }),
        signal: AbortSignal.timeout(this.timeoutMs),
      },
    );
    if (!response.ok) {
      throw Object.assign(new Error(`google embedding provider failed: HTTP ${response.status}`), {
        code: 'EMBEDDING_PROVIDER_FAILED',
      });
    }
    const payload = (await response.json()) as { embeddings?: Array<{ values: number[] }> };
    const embeddings = payload.embeddings ?? [];
    return embeddings.map((e) => e.values);
  }
}

/** Cosine similarity of two equal-length vectors. */
export function cosineSimilarity(a: number[], b: number[]): number {
  if (a.length === 0 || a.length !== b.length) return 0;
  let dot = 0;
  let normA = 0;
  let normB = 0;
  for (let i = 0; i < a.length; i += 1) {
    dot += a[i]! * b[i]!;
    normA += a[i]! * a[i]!;
    normB += b[i]! * b[i]!;
  }
  if (normA === 0 || normB === 0) return 0;
  return dot / (Math.sqrt(normA) * Math.sqrt(normB));
}

/** Stable embedding version marker for reindex decisions (§95). */
export function embeddingVersionKey(provider: EmbeddingProvider): string {
  return createHash('sha256')
    .update(`${provider.id}:${provider.model}:${provider.version}:${provider.dimension}`)
    .digest('hex')
    .slice(0, 24);
}
