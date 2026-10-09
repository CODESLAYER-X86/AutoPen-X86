/**
 * Case memory: CTF write-ups and similar-case retrieval (spec Part 5
 * §36-§42, §100-§102, §124).
 *
 * Case memory is SEPARATE from general knowledge (§37): observations, dead
 * ends and findings from prior engagements are engagement evidence owned by
 * Part 2/4 — never mixed into this corpus.
 *
 * CTF safety (§41): write-up content is UNTRUSTED external knowledge. The
 * system extracts structured PATTERNS (§42: technique / precondition /
 * signal / test pattern / verification / false-positive condition) instead
 * of storing only prose, and PATTERN_RETRIEVAL never copies a solution —
 * it expands the hypothesis space (§124).
 */
import type { SecurityTaxonomyCategory } from '@aegis/shared';
import type { Repositories } from '@aegis/database';
import type { SimilarCase, SimilarCaseRequest, SimilarCaseResult, IngestionOutcome } from '@aegis/contracts';
import { HybridRetriever } from './retrieval.js';
import { ctfClueConcepts, ctfConceptList } from './taxonomy.js';
import { jaccardText } from './similarity.js';

export interface CtfWriteupInput {
  sourceId: string;
  url: string;
  challenge_name: string;
  event?: string | null;
  year?: number | null;
  category?: string | null;
  platform?: string | null;
  difficulty?: string | null;
  description: string;
  technique?: string | null;
  solution_summary?: string | null;
  /** Full write-up body (optional; pattern extraction runs on it). */
  body?: string;
}

export interface CaseMemoryDeps {
  repos: Repositories;
  retriever?: HybridRetriever;
  ingest: (input: {
    sourceId: string;
    url: string;
    raw?: { bytes: Uint8Array; contentType: string | null };
    titleOverride?: string;
    ctf?: Record<string, unknown>;
  }) => Promise<IngestionOutcome>;
}

export interface PatternExtraction {
  technique: string;
  precondition: string | null;
  observable_signal: string | null;
  test_pattern: string | null;
  verification_condition: string | null;
  false_positive_condition: string | null;
}

/**
 * Deterministic CTF pattern extraction (§42): recognize structured labels
 * in write-up prose ("Signal:", "Precondition:", ...) and fall back to
 * sentence-level heuristics. Patterns are stored in security_techniques.
 */
export function extractPatterns(text: string, fallbackTechnique: string | null | undefined): PatternExtraction[] {
  const patterns: PatternExtraction[] = [];
  const labeled = (label: string): string | null => {
    const re = new RegExp(`\\b${label}\\s*[:\\-]\\s*([^\\n.]{5,300})`, 'i');
    return re.exec(text)?.[1]?.trim() ?? null;
  };
  const technique = labeled('technique') ?? fallbackTechnique ?? null;
  if (!technique) return patterns;
  patterns.push({
    technique: technique.slice(0, 256),
    precondition: labeled('precondition'),
    observable_signal: labeled('(?:signal|observable)'),
    test_pattern: labeled('(?:test pattern|how to test)'),
    verification_condition: labeled('verification'),
    false_positive_condition: labeled('(?:false positive|pitfall)'),
  });
  return patterns;
}

/** Ingest a CTF write-up into case memory with pattern extraction (§39/§42). */
export async function ingestCtfWriteup(
  deps: CaseMemoryDeps,
  input: CtfWriteupInput,
): Promise<{ documentId: string; patternsStored: number }> {
  const body = input.body ?? `${input.description}\n\nTechnique: ${input.technique ?? ''}`;
  const raw = Buffer.from(body, 'utf8');
  const outcome = await deps.ingest({
    sourceId: input.sourceId,
    url: input.url,
    raw: { bytes: new Uint8Array(raw), contentType: 'text/markdown' },
    // The challenge name is the human-facing title of the write-up (§39).
    titleOverride: input.challenge_name,
    ctf: {
      challenge_name: input.challenge_name,
      event: input.event ?? null,
      year: input.year ?? null,
      category: input.category ?? null,
      platform: input.platform ?? null,
      difficulty: input.difficulty ?? null,
      description: input.description,
      technique: input.technique ?? null,
      solution_summary: input.solution_summary ?? null,
    },
  });

  // Structured concepts (§42) land in security_techniques — knowledge-to-test
  // translation material, not payload dumps (§44).
  let patternsStored = 0;
  for (const pattern of extractPatterns(body, input.technique)) {
    const category = categoryFor(input.category ?? null, body);
    await deps.repos.securityTechniques.upsert({
      name: `CTF: ${pattern.technique}`.slice(0, 256),
      category,
      description: (pattern.technique ?? input.challenge_name).slice(0, 4000),
      preconditions: pattern.precondition ? [pattern.precondition] : [],
      signals: pattern.observable_signal ? [pattern.observable_signal] : [],
      testPatterns: pattern.test_pattern ? [pattern.test_pattern] : [],
      verificationPatterns: pattern.verification_condition ? [pattern.verification_condition] : [],
      falsePositiveConditions: pattern.false_positive_condition ? [pattern.false_positive_condition] : [],
      sourceIds: [input.sourceId],
      confidence: 0.55,
    });
    patternsStored += 1;
  }
  return { documentId: outcome.document_id, patternsStored };
}

function categoryFor(ctfCategory: string | null | undefined, text: string): SecurityTaxonomyCategory {
  const raw = (ctfCategory ?? '').toLowerCase();
  if (raw.includes('web')) return 'CLIENT_SIDE';
  if (raw.includes('crypto')) return 'CRYPTO';
  if (raw.includes('auth')) return raw.includes('authz') ? 'AUTHORIZATION' : 'AUTHENTICATION';
  const lowered = text.toLowerCase();
  if (lowered.includes('authorization') || lowered.includes('idor')) return 'AUTHORIZATION';
  if (lowered.includes('injection') || lowered.includes('sqli')) return 'INJECTION';
  if (lowered.includes('session') || lowered.includes('cookie')) return 'SESSION';
  if (lowered.includes('jwt') || lowered.includes('login')) return 'AUTHENTICATION';
  return 'BUSINESS_LOGIC';
}

/**
 * Similar-case retrieval (§36, §40, §102).
 *
 * PATTERN_RETRIEVAL (default): the observation text is expanded through the
 * CTF concept map and matched against write-up descriptions/techniques —
 * the leader gets candidate PATTERNS, not a solution (§124).
 * EXACT_CASE_RETRIEVAL: challenge-name/title matching, for benchmark
 * evaluation only (§102: the two modes stay distinct).
 */
export async function similarCases(
  deps: CaseMemoryDeps,
  request: SimilarCaseRequest,
): Promise<SimilarCaseResult> {
  const documents = await deps.repos.knowledgeDocuments.listLatest({ documentType: 'TXT' });
  // Case memory = documents carrying ctf metadata (§37 separation).
  const allLatest = [
    ...documents,
    ...(await deps.repos.knowledgeDocuments.listLatest({ documentType: 'MARKDOWN' })),
    ...(await deps.repos.knowledgeDocuments.listLatest({ documentType: 'HTML' })),
  ];
  const cases = allLatest.filter((doc) => doc.ctf !== null).slice(0, 500);
  const notes: string[] = [];

  let queryText = request.observation;
  if (request.retrieval_mode === 'EXACT_CASE_RETRIEVAL') {
    queryText = request.observation;
    notes.push('EXACT_CASE_RETRIEVAL is for benchmark evaluation; autonomous engagements use PATTERN_RETRIEVAL (§102)');
  } else {
    const concepts = ctfConceptList(request.observation);
    if (concepts.length > 0) {
      queryText = `${request.observation} ${concepts.join(' ')}`;
      notes.push(`Clue concepts expanded: ${concepts.slice(0, 8).join(', ')}`);
    }
  }
  if (request.hypothesis_category) {
    queryText += ` ${request.hypothesis_category}`;
  }
  if (request.technology) {
    queryText += ` ${request.technology}`;
  }
  if (request.workflow_description) {
    queryText += ` ${request.workflow_description}`;
  }

  const scored = cases
    .map((doc) => {
      const ctf = doc.ctf!;
      const haystack = `${ctf.challenge_name} ${ctf.description} ${ctf.technique ?? ''} ${ctf.category ?? ''}`;
      let score = jaccardText(queryText, haystack);
      if (request.retrieval_mode === 'EXACT_CASE_RETRIEVAL') {
        const nameMatch = ctf.challenge_name.toLowerCase().includes(request.observation.toLowerCase().slice(0, 60));
        if (nameMatch) score = Math.min(1, score + 0.5);
      } else {
        // Clue-word concept hits (§100: "old" → legacy API, stale session...).
        for (const { concepts } of ctfClueConcepts(request.observation)) {
          if (concepts.some((concept) => haystack.toLowerCase().includes(concept))) score = Math.min(1, score + 0.25);
        }
      }
      return { doc, ctf, score };
    })
    .filter((entry) => entry.score > 0.05)
    .sort((a, b) => b.score - a.score)
    .slice(0, request.max_results);

  const results: SimilarCase[] = scored.map(({ doc, ctf, score }) => ({
    document_id: doc.id,
    title: doc.title,
    url: doc.canonical_url,
    source_name: '',
    trust_level: doc.trust_level,
    year: ctf.year,
    event: ctf.event,
    category: ctf.category,
    difficulty: ctf.difficulty,
    description_excerpt: ctf.description.slice(0, 1500),
    technique: ctf.technique,
    solution_summary: ctf.solution_summary?.slice(0, 1500) ?? null,
    relevance: Math.round(score * 1000) / 1000,
  }));

  // Fill source names.
  const sources = await deps.repos.knowledgeSources.list({ limit: 500 });
  const nameById = new Map(sources.map((source) => [source.id, source.name]));
  for (const result of results) {
    const doc = scored.find((entry) => entry.doc.id === result.document_id)?.doc;
    result.source_name = doc ? (nameById.get(doc.source_id) ?? 'unknown source') : 'unknown source';
  }

  if (results.length === 0) {
    notes.push('No similar cases found in case memory — the leader reasons from local observations');
  }
  return { cases: results, retrieval_mode: request.retrieval_mode, notes: [...new Set(notes)].slice(0, 8) };
}
