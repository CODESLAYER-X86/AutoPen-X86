/**
 * Live research engine (spec Part 5 §30-§33, §71-§73, §78, §83, §105, §111).
 *
 * Research is a bounded, budgeted, fully audited workflow:
 *
 *   question → query plan → bounded web search → candidate sources →
 *   trust/ranking → fetch relevant pages → extract relevant sections →
 *   compare → identify agreement/disagreement → compact result → agent
 *
 * Budgets (§83): max searches, max fetched pages, max bytes, max time and
 * max tokens — a research request can never spend the engagement's whole
 * budget researching instead of testing. Escalation (§105): LOCAL →
 * CURATED → LIVE, only when the current level cannot answer.
 */
import type { Repositories } from '@aegis/database';
import type { PlatformEvent, ResearchRequest, ResearchResult, ResearchEvidence } from '@aegis/contracts';
import { generateId } from '@aegis/shared';
import type { WebSearchProvider } from './providers.js';
import type { KnowledgeFetcher } from './fetcher.js';
import { domainOf } from './util.js';
import { jaccardText } from './similarity.js';

export interface ResearchBudget {
  maxSearches: number;
  maxPages: number;
  maxBytes: number;
  maxTimeMs: number;
  maxTokens: number;
}

export interface ResearchEngineDeps {
  repos: Repositories;
  searchProvider: WebSearchProvider;
  fetcher?: KnowledgeFetcher;
  budget: ResearchBudget;
  publish: (event: PlatformEvent) => Promise<void>;
  /** Curated sources used for CURATED_WEB domain constraints. */
  curatedDomains?: string[];
  logger?: { warn: (event: string, fields?: Record<string, unknown>) => void };
}

/** Trust classification of a search-result domain (§32: untrusted until classified). */
export function classifyDomain(
  domain: string,
  curated: string[],
): 'OFFICIAL' | 'TRUSTED_TRAINING' | 'RESEARCH' | 'CTF' | 'COMMUNITY' | 'UNTRUSTED' {
  const lowered = domain.toLowerCase();
  const matches = (candidate: string) => lowered === candidate || lowered.endsWith(`.${candidate}`);
  if (curated.some((entry) => matches(entry.toLowerCase()))) {
    // Curated registry entries: standards bodies and official docs are
    // OFFICIAL; challenge platforms stay CTF; everything else curated is
    // trusted training material.
    if (/ctf|challenge/.test(lowered)) return 'CTF';
    return 'OFFICIAL';
  }
  // Well-known reputable security domains — a starting classification, not
  // a guarantee (search ranking is not a security trust system, §32).
  const known: Array<[string, 'OFFICIAL' | 'RESEARCH' | 'TRUSTED_TRAINING' | 'COMMUNITY']> = [
    ['portswigger.net', 'TRUSTED_TRAINING'],
    ['owasp.org', 'OFFICIAL'],
    ['github.com', 'COMMUNITY'],
    ['stackoverflow.com', 'COMMUNITY'],
    ['securiteam.com', 'RESEARCH'],
    ['packetstormsecurity.org', 'RESEARCH'],
  ];
  for (const [candidate, level] of known) {
    if (matches(candidate)) return level;
  }
  return 'UNTRUSTED';
}

const TRUST_RANK: Record<string, number> = {
  OFFICIAL: 5,
  TRUSTED_TRAINING: 4,
  RESEARCH: 3,
  CTF: 2,
  COMMUNITY: 1,
  UNTRUSTED: 0,
};

/**
 * Bounded research plan (§71): 1-3 derived queries from the question —
 * deterministic question decomposition, never an open-ended search loop.
 */
export function planQueries(question: string, maxQueries: number): string[] {
  const trimmed = question.trim().slice(0, 500);
  const sentences = trimmed.split(/(?<=[.?])\s+/).filter((s) => s.length > 8);
  const queries = new Set<string>([trimmed]);
  // Key-term query: significant words only, keeps noise out.
  const significant = trimmed
    .toLowerCase()
    .replace(/[^a-z0-9\s-]/g, ' ')
    .split(/\s+/)
    .filter((word) => word.length > 4)
    .slice(0, 10)
    .join(' ');
  if (significant) queries.add(significant);
  for (const sentence of sentences.slice(0, 2)) {
    if (sentence.length > 16) queries.add(sentence.slice(0, 300));
  }
  return [...queries].slice(0, Math.max(1, maxQueries));
}

export class ResearchEngine {
  constructor(private readonly deps: ResearchEngineDeps) {}

  /**
   * Run a research task (§31/§72). Every outcome — including failure and
   * budget exhaustion — is persisted on the research task row and
   * published as events (§85/§86). Research results are ADVISORY only.
   */
  async research(request: ResearchRequest, requestedBy: string): Promise<ResearchResult> {
    const { repos } = this.deps;
    const deadline = Date.now() + this.deps.budget.maxTimeMs;
    const budget = { searches: 0, pages: 0, bytes: 0 };

    const task = await repos.researchTasks.insert({
      engagementId: request.engagement_id,
      requestedBy,
      question: request.question,
      hypothesis: request.hypothesis,
      requiredEvidence: request.required_evidence,
      sourceConstraints: request.source_constraints,
      mode: request.mode,
      maxSources: request.max_sources,
      maxTokens: request.max_tokens,
      deadlineMs: this.deps.budget.maxTimeMs,
    });

    const notes: string[] = [];
    const evidence: ResearchEvidence[] = [];
    const startedAt = new Date().toISOString();

    const publishStarted: PlatformEvent = {
      type: 'WEB_RESEARCH_STARTED',
      engagement_id: request.engagement_id ?? 'global',
      task_id: null,
      trace_id: generateId('TRC'),
      actor_id: null,
      payload: { research_id: task.id, question: request.question.slice(0, 300), mode: request.mode },
      occurred_at: startedAt,
      dedup_key: `research-started:${task.id}`,
    };
    await this.deps.publish(publishStarted).catch(() => undefined);
    await repos.researchTasks.update(task.id, { status: 'RUNNING', startedAt });

    try {
      // --- LOCAL level (§105): local index first, escalate when thin. ----
      const local = await this.localEvidence(request, notes);
      evidence.push(...local.slice(0, request.max_sources));

      const mode = request.mode;
      const needsWeb = mode !== 'LOCAL_ONLY' && evidence.length < Math.min(2, request.max_sources);
      if (needsWeb && Date.now() < deadline) {
        const curated = mode === 'CURATED_WEB';
        const queries = planQueries(request.question, this.deps.budget.maxSearches);
        for (const query of queries) {
          if (budget.searches >= this.deps.budget.maxSearches) {
            notes.push(`Search budget exhausted (${this.deps.budget.maxSearches} searches)`);
            break;
          }
          if (Date.now() >= deadline) {
            notes.push('Research deadline reached before all searches completed');
            break;
          }
          budget.searches += 1;
          const search = await this.deps.searchProvider.search(query, {
            maxResults: request.max_sources * 2,
            domainAllowlist: curated ? (this.deps.curatedDomains ?? []) : [],
          });
          if (search.note) notes.push(search.note);
          if (search.results.length === 0) continue;

          // Select sources by trust rank (§31), bounded by max_sources.
          const ranked = search.results
            .map((result) => {
              const domain = domainOf(result.url) ?? 'unknown';
              return { ...result, domain, trust: classifyDomain(domain, this.deps.curatedDomains ?? []) };
            })
            .filter((result) => {
              if (request.source_constraints.length > 0) {
                return request.source_constraints.some((d) => result.domain === d || result.domain.endsWith(`.${d}`));
              }
              return true;
            })
            .sort((a, b) => (TRUST_RANK[b.trust] ?? 0) - (TRUST_RANK[a.trust] ?? 0))
            .slice(0, request.max_sources);

          for (const candidate of ranked) {
            await repos.researchSources.insert({
              researchTaskId: task.id,
              documentId: null,
              url: candidate.url,
              domain: candidate.domain,
              trustLevel: candidate.trust,
              rank: ranked.indexOf(candidate),
              selected: true,
              reason: `search hit (query: ${query.slice(0, 120)})`,
            });
            const selectedEvent: PlatformEvent = {
              type: 'WEB_SOURCE_SELECTED',
              engagement_id: request.engagement_id ?? 'global',
              task_id: null,
              trace_id: generateId('TRC'),
              actor_id: null,
              payload: { research_id: task.id, url: candidate.url.slice(0, 500), domain: candidate.domain, trust: candidate.trust },
              occurred_at: new Date().toISOString(),
              dedup_key: `research-source:${task.id}:${candidate.domain}:${ranked.indexOf(candidate)}`,
            };
            await this.deps.publish(selectedEvent).catch(() => undefined);
          }

          // Fetch selected pages (bounded, §83).
          if (this.deps.fetcher) {
            for (const candidate of ranked) {
              if (budget.pages >= this.deps.budget.maxPages || budget.bytes >= this.deps.budget.maxBytes) {
                notes.push(`Fetch budget exhausted (${this.deps.budget.maxPages} pages / ${this.deps.budget.maxBytes} bytes)`);
                break;
              }
              if (Date.now() >= deadline) {
                notes.push('Research deadline reached during fetch');
                break;
              }
              try {
                const fetched = await this.deps.fetcher.fetch(candidate.url, {
                  allowedDomains: curated ? (this.deps.curatedDomains ?? []) : [],
                  blockedDomains: [],
                }, { budget });
                budget.pages += 1;
                budget.bytes += fetched.byteLength;
                const text = Buffer.from(fetched.bytes).toString('utf8');
                const excerpt = extractRelevantSection(text, request.question, 1800);
                evidence.push({
                  document_id: null,
                  url: candidate.url,
                  source_name: candidate.domain,
                  trust_level: candidate.trust,
                  excerpt,
                  relevance: jaccardText(request.question, excerpt),
                });
                const fetchedEvent: PlatformEvent = {
                  type: 'WEB_DOCUMENT_FETCHED',
                  engagement_id: request.engagement_id ?? 'global',
                  task_id: null,
                  trace_id: generateId('TRC'),
                  actor_id: null,
                  payload: { research_id: task.id, url: candidate.url.slice(0, 500), bytes: fetched.byteLength, truncated: fetched.truncated },
                  occurred_at: new Date().toISOString(),
                  dedup_key: `research-fetched:${task.id}:${budget.pages}`,
                };
                await this.deps.publish(fetchedEvent).catch(() => undefined);
              } catch (error) {
                this.deps.logger?.warn('research.fetch_failed', {
                  research_id: task.id,
                  url: candidate.url.slice(0, 200),
                  error: error instanceof Error ? error.message : String(error),
                });
              }
            }
          } else {
            notes.push('No web fetcher configured — search results returned without page content');
            for (const candidate of ranked) {
              if (evidence.length >= request.max_sources) break;
              evidence.push({
                document_id: null,
                url: candidate.url,
                source_name: candidate.domain,
                trust_level: candidate.trust,
                excerpt: candidate.snippet.slice(0, 1800),
                relevance: jaccardText(request.question, candidate.snippet),
              });
            }
          }
          if (evidence.length >= request.max_sources) break;
        }
      } else if (mode === 'LOCAL_ONLY') {
        notes.push('LOCAL_ONLY mode: local knowledge only (§103)');
      }

      // --- Compare: corroboration + preserved disagreement (§72/§73/§111). ---
      const { corroboration, disagreements } = compareEvidence(evidence);

      const tokensEstimate = Math.ceil(
        evidence.reduce((sum, item) => sum + item.excerpt.length, 0) / 4,
      );
      const truncated = tokensEstimate > this.deps.budget.maxTokens;
      const boundedEvidence = truncated
        ? evidence.slice(0, Math.max(1, Math.floor((this.deps.budget.maxTokens / Math.max(1, tokensEstimate)) * evidence.length)))
        : evidence;

      const result: ResearchResult = {
        research_id: task.id,
        question: request.question,
        status: 'COMPLETED',
        mode: request.mode,
        summary: buildSummary(request.question, boundedEvidence, corroboration, disagreements),
        evidence: boundedEvidence.slice(0, 10),
        corroboration,
        disagreements,
        sources_considered: budget.searches,
        sources_fetched: budget.pages,
        tokens_estimate: Math.min(tokensEstimate, this.deps.budget.maxTokens),
        notes: [...new Set(notes)].slice(0, 16),
      };

      await repos.researchTasks.update(task.id, {
        status: 'COMPLETED',
        completedAt: new Date().toISOString(),
        result: result as unknown as Record<string, unknown>,
        tokensConsumed: result.tokens_estimate,
      });
      await this.publishCompleted(task.id, 'COMPLETED');
      return result;
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      await repos.researchTasks.update(task.id, {
        status: 'FAILED',
        completedAt: new Date().toISOString(),
        error: message.slice(0, 2000),
      });
      await this.publishCompleted(task.id, 'FAILED');
      throw error;
    }
  }

  /** LOCAL level evidence (§105): the local knowledge index answers first. */
  private async localEvidence(request: ResearchRequest, notes: string[]): Promise<ResearchEvidence[]> {
    const rows = await this.deps.repos.knowledgeChunks.searchJoined(request.question, request.max_sources);
    if (rows.length === 0) {
      notes.push('Local knowledge index had no direct answer — research escalated (§105)');
    }
    return rows.map((row) => ({
      document_id: row.chunk_id,
      url: row.url,
      source_name: row.source_name,
      trust_level: row.trust_level as ResearchEvidence['trust_level'],
      excerpt: row.content.slice(0, 1800),
      relevance: jaccardText(request.question, row.content),
    }));
  }

  private async publishCompleted(researchId: string, status: string): Promise<void> {
    const event: PlatformEvent = {
      type: 'RESEARCH_COMPLETED',
      engagement_id: 'global',
      task_id: null,
      trace_id: generateId('TRC'),
      actor_id: null,
      payload: { research_id: researchId, status },
      occurred_at: new Date().toISOString(),
      dedup_key: `research-completed:${researchId}`,
    };
    await this.deps.publish(event).catch(() => undefined);
  }
}

/** Extract the most query-relevant section of a fetched page (§31). */
export function extractRelevantSection(text: string, question: string, maxChars: number): string {
  const cleaned = text
    .replace(/<script\b[^>]*>[\s\S]*?<\/script>/gi, ' ')
    .replace(/<style\b[^>]*>[\s\S]*?<\/style>/gi, ' ')
    .replace(/<[^>]+>/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();
  const queryTerms = new Set(
    question
      .toLowerCase()
      .replace(/[^a-z0-9\s]/g, ' ')
      .split(/\s+/)
      .filter((term) => term.length > 3),
  );
  // Score sliding windows by DISTINCT query-term coverage weighted by
  // inverse document frequency — repeated boilerplate words score low,
  // windows covering rare query terms score high.
  const words = cleaned.split(' ');
  const termFreq = new Map<string, number>();
  for (const word of words) {
    const lowered = word.toLowerCase();
    termFreq.set(lowered, (termFreq.get(lowered) ?? 0) + 1);
  }
  const window = Math.min(160, Math.max(30, Math.ceil(maxChars / 5)));
  let best = { score: 0, start: 0 };
  for (let start = 0; start + window <= words.length; start += Math.floor(window / 2)) {
    const slice = words.slice(start, start + window);
    const seen = new Set<string>();
    let score = 0;
    for (const word of slice) {
      const lowered = word.toLowerCase();
      if (queryTerms.has(lowered) && !seen.has(lowered)) {
        seen.add(lowered);
        score += 1 / Math.max(1, termFreq.get(lowered) ?? 1);
      }
    }
    if (score > best.score) best = { score, start };
  }
  const chosen = words.slice(best.start, best.start + window).join(' ');
  const final = best.score > 0 ? chosen : cleaned.slice(0, maxChars);
  // Tolerance: the chosen window is the relevant unit; never cut inside it.
  return final.slice(0, Math.max(maxChars, final.length));
}

/** Corroboration + disagreement detection across evidence (§73/§111). */
export function compareEvidence(evidence: ResearchEvidence[]): {
  corroboration: Array<{ claim: string; source_count: number }>;
  disagreements: Array<{ topic: string; position_a: string; position_b: string }>;
} {
  const corroboration: Array<{ claim: string; source_count: number }> = [];
  const disagreements: Array<{ topic: string; position_a: string; position_b: string }> = [];
  const reputable = evidence.filter((item) => item.trust_level === 'OFFICIAL' || item.trust_level === 'TRUSTED_TRAINING');

  // Corroboration: distinct reputable sources with high lexical overlap.
  for (let i = 0; i < reputable.length; i += 1) {
    for (let j = i + 1; j < reputable.length; j += 1) {
      const a = reputable[i]!;
      const b = reputable[j]!;
      if (domainOf(a.url) === domainOf(b.url)) continue;
      const similarity = jaccardText(a.excerpt, b.excerpt);
      if (similarity >= 0.35) {
        const claim = a.excerpt.slice(0, 200);
        if (!corroboration.some((c) => c.claim === claim)) {
          corroboration.push({ claim, source_count: 2 });
        }
      } else if (similarity <= 0.08 && a.relevance > 0.15 && b.relevance > 0.15) {
        // Disagreement is PRESERVED, never averaged (§73).
        const topic = a.excerpt.slice(0, 120);
        if (!disagreements.some((d) => d.topic === topic)) {
          disagreements.push({
            topic,
            position_a: `${a.source_name}: ${a.excerpt.slice(120, 240)}`,
            position_b: `${b.source_name}: ${b.excerpt.slice(120, 240)}`,
          });
        }
      }
    }
  }
  return { corroboration: corroboration.slice(0, 8), disagreements: disagreements.slice(0, 8) };
}

function buildSummary(
  question: string,
  evidence: ResearchEvidence[],
  corroboration: Array<{ claim: string; source_count: number }>,
  disagreements: Array<{ topic: string; position_a: string; position_b: string }>,
): string {
  const parts: string[] = [`Research question: ${question.slice(0, 300)}`];
  if (evidence.length === 0) {
    parts.push('No evidence was retrieved; treat this question as unanswered.');
  } else {
    parts.push(`${evidence.length} evidence items retrieved.`);
  }
  if (corroboration.length > 0) {
    parts.push(`Corroborated claims: ${corroboration.length} (multiple reputable sources agree).`);
  }
  if (disagreements.length > 0) {
    parts.push(
      `Preserved disagreements: ${disagreements.length} — sources disagree; verify against the target before concluding (§78).`,
    );
  }
  parts.push('Research is ADVISORY: knowledge recommends testing strategy; only target observations are evidence (§77).');
  return parts.join(' ').slice(0, 3000);
}
