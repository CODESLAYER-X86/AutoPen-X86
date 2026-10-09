/**
 * CTF challenge memory (spec Part 6 §4, §34, §67 case-memory layer).
 *
 * Retrieves similar challenges via the Part 5 knowledge engine (case
 * memory / CTF write-ups). Retrieved cases are ADVISORY: they recommend
 * candidate techniques and interpretations; they never directly create a
 * target action without policy validation (§34), and their content stays
 * untrusted when rendered to models.
 */
import type { CtfInterpretation } from '@aegis/contracts';
import type { KnowledgePort } from '../engine/ports.js';

export interface SimilarChallenge {
  title: string;
  similarity: number;
  patterns: string[];
  source: string;
}

export interface ChallengeMemoryResult {
  cases: SimilarChallenge[];
  suggestedTechniques: string[];
  notes: string[];
}

export class ChallengeMemory {
  constructor(private readonly knowledge: KnowledgePort) {}

  /**
   * Retrieve similar cases for a challenge description (§67 case memory:
   * previous challenges — a distinct layer from engagement memory).
   */
  async similarChallenges(challengeText: string, maxResults = 5): Promise<ChallengeMemoryResult> {
    try {
      const result = await this.knowledge.similarCases(
        { observation: challengeText.slice(0, 2000), max_results: maxResults },
        'ctf-engine',
      );
      return {
        cases: result.cases.map((c) => ({
          title: c.title,
          similarity: c.relevance,
          patterns: c.technique ? [c.technique] : [],
          source: c.source_name,
        })),
        suggestedTechniques: [],
        notes: result.notes ?? [],
      };
    } catch {
      return { cases: [], suggestedTechniques: [], notes: ['case memory unavailable'] };
    }
  }

  /**
   * Knowledge retrieval for candidate concepts (§29 pipeline step:
   * KNOWLEDGE RETRIEVAL). Concepts with retrieved local knowledge gain a
   * confidence bump (bounded); concepts without stay untouched.
   */
  async corroborateInterpretations(
    interpretations: CtfInterpretation[],
    maxResults = 3,
  ): Promise<CtfInterpretation[]> {
    const out: CtfInterpretation[] = [];
    for (const interpretation of interpretations.slice(0, 6)) {
      try {
        const packet = await this.knowledge.search(
          { query: `CTF technique: ${interpretation.concept}`, max_results: maxResults },
          'ctf-engine',
        );
        const corroborated = packet.results.length > 0;
        out.push({
          ...interpretation,
          confidence: Math.min(
            0.9,
            corroborated ? interpretation.confidence + 0.1 : interpretation.confidence,
          ),
          rationale: corroborated
            ? `${interpretation.rationale}; local knowledge retrieval found ${packet.results.length} corroborating references`
            : `${interpretation.rationale}; no local corroboration found`,
        });
      } catch {
        out.push(interpretation);
      }
    }
    return out;
  }
}
