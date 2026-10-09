/**
 * Security technique model + knowledge-to-test translation (spec Part 5
 * §43-§46, §110).
 *
 * Techniques describe WHY to test, WHEN to test, WHAT signal matters, WHAT
 * evidence confirms it and WHAT alternatives exist (§44). The technique
 * model is a recommendation surface only — knowledge never executes
 * actions (§47): execution remains leader → task → policy → worker → tool.
 */
import type { Repositories } from '@aegis/database';
import type { RetrievedTechnique, SecurityTechniqueRecord } from '@aegis/contracts';
import type { SecurityTaxonomyCategory } from '@aegis/shared';
import { jaccardText } from './similarity.js';

export interface TechniqueMatchInput {
  query: string;
  categories: SecurityTaxonomyCategory[];
  technologies: string[];
  maxResults: number;
}

export interface TechniqueDeps {
  repos: Repositories;
}

function toRetrieved(record: SecurityTechniqueRecord, relevantBecause: string): RetrievedTechnique {
  return {
    technique_id: record.id,
    name: record.name,
    category: record.category,
    description: record.description.slice(0, 2000),
    preconditions: record.preconditions.slice(0, 8),
    signals: record.signals.slice(0, 8),
    test_patterns: record.test_patterns.slice(0, 8),
    verification_patterns: record.verification_patterns.slice(0, 8),
    false_positive_conditions: record.false_positive_conditions.slice(0, 8),
    confidence: record.confidence,
    relevant_because: relevantBecause.slice(0, 1000),
    suggested_evidence: suggestedEvidenceFor(record),
    alternative_explanations: alternativeExplanationsFor(record),
  };
}

/** Deterministic suggested-evidence mapping (§46). */
function suggestedEvidenceFor(record: SecurityTechniqueRecord): string[] {
  const evidence: string[] = [];
  if (record.category === 'AUTHORIZATION') {
    evidence.push('same object requested under two distinct authenticated identities');
  }
  if (record.category === 'AUTHENTICATION') {
    evidence.push('authentication boundary response recorded for invalid and valid credentials');
  }
  if (record.category === 'SESSION') {
    evidence.push('session cookie attributes observed and cross-identity session reuse compared');
  }
  if (record.category === 'INJECTION') {
    evidence.push('structurally mutated request and the raw response recorded side by side');
  }
  for (const pattern of record.verification_patterns.slice(0, 3)) {
    evidence.push(pattern);
  }
  return [...new Set(evidence)].slice(0, 8);
}

/** Deterministic alternative-explanation mapping (§46 — skeptical by design). */
function alternativeExplanationsFor(record: SecurityTechniqueRecord): string[] {
  const alternatives: string[] = [...record.false_positive_conditions];
  if (record.category === 'AUTHORIZATION') {
    alternatives.push('shared object visibility', 'public object by design', 'response caching');
  }
  if (record.category === 'AUTHENTICATION') {
    alternatives.push('credential misconfiguration', 'rate limiting behaviour');
  }
  if (record.category === 'INJECTION') {
    alternatives.push('input rejected before evaluation', 'WAF/normalization artefact');
  }
  if (alternatives.length === 0) {
    alternatives.push('observation may be expected application behaviour');
  }
  return [...new Set(alternatives)].slice(0, 8);
}

/**
 * Match techniques for a query (§46). Deterministic: category filter +
 * lexical similarity + confidence. The output feeds the knowledge packet's
 * technique section.
 */
export async function matchTechniques(
  deps: TechniqueDeps,
  input: TechniqueMatchInput,
): Promise<RetrievedTechnique[]> {
  const categories = input.categories.length > 0 ? input.categories : null;
  const pool = categories
    ? (
        await Promise.all(
          categories.slice(0, 4).map((category) => deps.repos.securityTechniques.listByCategory(category, 100)),
        )
      ).flat()
    : await deps.repos.securityTechniques.list(500);

  const scored = pool
    .map((record) => {
      const haystack = `${record.name} ${record.description} ${record.signals.join(' ')} ${record.test_patterns.join(' ')}`;
      let score = jaccardText(input.query, haystack) + record.confidence * 0.15;
      if (input.technologies.length > 0) {
        const lowered = haystack.toLowerCase();
        const hits = input.technologies.filter((tech) => lowered.includes(tech.toLowerCase())).length;
        score += hits * 0.05;
      }
      return { record, score };
    })
    .filter((entry) => entry.score > 0.08)
    .sort((a, b) => b.score - a.score)
    .slice(0, input.maxResults);

  return scored.map(({ record, score }) =>
    toRetrieved(
      record,
      `matched the query (similarity ${Math.round(score * 100) / 100}); category ${record.category}; confidence ${record.confidence}`,
    ),
  );
}

/**
 * Knowledge-to-test translation example (§46): a technique becomes a
 * structured recommendation — never an executed test.
 */
export function techniqueRecommendation(technique: RetrievedTechnique): {
  technique: string;
  relevant_because: string;
  suggested_evidence: string[];
  alternative_explanations: string[];
} {
  return {
    technique: technique.name,
    relevant_because: technique.relevant_because,
    suggested_evidence: technique.suggested_evidence,
    alternative_explanations: technique.alternative_explanations,
  };
}
