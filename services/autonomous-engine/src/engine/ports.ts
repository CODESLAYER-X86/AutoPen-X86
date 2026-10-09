/**
 * Structural ports for the autonomous engine (spec Part 6 §5, §34, §26).
 *
 * The engine depends on PORTS, not service instances: the composition root
 * injects the Part 4 reasoning engine and the Part 5 knowledge engine
 * through these interfaces. This keeps @aegis/autonomous decoupled from
 * @aegis/reasoning / @aegis/knowledge package internals (the same pattern
 * @aegis/agent uses with SecurityContextProvider).
 */
import type { HypothesisCandidate, TestCandidate, VerificationRecord } from '@aegis/contracts';

/**
 * §16: Part 4 candidate groups (structural mirror of the reasoning engine's
 * HypothesisGroup — primary + competitors + distinguishing tests).
 */
export interface HypothesisGroup {
  signalId: string;
  signalType: string;
  primary: HypothesisCandidate;
  competitors: HypothesisCandidate[];
  distinguishingTests: string[];
}

/** §26/§72-§74: verification port (Part 4 SecurityReasoningEngine). */
export interface ReasoningPort {
  ingest(engagementId: string, limit?: number): Promise<unknown>;
  hypothesisCandidates(engagementId: string): Promise<HypothesisGroup[]>;
  markSignalsConsumed(signalIds: string[]): Promise<void>;
  testCandidates(engagementId: string): Promise<{ items: TestCandidate[]; total: number }>;
  verify(input: {
    engagementId: string;
    hypothesisId: string;
    endpointId?: string | null;
  }): Promise<{
    verification: VerificationRecord;
    outcome: {
      kind: string;
      status: 'VERIFIED' | 'REFUTED' | 'INCONCLUSIVE';
      checklist: Array<{ check: string; status: string; detail: string; evidence_ids: string[] }>;
      alternatives: Array<{ explanation: string; refuted: boolean; detail: string }>;
      result: Record<string, unknown>;
      evidenceIds: string[];
    };
  }>;
  compareDifferential(input: {
    engagementId: string;
    baselineRequestId: string;
    candidateRequestId: string;
    hypothesisId?: string | null;
    testId?: string | null;
  }): Promise<{
    recordId: string;
    summary: {
      status_changed: boolean;
      status_baseline: number | null;
      status_candidate: number | null;
      headers_changed: string[];
      schema_changed: boolean;
      fields_added: string[];
      fields_removed: string[];
      values_changed: Array<{ path: string; baseline: string; candidate: string; volatile: boolean }>;
      body_similarity: number;
      redirect_changed: boolean;
      timing_changed: boolean;
      volatile_fields: string[];
    };
  }>;
}

/** §34: knowledge port (Part 5 KnowledgeEngine). */
export interface KnowledgePort {
  search(
    request: { query: string; engagement_id?: string | null; max_results?: number; mode?: string },
    requestedBy?: string,
  ): Promise<{
    query_id: string;
    results: Array<{ chunk_id: string; source_name: string; title: string; trust_level: string; content: string; relevance?: number }>;
    techniques: Array<{ name: string; category: string }>;
    packet_tokens: number;
    notes: string[];
  }>;
  similarCases(
    request: {
      engagement_id?: string | null;
      observation: string;
      hypothesis_category?: string | null;
      technology?: string | null;
      workflow_description?: string | null;
      retrieval_mode?: 'PATTERN_RETRIEVAL' | 'EXACT_CASE_RETRIEVAL';
      max_results?: number;
    },
    requestedBy?: string,
  ): Promise<{
    cases: Array<{
      document_id: string;
      title: string;
      url: string;
      source_name: string;
      trust_level: string;
      year: number | null;
      event: string | null;
      category: string | null;
      difficulty: string | null;
      description_excerpt: string;
      technique: string | null;
      solution_summary: string | null;
      relevance: number;
    }>;
    retrieval_mode: string;
    notes: string[];
  }>;
}

/** Engagement lifecycle completion (Part 2 EngagementController). */
export interface EngagementCompletionPort {
  complete(engagementId: string, actorId: string | null, reason: string): Promise<void>;
  fail(engagementId: string, actorId: string | null, reason: string): Promise<void>;
}
