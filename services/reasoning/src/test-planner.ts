/**
 * Test planner (spec §47-§50, §100, §118, §131).
 *
 * Selects tests that DISTINGUISH hypotheses (§47): expected information gain
 * is computed deterministically from how many competing-hypothesis pairs the
 * test separates. Preconditions are checked (§49). Fingerprints avoid
 * duplicates (§50). The Part 2 scheduler remains responsible for execution
 * (§118-§119) — this module only outputs candidates.
 */
import { createHash } from 'node:crypto';
import type { TestCandidate } from '@aegis/contracts';
import type { MutationCategory } from '@aegis/shared';
import type {
  AuthorizationMatrixRecord,
  EndpointRecord,
  HypothesisRecord,
  ObjectCandidateRecord,
  ParameterRecord,
} from '@aegis/database';
import { generateMutations, type MutationStrategyContext } from './mutation-strategies.js';

export interface TestPlanInput {
  engagementId: string;
  hypotheses: HypothesisRecord[];
  endpoints: EndpointRecord[];
  matrix: AuthorizationMatrixRecord[];
  objects: ObjectCandidateRecord[];
  parametersByEndpoint: Map<string, ParameterRecord[]>;
  identities: Array<{ id: string; name: string; role: string }>;
  /** Existing test fingerprints (duplicate precondition, §49). */
  existingFingerprints: Set<string>;
  allowDestructive: boolean;
}

export interface TestPlanResult {
  candidates: TestCandidate[];
  stopRecommendations: Array<{
    recommendation: 'NO_ACTIONABLE_HYPOTHESES' | 'REQUIRES_IDENTITY' | 'SUFFICIENT_EVIDENCE';
    detail: string;
  }>;
}

export function testFingerprint(input: {
  hypothesisId: string | null;
  endpointFingerprint: string;
  identity: string;
  mutationCategory: string;
  relevantParameter: string;
}): string {
  const canonical = JSON.stringify({
    h: input.hypothesisId ?? 'none',
    e: input.endpointFingerprint,
    i: input.identity.trim().toLowerCase(),
    m: input.mutationCategory,
    p: input.relevantParameter.trim().toLowerCase().replace(/\/+$/, ''),
  });
  return createHash('sha256').update(canonical).digest('hex').slice(0, 40);
}

/**
 * Expected information gain (§47): fraction of competing-hypothesis pairs
 * the candidate test separates, based on predicted outcomes per hypothesis
 * type. Deterministic and explainable.
 */
export function expectedInformationGain(
  hypothesisTypes: string[],
  testKind: 'ANONYMOUS_REPLAY' | 'CROSS_IDENTITY_REPLAY' | 'BASELINE_STABILITY' | 'MUTATION',
): number {
  if (hypothesisTypes.length < 2) return 0.3;
  let separated = 0;
  let pairs = 0;
  for (let i = 0; i < hypothesisTypes.length; i += 1) {
    for (let j = i + 1; j < hypothesisTypes.length; j += 1) {
      pairs += 1;
      const predictionA = predictOutcome(hypothesisTypes[i]!, testKind);
      const predictionB = predictOutcome(hypothesisTypes[j]!, testKind);
      if (predictionA !== predictionB) separated += 1;
    }
  }
  return pairs === 0 ? 0.5 : separated / pairs;
}

/**
 * Deterministic outcome predictions per hypothesis interpretation.
 * AUTHORIZATION failure -> non-owner access succeeds;
 * intentional public    -> anonymous access succeeds;
 * CONFIGURATION (cache) -> byte-stable repeats, cache headers;
 * others                -> depends (INCONCLUSIVE-lean).
 */
function predictOutcome(hypothesisType: string, testKind: string): string {
  switch (hypothesisType) {
    case 'AUTHORIZATION':
      return testKind === 'ANONYMOUS_REPLAY' ? 'DENIED' : 'ALLOWED';
    case 'CONFIGURATION':
      return testKind === 'BASELINE_STABILITY' ? 'IDENTICAL' : 'ALLOWED';
    case 'DATA_EXPOSURE':
      return 'EXPOSED';
    case 'BUSINESS_LOGIC':
      return testKind === 'MUTATION' ? 'ACCEPTED' : 'DENIED';
    case 'CLIENT_SIDE':
      return 'REFLECTED';
    default:
      return 'INCONCLUSIVE';
  }
}

/** Plan candidate tests for the engagement (§118 shape). */
export function planTests(input: TestPlanInput): TestPlanResult {
  const candidates: TestCandidate[] = [];
  const actionable = input.hypotheses.filter((hypothesis) =>
    ['PROPOSED', 'ACTIVE', 'TESTING', 'SUPPORTED'].includes(hypothesis.status),
  );

  const stopRecommendations: TestPlanResult['stopRecommendations'] = [];
  if (actionable.length === 0) {
    stopRecommendations.push({
      recommendation: 'NO_ACTIONABLE_HYPOTHESES',
      detail: 'No active hypotheses to distinguish — ingest more observations or create hypotheses from signals',
    });
  }
  const authzHypotheses = actionable.filter((hypothesis) => hypothesis.type === 'AUTHORIZATION');
  const identityCount = input.identities.length;
  if (authzHypotheses.length > 0 && identityCount < 2) {
    stopRecommendations.push({
      recommendation: 'REQUIRES_IDENTITY',
      detail: 'Cross-identity testing needs at least two identities; only one is registered',
    });
  }

  for (const hypothesis of actionable.slice(0, 12)) {
    // Focus on endpoints referenced by the matrix with object-level entries.
    const relevantEndpoints = selectEndpoints(hypothesis, input);
    for (const endpoint of relevantEndpoints.slice(0, 3)) {
      const parameters = input.parametersByEndpoint.get(endpoint.id) ?? [];
      const relevantParameter = parameters.find((parameter) =>
        parameter.semantic_candidates.some((candidate) => candidate.semantic === 'IDENTIFIER'),
      );
      const familyTypes = collectFamilyTypes(hypothesis, actionable);
      const siblingTypes = familyTypes.length >= 2 ? familyTypes : [hypothesis.type, 'AUTHORIZATION'];

      // 1. Cross-identity replay (§61) — the primary authz discriminator.
      if (identityCount >= 2 && (hypothesis.type === 'AUTHORIZATION' || hypothesis.type === 'BUSINESS_LOGIC')) {
        const baselineIdentity = pickIdentity(input.matrix, endpoint.id, 'ALLOWED') ?? input.identities[0]?.id ?? null;
        const candidateIdentity =
          input.identities.find((identity) => identity.id !== baselineIdentity)?.id ?? null;
        if (baselineIdentity && candidateIdentity) {
          const fingerprint = testFingerprint({
            hypothesisId: hypothesis.id,
            endpointFingerprint: endpoint.fingerprint,
            identity: `${baselineIdentity}->${candidateIdentity}`,
            mutationCategory: 'AUTHORIZATION',
            relevantParameter: relevantParameter?.name ?? '',
          });
          const baselineRequestId = findLatestRequest(input.matrix, endpoint.id, baselineIdentity);
          candidates.push({
            hypothesis_id: hypothesis.id,
            test_type: 'IDENTITY_COMPARISON',
            endpoint_id: endpoint.id,
            baseline_identity: baselineIdentity,
            candidate_identity: candidateIdentity,
            mutation_category: 'AUTHORIZATION',
            base_request_id: baselineRequestId,
            mutations: [],
            expected_information_gain: expectedInformationGain(siblingTypes, 'CROSS_IDENTITY_REPLAY'),
            estimated_cost: 2,
            priority: combine(hypothesis.priority, 0.8),
            fingerprint,
            preconditions: {
              scope_ok: true,
              identity_available: true,
              baseline_available: baselineRequestId !== null,
              duplicate_absent: !input.existingFingerprints.has(fingerprint),
            },
            rationale: `Distinguishes authorization-failure from shared/public access interpretations on ${endpoint.canonical_path} (spec §47)`,
          });
        }
      }

      // 2. Anonymous replay — distinguishes public-object interpretations (§47).
      const anonFingerprint = testFingerprint({
        hypothesisId: hypothesis.id,
        endpointFingerprint: endpoint.fingerprint,
        identity: 'ANONYMOUS',
        mutationCategory: 'AUTHENTICATION',
        relevantParameter: relevantParameter?.name ?? '',
      });
      candidates.push({
        hypothesis_id: hypothesis.id,
        test_type: 'ANONYMOUS_ACCESS',
        endpoint_id: endpoint.id,
        baseline_identity: pickIdentity(input.matrix, endpoint.id, 'ALLOWED'),
        candidate_identity: null,
        mutation_category: 'AUTHENTICATION',
        base_request_id: findLatestRequest(input.matrix, endpoint.id, null) ?? findLatestRequest(input.matrix, endpoint.id, pickIdentity(input.matrix, endpoint.id, 'ALLOWED')),
        mutations: [],
        expected_information_gain: expectedInformationGain(siblingTypes, 'ANONYMOUS_REPLAY'),
        estimated_cost: 1,
        priority: combine(hypothesis.priority, 0.7),
        fingerprint: anonFingerprint,
        preconditions: {
          scope_ok: true,
          identity_available: true,
          baseline_available: true,
          duplicate_absent: !input.existingFingerprints.has(anonFingerprint),
        },
        rationale: 'Anonymous access separates the public-object/shared-access interpretations from authorization failures (spec §47)',
      });

      // 3. Structural mutations when parameters are rich (§51, §54).
      if (parameters.length > 0 && (hypothesis.type === 'BUSINESS_LOGIC' || hypothesis.type === 'INPUT_VALIDATION' || hypothesis.type === 'AUTHORIZATION')) {
        const context: MutationStrategyContext = {
          canonicalPath: endpoint.canonical_path,
          observedUrl: endpoint.observed_urls[0] ?? endpoint.path,
          parameters,
          objectValues: input.objects
            .filter((object) => object.endpoint_id === endpoint.id || object.endpoint_id === null)
            .flatMap((object) => object.example_values.map((value) => ({ name: object.name, value })))
            .slice(0, 16),
          identityOptions: input.identities.map((identity) => ({
            identityId: identity.id,
            label: `${identity.name} (${identity.role || identity.id})`,
          })),
          allowDestructive: input.allowDestructive,
        };
        const category: MutationCategory =
          hypothesis.type === 'BUSINESS_LOGIC' ? 'BOUNDARY' : relevantParameter ? 'IDENTIFIER' : 'STRUCTURE';
        const plans = generateMutations(category, context).slice(0, 2);
        for (const plan of plans) {
          const fingerprint = testFingerprint({
            hypothesisId: hypothesis.id,
            endpointFingerprint: endpoint.fingerprint,
            identity: plan.identityId ?? 'BASELINE',
            mutationCategory: category,
            relevantParameter: relevantParameter?.name ?? '',
          });
          candidates.push({
            hypothesis_id: hypothesis.id,
            test_type: 'STRUCTURED_MUTATION',
            endpoint_id: endpoint.id,
            baseline_identity: plan.identityId,
            candidate_identity: null,
            mutation_category: category,
            base_request_id: findLatestRequest(input.matrix, endpoint.id, plan.identityId),
            mutations: plan.mutations,
            expected_information_gain: expectedInformationGain(siblingTypes, 'MUTATION'),
            estimated_cost: Math.max(1, plan.mutations.length),
            priority: combine(hypothesis.priority, 0.6),
            fingerprint,
            preconditions: {
              scope_ok: true,
              identity_available: true,
              baseline_available: true,
              duplicate_absent: !input.existingFingerprints.has(fingerprint),
            },
            rationale: plan.description,
          });
        }
      }
    }
  }

  const deduped = dedupeByFingerprint(candidates);
  return {
    candidates: deduped
      .filter((candidate) => candidate.preconditions.duplicate_absent)
      .sort((a, b) => b.priority - a.priority)
      .slice(0, 16),
    stopRecommendations,
  };
}

function selectEndpoints(hypothesis: HypothesisRecord, input: TestPlanInput): EndpointRecord[] {
  // Prefer endpoints with object-level matrix rows and high signal counts —
  // deterministic prioritization per §84-§85 (full ranking in prioritization.ts).
  const withObjectLevel = input.endpoints.filter((endpoint) =>
    input.matrix.some(
      (entry) => entry.endpoint_id === endpoint.id && entry.object_ref !== null && entry.outcome === 'ALLOWED',
    ),
  );
  if (withObjectLevel.length > 0) {
    return [...withObjectLevel].sort((a, b) => b.signal_count - a.signal_count || b.observation_count - a.observation_count);
  }
  return [...input.endpoints].sort((a, b) => b.signal_count - a.signal_count || b.observation_count - a.observation_count);
}

function collectFamilyTypes(hypothesis: HypothesisRecord, all: HypothesisRecord[]): string[] {
  // Sibling competing interpretations: same engagement, non-terminal,
  // overlapping types around the same target. Simplification: distinct types
  // among actionable hypotheses (bounded).
  const types = new Set<string>([hypothesis.type]);
  for (const other of all) {
    if (other.id !== hypothesis.id && other.type !== hypothesis.type) types.add(other.type);
  }
  return [...types].slice(0, 6);
}

function pickIdentity(
  matrix: AuthorizationMatrixRecord[],
  endpointId: string,
  outcome: string,
): string | null {
  const entry = matrix.find(
    (candidate) => candidate.endpoint_id === endpointId && candidate.outcome === outcome && candidate.identity_id !== null,
  );
  return entry?.identity_id ?? null;
}

function findLatestRequest(
  matrix: AuthorizationMatrixRecord[],
  endpointId: string,
  identityId: string | null,
): string | null {
  const entry = matrix.find(
    (candidate) =>
      candidate.endpoint_id === endpointId &&
      (candidate.identity_id ?? null) === (identityId ?? null) &&
      candidate.request_id !== null,
  );
  return entry?.request_id ?? null;
}

function combine(hypothesisPriority: number, testValue: number): number {
  return Math.min(1, Math.max(0, hypothesisPriority * 0.6 + testValue * 0.4));
}

function dedupeByFingerprint(candidates: TestCandidate[]): TestCandidate[] {
  const seen = new Set<string>();
  const result: TestCandidate[] = [];
  for (const candidate of candidates) {
    if (seen.has(candidate.fingerprint)) continue;
    seen.add(candidate.fingerprint);
    result.push(candidate);
  }
  return result;
}
