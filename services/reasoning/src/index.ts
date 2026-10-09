/**
 * Security Reasoning Engine composition (spec Part 4 §108, §133).
 *
 * The facade wires the deterministic pipeline: observation ingestion,
 * differential comparison, verification, hypothesis candidates, test
 * candidates, the focused attack-surface query and the leader projection.
 *
 * Part 2 responsibilities (scheduling, quota, worker lifecycle, LLM calls)
 * stay OUTSIDE this engine (§119): it provides security intelligence only.
 */
import { generateId } from '@aegis/shared';
import type {
  DifferentialResult,
  ReasoningQueryResponse,
  SecurityProjection,
  TestCandidateListResponse,
  VerificationEvaluateResponse,
  VerificationRecord,
} from '@aegis/contracts';
import type { Repositories, WorkflowStateRecord } from '@aegis/database';
import type { EventBus } from '@aegis/events';
import type { Logger } from '@aegis/logging';
import { mapRequestRow } from '@aegis/target-http';
import { compareResponses, differentialFingerprint, responseRowToComparison, type DifferentialSummary } from './differential.js';
import { ReasoningEventProcessor, type IngestSummary } from './processor.js';
import { hypothesisGroupsFromSignals, type HypothesisGroup } from './hypothesis-candidates.js';
import { evaluateVerification, deadEndPayload, type VerificationOutcome } from './verification.js';
import { classifyEvidence, reproductionCountFor } from './evidence-strength.js';
import { SecurityProjectionBuilder, planCandidateTests } from './projection.js';
import type { ReasoningLimits } from './limits.js';
import { unusualResponseDifferenceSignal } from './signal-engine.js';

export interface ReasoningEngineDeps {
  repos: Repositories;
  eventBus: EventBus;
  logger?: Pick<Logger, 'info' | 'warn'>;
  limits?: Partial<ReasoningLimits>;
  /** Scope-aware destructive policy for test planning (§49, §132). */
  allowDestructive?: boolean;
}

export class SecurityReasoningEngine {
  readonly processor: ReasoningEventProcessor;
  private readonly repos: Repositories;
  private readonly eventBus: EventBus;
  private readonly logger?: ReasoningEngineDeps['logger'];
  private readonly allowDestructive: boolean;
  private readonly projectionBuilder = new SecurityProjectionBuilder();

  constructor(deps: ReasoningEngineDeps) {
    this.repos = deps.repos;
    this.eventBus = deps.eventBus;
    this.logger = deps.logger;
    this.allowDestructive = deps.allowDestructive ?? false;
    this.processor = new ReasoningEventProcessor({
      repos: deps.repos,
      eventBus: deps.eventBus,
      logger: deps.logger,
      limits: deps.limits,
    });
  }

  // -------------------------------------------------------------------------
  // Ingestion (§110).
  // -------------------------------------------------------------------------

  ingest(engagementId: string, limit = 200): Promise<IngestSummary> {
    return this.processor.backfill(engagementId, limit);
  }

  // -------------------------------------------------------------------------
  // Differential comparison (§25, §118 differential.compare).
  // -------------------------------------------------------------------------

  async compareDifferential(input: {
    engagementId: string;
    baselineRequestId: string;
    candidateRequestId: string;
    hypothesisId?: string | null;
    testId?: string | null;
  }): Promise<{ recordId: string; summary: DifferentialSummary }> {
    const baselineRow = await this.repos.httpRequests.findById(input.baselineRequestId);
    const candidateRow = await this.repos.httpRequests.findById(input.candidateRequestId);
    if (!baselineRow || baselineRow['engagement_id'] !== input.engagementId) {
      throw Object.assign(new Error('baseline request not found for engagement'), { code: 'REQUEST_NOT_FOUND' });
    }
    if (!candidateRow || candidateRow['engagement_id'] !== input.engagementId) {
      throw Object.assign(new Error('candidate request not found for engagement'), { code: 'REQUEST_NOT_FOUND' });
    }
    const baselineResponse = await this.repos.httpResponses.findByRequestId(input.baselineRequestId);
    const candidateResponse = await this.repos.httpResponses.findByRequestId(input.candidateRequestId);
    if (!baselineResponse || !candidateResponse) {
      throw Object.assign(new Error('both requests need recorded responses for comparison'), { code: 'RESPONSE_NOT_FOUND' });
    }

    const baselineRequest = mapRequestRow(baselineRow);
    const candidateIdentity = typeof candidateRow['identity_id'] === 'string' ? (candidateRow['identity_id'] as string) : null;
    const outcome = compareResponses(responseRowToComparison(baselineResponse), responseRowToComparison(candidateResponse));

    const record = await this.repos.differentialResults.insert({
      engagementId: input.engagementId,
      testId: input.testId ?? null,
      hypothesisId: input.hypothesisId ?? null,
      baselineRequestId: input.baselineRequestId,
      candidateRequestId: input.candidateRequestId,
      baselineIdentity: baselineRequest.identity_id,
      candidateIdentity,
      summary: outcome.summary as unknown as Record<string, unknown>,
      detail: outcome.detail,
    });

    // Differential-driven signal (§24-§25): differences are signals, never
    // conclusions (§61).
    const signal = unusualResponseDifferenceSignal({
      endpointId: null,
      baselineIdentity: baselineRequest.identity_id,
      candidateIdentity,
      summary: outcome.summary,
      evidenceIds: [input.baselineRequestId, input.candidateRequestId],
    });
    if (signal) {
      await this.repos.securitySignals
        .insert({
          engagementId: input.engagementId,
          signalType: signal.signalType,
          source: signal.source,
          endpointId: signal.endpointId,
          parameterId: signal.parameterId,
          identityIds: signal.identityIds,
          objectRef: signal.objectRef,
          confidence: signal.confidence,
          summary: signal.summary.slice(0, 2000),
          metadata: signal.metadata,
          evidenceIds: signal.evidenceIds,
          fingerprint: signal.fingerprint,
        })
        .catch(() => undefined);
    }

    await this.eventBus.publish({
      type: 'DIFFERENTIAL_COMPARISON_RECORDED',
      engagement_id: input.engagementId,
      task_id: null,
      trace_id: generateId('TRC'),
      actor_id: null,
      payload: {
        differential_id: record.id,
        baseline_request_id: input.baselineRequestId,
        candidate_request_id: input.candidateRequestId,
        body_similarity: outcome.summary.body_similarity,
        schema_changed: outcome.summary.schema_changed,
        status_changed: outcome.summary.status_changed,
      },
      occurred_at: new Date().toISOString(),
      dedup_key: `differential:${differentialFingerprint(input.baselineRequestId, input.candidateRequestId)}`,
    });

    return { recordId: record.id, summary: outcome.summary };
  }

  // -------------------------------------------------------------------------
  // Hypothesis candidates (§44-§45) — deterministic, competing.
  // -------------------------------------------------------------------------

  async hypothesisCandidates(engagementId: string): Promise<HypothesisGroup[]> {
    const signals = await this.repos.securitySignals.listNew(engagementId, 100);
    return hypothesisGroupsFromSignals(signals);
  }

  async markSignalsConsumed(signalIds: string[]): Promise<void> {
    for (const signalId of signalIds.slice(0, 64)) {
      await this.repos.securitySignals.markStatus(signalId, 'CONSUMED').catch(() => undefined);
    }
  }

  // -------------------------------------------------------------------------
  // Test candidates (§118) — the Part 2 scheduler seam.
  // -------------------------------------------------------------------------

  async testCandidates(engagementId: string): Promise<TestCandidateListResponse> {
    const [hypotheses, endpoints, matrix, objects, identities, tests] = await Promise.all([
      this.repos.hypotheses.listByEngagement(engagementId, {
        statuses: ['PROPOSED', 'ACTIVE', 'TESTING', 'SUPPORTED'],
      }),
      this.repos.endpoints.listByEngagement(engagementId, { limit: 200 }),
      this.repos.authzMatrix.listByEngagement(engagementId, 500),
      this.repos.objectCandidates.listByEngagement(engagementId, 200),
      this.repos.identities.listByEngagement(engagementId),
      this.repos.tests.listByEngagement(engagementId, 200),
    ]);
    const parameterMap = new Map<string, Awaited<ReturnType<typeof this.repos.parameters.listByEndpoint>>>();
    for (const endpoint of endpoints) {
      parameterMap.set(endpoint.id, await this.repos.parameters.listByEndpoint(endpoint.id));
    }
    const existingFingerprints = new Set(tests.map((test) => test.fingerprint));
    const plan = planCandidateTests({
      engagementId,
      hypotheses,
      endpoints,
      matrix,
      objects,
      parametersByEndpoint: parameterMap,
      identities: identities.map((identity) => ({ id: identity.id, name: identity.name, role: identity.role })),
      existingFingerprints,
      allowDestructive: this.allowDestructive,
    });
    return { items: plan.candidates, total: plan.candidates.length };
  }

  // -------------------------------------------------------------------------
  // Verification (§72-§74).
  // -------------------------------------------------------------------------

  async verify(input: {
    engagementId: string;
    hypothesisId: string;
    endpointId?: string | null;
  }): Promise<{ verification: VerificationRecord; outcome: VerificationOutcome }> {
    const hypothesis = await this.repos.hypotheses.findByIdAndEngagement(input.hypothesisId, input.engagementId);
    if (!hypothesis) {
      throw Object.assign(new Error('hypothesis not found for engagement'), { code: 'HYPOTHESIS_NOT_FOUND' });
    }

    // Endpoint selection: explicit, or the signal-richest object-level
    // endpoint (deterministic, §84).
    let endpointId = input.endpointId ?? null;
    if (!endpointId) {
      const signals = await this.repos.securitySignals.listByEngagement(input.engagementId, {
        types: ['CROSS_IDENTITY_OBJECT_REFERENCE', 'CROSS_IDENTITY_DIFFERENCE'],
        limit: 32,
      });
      endpointId = [...signals].sort((a, b) => b.confidence - a.confidence).find((signal) => signal.endpoint_id)?.endpoint_id ?? null;
    }
    const endpoint = endpointId ? (await this.repos.endpoints.findById(endpointId)) ?? null : null;

    const matrix = await this.repos.authzMatrix.listByEngagement(input.engagementId, 1000);
    const relevantMatrix = matrix.filter((entry) => (endpoint ? entry.endpoint_id === endpoint.id : true));
    let differentials = await this.repos.differentialResults.listByHypothesis(input.hypothesisId);
    if (differentials.length === 0) {
      const all = await this.repos.differentialResults.listByEngagement(input.engagementId, 100);
      differentials = all.slice(0, 8);
    }
    const anonymousOutcome =
      relevantMatrix.find((entry) => entry.identity_id === null)?.outcome ??
      (endpoint ? (await this.repos.authzMatrix.listByEndpoint(endpoint.id)).find((entry) => entry.identity_id === null)?.outcome ?? null : null);

    // Evidence-strength classification (§70) — explainable.
    const reproductions = endpoint
      ? relevantMatrix
          .filter((entry) => entry.object_ref !== null && entry.outcome === 'ALLOWED')
          .map((entry) => reproductionCountFor(relevantMatrix, endpoint.id, entry.object_ref!, 'ALLOWED'))
      : [];
    const strength = classifyEvidence({
      reproductionCount: reproductions.length > 0 ? Math.max(...reproductions) : 0,
      crossIdentityEvidence: relevantMatrix.some((entry) => entry.identity_id !== null),
      objectLevelEvidence: relevantMatrix.some((entry) => entry.object_ref !== null),
      baselineDifferential: differentials[0] ?? null,
      anonymousOutcome,
    });

    const outcome = evaluateVerification({
      hypothesis,
      endpoint,
      matrix: relevantMatrix,
      differentials,
      anonymousOutcome,
    });

    const record = await this.repos.verifications.create({
      engagementId: input.engagementId,
      hypothesisId: hypothesis.id,
      kind: outcome.kind,
      alternatives: outcome.alternatives,
      checklist: [
        ...outcome.checklist,
        {
          check: 'EVIDENCE_STRENGTH',
          status: 'NOT_APPLICABLE',
          detail: `classified ${strength.level}: ${strength.reasons.join('; ')}`.slice(0, 1000),
          evidence_ids: [],
        },
      ],
      evidenceIds: outcome.evidenceIds,
    });
    const completed = await this.repos.verifications.complete(record.id, {
      status: outcome.status,
      result: { ...outcome.result, evidence_strength: strength.level, strength_reasons: strength.reasons },
      checklist: record.checklist,
      evidenceIds: outcome.evidenceIds,
    });

    await this.eventBus.publish({
      type: 'VERIFICATION_CREATED',
      engagement_id: input.engagementId,
      task_id: null,
      trace_id: generateId('TRC'),
      actor_id: null,
      payload: { verification_id: record.id, hypothesis_id: hypothesis.id, kind: outcome.kind },
      occurred_at: new Date().toISOString(),
      dedup_key: `verification-created:${record.id}`,
    });
    await this.eventBus.publish({
      type: 'VERIFICATION_COMPLETED',
      engagement_id: input.engagementId,
      task_id: null,
      trace_id: generateId('TRC'),
      actor_id: null,
      payload: {
        verification_id: completed.id,
        hypothesis_id: hypothesis.id,
        status: outcome.status,
        reason: String(outcome.result['reason'] ?? ''),
      },
      occurred_at: new Date().toISOString(),
      dedup_key: `verification-completed:${completed.id}`,
    });

    return { verification: completed, outcome };
  }

  /** Dead-end payload for a refuted hypothesis (§75). */
  deadEndFor(verification: VerificationRecord, hypothesis: { id: string; statement: string }): {
    description: string;
    reason: string;
    tests: string[];
  } {
    return deadEndPayload(verification, {
      id: hypothesis.id,
      engagement_id: '',
      type: 'UNKNOWN',
      statement: hypothesis.statement,
      status: 'DISPROVED',
      confidence: 0,
      priority: 0,
      source: 'system',
      parent_hypothesis_id: null,
      created_at: '',
      updated_at: '',
      confirmed_at: null,
      disproved_at: null,
    });
  }

  // -------------------------------------------------------------------------
  // Focused attack-surface query (§80) — for workers via tools.
  // -------------------------------------------------------------------------

  async query(input: {
    engagementId: string;
    endpointId?: string | null;
    hypothesisId?: string | null;
    signalType?: string | null;
  }): Promise<ReasoningQueryResponse> {
    const [endpointsAll, parametersAll, matrix, signals, objects, workflows, differentials, deadEnds] =
      await Promise.all([
        this.repos.endpoints.listByEngagement(input.engagementId, { limit: 500 }),
        this.repos.parameters.listByEngagement(input.engagementId, 1000),
        this.repos.authzMatrix.listByEngagement(input.engagementId, 1000),
        this.repos.securitySignals.listByEngagement(input.engagementId, { limit: 200 }),
        this.repos.objectCandidates.listByEngagement(input.engagementId, 200),
        this.repos.workflows.listByEngagement(input.engagementId),
        this.repos.differentialResults.listByEngagement(input.engagementId, 20),
        this.repos.deadEnds.listByEngagement(input.engagementId, 10),
      ]);

    const endpointFocus = input.endpointId ?? null;
    const endpoints = endpointFocus
      ? endpointsAll.filter((endpoint) => endpoint.id === endpointFocus)
      : endpointsAll.slice(0, 16);
    const endpointIds = new Set(endpoints.map((endpoint) => endpoint.id));
    const parameters = parametersAll
      .filter((parameter) => parameter.endpoint_id !== null && endpointIds.has(parameter.endpoint_id))
      .slice(0, 64);
    const focusedMatrix = matrix.filter((entry) => endpointIds.has(entry.endpoint_id)).slice(0, 64);
    const filteredSignals = input.signalType
      ? signals.filter((signal) => signal.signal_type === input.signalType)
      : signals;
    const focusSignals = (
      endpointFocus ? filteredSignals.filter((signal) => signal.endpoint_id === endpointFocus) : filteredSignals
    ).slice(0, 32);

    const workflowStates: WorkflowStateRecord[] = [];
    for (const workflow of workflows.slice(0, 8)) {
      const states = await this.repos.workflowStates.listByWorkflow(workflow.id);
      workflowStates.push(...states);
    }

    return {
      engagement_id: input.engagementId,
      endpoints,
      parameters,
      matrix: focusedMatrix,
      signals: focusSignals,
      objects: objects
        .filter((object) => object.endpoint_id === null || endpointIds.has(object.endpoint_id))
        .slice(0, 32),
      workflow_states: workflowStates.slice(0, 32),
      recent_differentials: (input.hypothesisId
        ? differentials.filter((differential) => differential.hypothesis_id === input.hypothesisId)
        : differentials
      )
        .slice(0, 8)
        .map(
          (differential) =>
            ({
              ...differential,
              // We always write a structurally-typed summary (insert path);
              // the row stores it as a generic JSON record.
              summary: differential.summary as unknown as DifferentialResult['summary'],
              detail: differential.detail as Record<string, unknown>,
            }) satisfies DifferentialResult,
        ),
      dead_ends: deadEnds.map((deadEnd) => ({
        id: deadEnd.id,
        hypothesis_id: deadEnd.hypothesis_id,
        description: deadEnd.description,
        reason: deadEnd.reason,
      })),
    };
  }

  // -------------------------------------------------------------------------
  // Leader projection (§120) — SecurityContextProvider implementation.
  // -------------------------------------------------------------------------

  async buildSecurityProjection(engagementId: string): Promise<SecurityProjection> {
    const [endpoints, parameters, matrix, objects, workflows, workflowTransitions, signals, hypotheses, identities, tests] =
      await Promise.all([
        this.repos.endpoints.listByEngagement(engagementId, { limit: 500 }),
        this.repos.parameters.listByEngagement(engagementId, 1000),
        this.repos.authzMatrix.listByEngagement(engagementId, 1000),
        this.repos.objectCandidates.listByEngagement(engagementId, 200),
        this.repos.workflows.listByEngagement(engagementId),
        this.repos.workflowTransitions.listByEngagement(engagementId, 500),
        this.repos.securitySignals.listByEngagement(engagementId, { statuses: ['NEW'], limit: 50 }),
        this.repos.hypotheses.listByEngagement(engagementId, {
          statuses: ['PROPOSED', 'ACTIVE', 'TESTING', 'SUPPORTED'],
        }),
        this.repos.identities.listByEngagement(engagementId),
        this.repos.tests.listByEngagement(engagementId, 200),
      ]);

    const parameterMap = new Map<string, typeof parameters>();
    for (const endpoint of endpoints) {
      parameterMap.set(endpoint.id, parameters.filter((parameter) => parameter.endpoint_id === endpoint.id));
    }

    return this.projectionBuilder.build({
      endpoints,
      parametersByEndpoint: parameterMap,
      matrix,
      objects,
      workflowTransitions,
      workflowCount: workflows.length,
      identityCount: identities.length,
      parameterCount: parameters.length,
      signals: signals.map((signal) => ({
        id: signal.id,
        signal_type: signal.signal_type,
        summary: signal.summary,
        confidence: signal.confidence,
      })),
      hypotheses,
      deadEnds: [],
      identities: identities.map((identity) => ({ id: identity.id, name: identity.name, role: identity.role })),
      existingTestFingerprints: new Set(tests.map((test) => test.fingerprint)),
      allowDestructive: this.allowDestructive,
    });
  }

  // -------------------------------------------------------------------------
  // Status (§113 / API).
  // -------------------------------------------------------------------------

  async status(engagementId: string): Promise<{
    counts: {
      endpoints: number;
      parameters: number;
      signals: number;
      signals_new: number;
      objects: number;
      workflows: number;
      data_flows: number;
      matrix_entries: number;
      graph_nodes: number;
      graph_edges: number;
      differentials: number;
      verifications: number;
      processor_failures: number;
    };
    recent_failures: Array<{
      id: string;
      processor: string;
      event_type: string | null;
      error: string;
      created_at: string;
    }>;
  }> {
    const [endpoints, parameters, signalCounts, objects, workflows, dataFlows, matrix, nodes, edges, differentials, verifications, failures, recentFailures] =
      await Promise.all([
        this.repos.endpoints.countByEngagement(engagementId),
        this.repos.parameters.countByEngagement(engagementId),
        this.repos.securitySignals.countByEngagement(engagementId),
        this.repos.objectCandidates.countByEngagement(engagementId),
        this.repos.workflows.countByEngagement(engagementId),
        this.repos.dataFlows.countByEngagement(engagementId),
        this.repos.authzMatrix.countByEngagement(engagementId),
        this.repos.attackNodes.countByEngagement(engagementId),
        this.repos.attackEdges.countByEngagement(engagementId),
        this.repos.differentialResults.countByEngagement(engagementId),
        this.repos.verifications.countByEngagement(engagementId),
        this.repos.reasoningFailures.countByEngagement(engagementId),
        this.repos.reasoningFailures.listByEngagement(engagementId, 10),
      ]);
    return {
      counts: {
        endpoints,
        parameters,
        signals: signalCounts.total,
        signals_new: signalCounts.new,
        objects,
        workflows,
        data_flows: dataFlows,
        matrix_entries: matrix,
        graph_nodes: nodes,
        graph_edges: edges,
        differentials,
        verifications,
        processor_failures: failures,
      },
      recent_failures: recentFailures.map((failure) => ({
        id: failure.id,
        processor: failure.processor,
        event_type: failure.event_type,
        error: String((failure.error as Record<string, unknown>)?.['message'] ?? 'unknown failure').slice(0, 500),
        created_at: failure.created_at,
      })),
    };
  }

  /** Verification with a caller-provided verdict bridge (§71-§73). */
  async evaluateWithBridge(input: {
    engagementId: string;
    hypothesisId: string;
    endpointId?: string | null;
  }): Promise<VerificationEvaluateResponse & { outcome: VerificationOutcome }> {
    const { verification, outcome } = await this.verify(input);
    return {
      verification,
      hypothesis_status: null,
      finding_id: null,
      outcome,
    };
  }
}

export function createSecurityReasoningEngine(deps: ReasoningEngineDeps): SecurityReasoningEngine {
  return new SecurityReasoningEngine(deps);
}

// Re-exports (spec §108 service interfaces).
export { ReasoningEventProcessor } from './processor.js';
export type { IngestSummary } from './processor.js';
export { hypothesisGroupsFromSignals } from './hypothesis-candidates.js';
export type { HypothesisGroup } from './hypothesis-candidates.js';
export { evaluateVerification, deadEndPayload } from './verification.js';
export type { VerificationOutcome } from './verification.js';
export { classifyEvidence, reproductionCountFor } from './evidence-strength.js';
export { generateMutations } from './mutation-strategies.js';
export type { MutationPlan, MutationStrategyContext } from './mutation-strategies.js';
export { planTests, expectedInformationGain } from './test-planner.js';
export { rankEndpoints, DEFAULT_PRIORITIZATION_WEIGHTS } from './prioritization.js';
export type { PrioritizationWeights, RankedEndpoint } from './prioritization.js';
export { SecurityProjectionBuilder } from './projection.js';
export { AttackSurfaceGraph } from './graph.js';
export { DEFAULT_REASONING_LIMITS, ReasoningLimitError } from './limits.js';
export type { ReasoningLimits } from './limits.js';
export {
  analyzeValue,
  classifyParameterName,
  objectNameFromParameter,
  objectKindFromName,
  isSensitiveParameterName,
  observedTypeOf,
  looksLikeFileValue,
} from './value-analysis.js';
export {
  canonicalizePath,
  pathShape,
  endpointFingerprint,
  resourceFamilyOf,
  apiVersionOf,
  isIdentifierSegment,
  canonicalUpgrade,
  parseUrlParts,
  deriveEndpoint,
} from './endpoint-extractor.js';
export {
  extractRequestParameters,
  extractFormParameters,
  extractWsParameters,
  pathParameterNames,
  crossEndpointRelationships,
  parameterFingerprint,
} from './parameter-extractor.js';
export { compareResponses, isVolatileField, findReflection, differentialFingerprint, responseRowToComparison } from './differential.js';
export { analyzeJwt, compareTokens, scanForJwtTokens, looksLikeJwt } from './token-analysis.js';
export {
  authStateChangeSignal,
  signalsFromMatrix,
  signalsFromParameters,
  signalsFromResponse,
  unexpectedRedirectSignal,
  reflectionSignal,
  tokenPatternSignal,
  tokenComparisonSignals,
  stateTransitionAnomalySignal,
  unexpectedMethodSignal,
  unusualResponseDifferenceSignal,
} from './signal-engine.js';
export {
  classifyOutcome,
  classifyAuthSurface,
  objectRefForRequest,
  matrixFingerprint,
  authBoundaryFor,
  objectRefsFromParameters,
  authenticationObserved,
} from './authorization.js';
export {
  transitionsFromSequence,
  segmentByIdentity,
  prerequisiteAnomalies,
  workflowNameForHost,
  stateNameForStep,
  triggerSummaryFor,
} from './workflow-engine.js';
export {
  formToRequestFlows,
  scriptToEndpointFlows,
  storageToRequestFlows,
  reflectionFlows,
  detectTransformations,
} from './dataflow.js';
export { objectCandidatesFromParameters, objectFingerprint, lifecycleFromEndpoint } from './object-model.js';
