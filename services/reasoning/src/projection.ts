/**
 * Leader security projection (spec §80, §120).
 *
 * The leader NEVER receives the whole attack graph (§80): this builder
 * produces the compact §120-shaped projection — counts, interesting
 * anomalies, active hypotheses, recommended tests. Implements the
 * SecurityContextProvider seam consumed by the Part 2 context builder.
 */
import type { SecurityProjection } from '@aegis/contracts';
import type {
  AuthorizationMatrixRecord,
  EndpointRecord,
  HypothesisRecord,
  ObjectCandidateRecord,
  ParameterRecord,
  WorkflowTransitionRecord,
} from '@aegis/database';
import { rankEndpoints, type PrioritizationWeights } from './prioritization.js';
import { planTests, type TestPlanInput } from './test-planner.js';

export interface ProjectionInput {
  endpoints: EndpointRecord[];
  parametersByEndpoint: Map<string, ParameterRecord[]>;
  matrix: AuthorizationMatrixRecord[];
  objects: ObjectCandidateRecord[];
  workflowTransitions: WorkflowTransitionRecord[];
  workflowCount: number;
  identityCount: number;
  parameterCount: number;
  signals: Array<{ id: string; signal_type: string; summary: string; confidence: number }>;
  hypotheses: HypothesisRecord[];
  deadEnds: Array<Record<string, unknown>>;
  identities: Array<{ id: string; name: string; role: string }>;
  existingTestFingerprints: Set<string>;
  allowDestructive: boolean;
  weights?: PrioritizationWeights;
}

export class SecurityProjectionBuilder {
  build(input: ProjectionInput): SecurityProjection {
    const authenticationObserved = new Set<string>();
    const endpointFingerprints = new Map(input.endpoints.map((endpoint) => [endpoint.id, endpoint.fingerprint]));
    for (const entry of input.matrix) {
      if (entry.identity_id !== null && entry.outcome === 'ALLOWED') {
        const fingerprint = endpointFingerprints.get(entry.endpoint_id);
        const endpoint = input.endpoints.find((candidate) => candidate.id === entry.endpoint_id);
        if (endpoint) authenticationObserved.add(endpoint.id);
        void fingerprint;
      }
    }
    const workflowTriggerEndpointIds = new Set(
      input.workflowTransitions.map((transition) => transition.trigger_endpoint_id).filter((id): id is string => id !== null),
    );

    const ranked = rankEndpoints(input.endpoints, {
      parametersByEndpoint: input.parametersByEndpoint,
      objects: input.objects,
      workflowTriggerEndpointIds,
      authenticationObserved,
      weights: input.weights,
    });

    const resourceFamilies = new Set(
      input.endpoints.map((endpoint) => endpoint.resource_family).filter((family): family is string => family !== null),
    );

    const plan = planTests({
      engagementId: '',
      hypotheses: input.hypotheses,
      endpoints: input.endpoints,
      matrix: input.matrix,
      objects: input.objects,
      parametersByEndpoint: input.parametersByEndpoint,
      identities: input.identities,
      existingFingerprints: input.existingTestFingerprints,
      allowDestructive: input.allowDestructive,
    });

    return {
      attack_surface: {
        endpoint_count: input.endpoints.length,
        resource_family_count: resourceFamilies.size,
        identity_count: input.identityCount,
        workflow_count: input.workflowCount,
        parameter_count: input.parameterCount,
        object_count: input.objects.length,
        top_endpoints: ranked.slice(0, 12).map((entry) => ({
          id: entry.endpoint.id,
          method_summary: entry.endpoint.methods.map((method) => method.method).join(',').slice(0, 40),
          canonical_path: entry.endpoint.canonical_path.slice(0, 512),
          status: entry.endpoint.status,
          priority: Number(entry.priority.toFixed(3)),
        })),
      },
      interesting: input.signals.slice(0, 12).map((signal) => ({
        id: signal.id,
        signal_type: signal.signal_type,
        summary: signal.summary.slice(0, 500),
        confidence: signal.confidence,
      })),
      active_hypotheses: input.hypotheses
        .filter((hypothesis) => ['PROPOSED', 'ACTIVE', 'TESTING', 'SUPPORTED'].includes(hypothesis.status))
        .slice(0, 12)
        .map((hypothesis) => ({
          id: hypothesis.id,
          statement: hypothesis.statement.slice(0, 500),
          confidence: hypothesis.confidence,
        })),
      recommended_tests: plan.candidates.slice(0, 8),
    };
  }

  buildStopRecommendations(input: { actionableHypotheses: number; identityCount: number }): Array<{
    recommendation: 'NO_ACTIONABLE_HYPOTHESES' | 'REQUIRES_IDENTITY';
    detail: string;
  }> {
    const recommendations: Array<{ recommendation: 'NO_ACTIONABLE_HYPOTHESES' | 'REQUIRES_IDENTITY'; detail: string }> = [];
    if (input.actionableHypotheses === 0) {
      recommendations.push({
        recommendation: 'NO_ACTIONABLE_HYPOTHESES',
        detail: 'Reasoning engine has no actionable hypotheses; ingest observations or apply signal-derived candidates',
      });
    }
    if (input.identityCount < 2) {
      recommendations.push({
        recommendation: 'REQUIRES_IDENTITY',
        detail: 'Cross-identity differential testing requires a second registered identity',
      });
    }
    return recommendations;
  }
}

export function planCandidateTests(input: TestPlanInput): ReturnType<typeof planTests> {
  return planTests(input);
}
