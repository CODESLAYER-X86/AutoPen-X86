/**
 * Attack-surface prioritization (spec §84-§85).
 *
 * Rank assets with configurable factor weights: authentication boundary,
 * sensitive data, object identifiers, privilege context, workflow importance,
 * external exposure, parameter richness, observed anomalies, business
 * importance. The ranking is a SUGGESTION — the leader can override (§85).
 */
import type { EndpointRecord, ObjectCandidateRecord, ParameterRecord, WorkflowTransitionRecord } from '@aegis/database';

export interface PrioritizationFactors {
  authenticationBoundary: number;
  sensitiveData: number;
  objectIdentifiers: number;
  privilegeContext: number;
  workflowImportance: number;
  externalExposure: number;
  parameterRichness: number;
  observedAnomalies: number;
  businessImportance: number;
}

export type PrioritizationWeights = Record<keyof PrioritizationFactors, number>;

export const DEFAULT_PRIORITIZATION_WEIGHTS: PrioritizationWeights = {
  authenticationBoundary: 0.16,
  sensitiveData: 0.14,
  objectIdentifiers: 0.14,
  privilegeContext: 0.12,
  workflowImportance: 0.1,
  externalExposure: 0.08,
  parameterRichness: 0.08,
  observedAnomalies: 0.12,
  businessImportance: 0.06,
};

export interface RankedEndpoint {
  endpoint: EndpointRecord;
  priority: number;
  factors: PrioritizationFactors;
  reason: string;
}

const PRIVILEGE_PATH = /admin|manage|internal|priv|root|superuser|dashboard\/?users?/i;
const STATE_CHANGING = ['POST', 'PUT', 'PATCH', 'DELETE'];

/** Rank endpoints for hypothesis richness (§84-§85). */
export function rankEndpoints(
  endpoints: EndpointRecord[],
  context: {
    parametersByEndpoint: Map<string, ParameterRecord[]>;
    objects: ObjectCandidateRecord[];
    workflowTriggerEndpointIds: Set<string>;
    authenticationObserved: Set<string>;
    weights?: PrioritizationWeights;
  },
): RankedEndpoint[] {
  const weights = context.weights ?? DEFAULT_PRIORITIZATION_WEIGHTS;
  const ranked: RankedEndpoint[] = [];

  for (const endpoint of endpoints) {
    const parameters = context.parametersByEndpoint.get(endpoint.id) ?? [];
    const identifierParameters = parameters.filter((parameter) =>
      parameter.semantic_candidates.some((candidate) => candidate.semantic === 'IDENTIFIER') ||
      parameter.value_characteristics.includes('UUID'),
    );
    const endpointObjects = context.objects.filter((object) => object.endpoint_id === endpoint.id);
    const methods = endpoint.methods.map((method) => method.method);
    const stateChanging = methods.filter((method) => STATE_CHANGING.includes(method)).length;

    const factors: PrioritizationFactors = {
      authenticationBoundary: context.authenticationObserved.has(endpoint.id) ? 0.9 : 0.3,
      sensitiveData: Math.min(1, endpoint.signal_count / 5),
      objectIdentifiers: Math.min(1, identifierParameters.length * 0.4 + endpointObjects.length * 0.2),
      privilegeContext: PRIVILEGE_PATH.test(endpoint.canonical_path) ? 0.9 : 0.2,
      workflowImportance: context.workflowTriggerEndpointIds.has(endpoint.id) ? 0.85 : 0.2,
      // In-scope endpoints are all authorized; exposure defaults high for
      // non-page API surfaces (spec §84 external exposure).
      externalExposure: endpoint.canonical_path.startsWith('/api') ? 0.8 : 0.5,
      parameterRichness: Math.min(1, parameters.length / 8),
      observedAnomalies: Math.min(1, endpoint.signal_count / 4),
      businessImportance: Math.min(1, stateChanging * 0.35 + endpoint.observation_count / 50),
    };

    let priority = 0;
    for (const key of Object.keys(factors) as Array<keyof PrioritizationFactors>) {
      priority += factors[key] * weights[key];
    }
    ranked.push({
      endpoint,
      priority: Math.min(1, Math.max(0, priority)),
      factors,
      reason: [
        identifierParameters.length > 0 ? `${identifierParameters.length} identifier parameters` : null,
        endpointObjects.length > 0 ? `${endpointObjects.length} object candidates` : null,
        PRIVILEGE_PATH.test(endpoint.canonical_path) ? 'privilege-shaped path' : null,
        context.workflowTriggerEndpointIds.has(endpoint.id) ? 'workflow trigger' : null,
        stateChanging > 0 ? `${stateChanging} state-changing methods` : null,
        endpoint.signal_count > 0 ? `${endpoint.signal_count} signals` : null,
      ]
        .filter((entry): entry is string => entry !== null)
        .slice(0, 4)
        .join(', ') || 'low-information surface',
    });
  }
  return ranked.sort((a, b) => b.priority - a.priority);
}
