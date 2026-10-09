/**
 * Security signal engine (spec §42-§43, §62-§65, §121).
 *
 * Deterministic signal generation. Signals are NOT findings (§2, §136) —
 * they are evidence-backed observations that feed hypothesis generation.
 * Every signal has a deterministic fingerprint (§111 idempotency).
 */
import { createHash } from 'node:crypto';
import type { SignalType } from '@aegis/shared';
import type {
  AuthorizationMatrixRecord,
  EndpointRecord,
  ObjectCandidateRecord,
  ParameterRecord,
} from '@aegis/database';
import type { DifferentialSummary } from './differential.js';
import type { JwtFacts, TokenComparisonResult } from './token-analysis.js';

export interface SignalCandidate {
  signalType: SignalType;
  source: string;
  endpointId: string | null;
  parameterId: string | null;
  identityIds: string[];
  objectRef: string | null;
  confidence: number;
  summary: string;
  metadata: Record<string, unknown>;
  evidenceIds: string[];
  fingerprint: string;
}

export function signalFingerprint(type: SignalType, key: string): string {
  return createHash('sha256').update(`${type}|${key}`).digest('hex').slice(0, 40);
}

// ---------------------------------------------------------------------------
// Authorization-driven signals (§23-§24, §98-§99, §121).
// ---------------------------------------------------------------------------

/**
 * Cross-identity differences from the authorization matrix (§24). Same
 * endpoint, different identities, different outcomes — a signal, never a
 * conclusion (§24: do not assume differences indicate vulnerability).
 */
export function signalsFromMatrix(
  endpoint: EndpointRecord,
  entries: AuthorizationMatrixRecord[],
): SignalCandidate[] {
  const byIdentity = new Map<string, AuthorizationMatrixRecord[]>();
  for (const entry of entries) {
    const key = entry.identity_id ?? 'ANONYMOUS';
    if (!byIdentity.has(key)) byIdentity.set(key, []);
    byIdentity.get(key)!.push(entry);
  }
  const candidates: SignalCandidate[] = [];
  if (byIdentity.size < 2) return candidates;

  const outcomesBy = (identity: string): Set<string> => {
    const list = byIdentity.get(identity) ?? [];
    return new Set(list.map((entry) => entry.outcome));
  };
  const identityKeys = [...byIdentity.keys()];
  let differing = false;
  for (let i = 0; i < identityKeys.length && !differing; i += 1) {
    for (let j = i + 1; j < identityKeys.length && !differing; j += 1) {
      const outcomesA = outcomesBy(identityKeys[i]!);
      const outcomesB = outcomesBy(identityKeys[j]!);
      for (const outcome of outcomesA) {
        if (!outcomesB.has(outcome)) differing = true;
      }
    }
  }

  if (differing) {
    candidates.push({
      signalType: 'CROSS_IDENTITY_DIFFERENCE',
      source: 'AUTHORIZATION_MATRIX',
      endpointId: endpoint.id,
      parameterId: null,
      identityIds: identityKeys.filter((key) => key !== 'ANONYMOUS').slice(0, 16),
      objectRef: null,
      confidence: 0.8,
      summary: `Endpoint ${endpoint.canonical_path} produced different access outcomes across ${identityKeys.length} identities (matrix: ${identityKeys
        .map((key) => `${key}=${outcomesBy(key).size > 0 ? [...outcomesBy(key)].join('/') : 'NONE'}`)
        .join(', ')})`,
      metadata: {
        outcomes: identityKeys.map((key) => ({
          identity: key,
          outcomes: [...outcomesBy(key)],
        })),
        object_level: entries.some((entry) => entry.object_ref !== null),
      },
      evidenceIds: entries.flatMap((entry) => entry.evidence_ids).slice(0, 32),
      fingerprint: signalFingerprint('CROSS_IDENTITY_DIFFERENCE', endpoint.id),
    });
  }

  // Object-level cross-identity reference (§121): the same object accessed by
  // multiple identities, at least one ALLOWED for a non-owner identity.
  const objectRefs = new Set(entries.map((entry) => entry.object_ref).filter((ref): ref is string => ref !== null));
  for (const objectRef of [...objectRefs].slice(0, 32)) {
    const objectEntries = entries.filter((entry) => entry.object_ref === objectRef);
    const identitiesWithAccess = objectEntries
      .filter((entry) => entry.outcome === 'ALLOWED')
      .map((entry) => entry.identity_id ?? 'ANONYMOUS');
    if (new Set(identitiesWithAccess).size >= 2) {
      candidates.push({
        signalType: 'CROSS_IDENTITY_OBJECT_REFERENCE',
        source: 'AUTHORIZATION_MATRIX',
        endpointId: endpoint.id,
        parameterId: null,
        identityIds: identitiesWithAccess.filter((key) => key !== 'ANONYMOUS').slice(0, 16),
        objectRef,
        confidence: 0.85,
        summary: `Object ${objectRef} on ${endpoint.canonical_path} was accessed successfully by ${new Set(identitiesWithAccess).size} different identity contexts`,
        metadata: {
          object_ref: objectRef,
          allowed_identities: identitiesWithAccess,
          entries: objectEntries.map((entry) => ({
            identity: entry.identity_id ?? 'ANONYMOUS',
            outcome: entry.outcome,
            status_code: entry.status_code,
          })),
        },
        evidenceIds: objectEntries.flatMap((entry) => entry.evidence_ids).slice(0, 32),
        fingerprint: signalFingerprint('CROSS_IDENTITY_OBJECT_REFERENCE', `${endpoint.id}|${objectRef}`),
      });
    }
  }
  return candidates;
}

// ---------------------------------------------------------------------------
// Parameter-driven signals (§14-§19).
// ---------------------------------------------------------------------------

export function signalsFromParameters(endpoint: EndpointRecord, parameters: ParameterRecord[]): SignalCandidate[] {
  const candidates: SignalCandidate[] = [];
  for (const parameter of parameters.slice(0, 64)) {
    const identifierish =
      parameter.semantic_candidates.some((candidate) => candidate.semantic === 'IDENTIFIER' && candidate.confidence >= 0.5) ||
      parameter.value_characteristics.includes('IDENTIFIER') ||
      parameter.value_characteristics.includes('UUID');
    if (identifierish && parameter.example_values.length > 0 && parameter.location !== 'HEADER') {
      candidates.push({
        signalType: 'OBJECT_IDENTIFIER',
        source: 'PARAMETER',
        endpointId: endpoint.id,
        parameterId: parameter.id,
        identityIds: parameter.identity_association.slice(0, 16),
        objectRef: null,
        confidence: 0.7,
        summary: `Parameter "${parameter.name}" (${parameter.location}) on ${endpoint.canonical_path} carries object-reference-like values`,
        metadata: {
          parameter: parameter.name,
          location: parameter.location,
          characteristics: parameter.value_characteristics,
          example_count: parameter.example_values.length,
          note: 'identifier existence is not an authorization vulnerability (spec §19)',
        },
        evidenceIds: [],
        fingerprint: signalFingerprint('OBJECT_IDENTIFIER', `${endpoint.id}|${parameter.id}`),
      });
    }
    const privilegeish = parameter.semantic_candidates.some(
      (candidate) => candidate.semantic === 'PRIVILEGE' || candidate.semantic === 'MONETARY',
    );
    if (privilegeish) {
      candidates.push({
        signalType: 'CLIENT_CONTROLLED_VALUE',
        source: 'PARAMETER',
        endpointId: endpoint.id,
        parameterId: parameter.id,
        identityIds: parameter.identity_association.slice(0, 16),
        objectRef: null,
        confidence: 0.75,
        summary: `Client-controlled parameter "${parameter.name}" on ${endpoint.canonical_path} suggests ${parameter.semantic_candidates
          .filter((candidate) => candidate.semantic === 'PRIVILEGE' || candidate.semantic === 'MONETARY')
          .map((candidate) => candidate.semantic)
          .join('/')} semantics`,
        metadata: {
          parameter: parameter.name,
          location: parameter.location,
          semantics: parameter.semantic_candidates,
        },
        evidenceIds: [],
        fingerprint: signalFingerprint('CLIENT_CONTROLLED_VALUE', `${endpoint.id}|${parameter.id}`),
      });
    }
  }
  return candidates;
}

// ---------------------------------------------------------------------------
// Response-driven signals (§62-§65, §114).
// ---------------------------------------------------------------------------

const SENSITIVE_PATTERNS: Array<{ kind: string; pattern: RegExp }> = [
  { kind: 'STACK_TRACE', pattern: /\bat\s+[A-Za-z0-9_$./]+\([^)]+\)|Traceback \(most recent call last\)/ },
  { kind: 'SQL_ERROR', pattern: /SQL syntax|SQLSTATE|unterminated quoted string|pg_query|mysql_fetch|ORA-\d{5}/i },
  { kind: 'INTERNAL_IP', pattern: /\b(?:10|127|192\.168|172\.(?:1[6-9]|2\d|3[01]))\.\d+\.\d+\b/ },
  { kind: 'SOURCE_PATH', pattern: /\/(?:home|var\/www|usr\/(?:lib|share|local)|app|srv)\/[A-Za-z0-9._/-]{3,}/ },
  { kind: 'DEBUG_KEY', pattern: /"(?:debug|stack|error_detail|exception|env|config)"\s*:/i },
  { kind: 'FRAMEWORK', pattern: /(?:laravel|symfony|django|flask|express|next\.js|rails|spring|wp-content)/i },
];

export function signalsFromResponse(
  endpoint: EndpointRecord,
  response: { status: number; contentKind: string; bodyPreview: string | null; redirectTo: string | null },
): SignalCandidate[] {
  const candidates: SignalCandidate[] = [];
  const preview = (response.bodyPreview ?? '').slice(0, 8192);

  if (response.status >= 500) {
    const hits = SENSITIVE_PATTERNS.filter((entry) => entry.pattern.test(preview)).map((entry) => entry.kind);
    candidates.push({
      signalType: 'ERROR_DISCLOSURE',
      source: 'HTTP_RESPONSE',
      endpointId: endpoint.id,
      parameterId: null,
      identityIds: [],
      objectRef: null,
      confidence: hits.length > 0 ? 0.85 : 0.6,
      summary: `Endpoint ${endpoint.canonical_path} returned ${response.status}${hits.length > 0 ? ` with ${hits.join(', ')} indicators in the body` : ''}`,
      metadata: { status: response.status, indicators: hits, preview_bytes: preview.length },
      evidenceIds: [],
      fingerprint: signalFingerprint('ERROR_DISCLOSURE', `${endpoint.id}|${response.status}`),
    });
  } else if (preview.length > 0) {
    const hits = SENSITIVE_PATTERNS.filter((entry) => entry.pattern.test(preview)).map((entry) => entry.kind);
    if (hits.length > 0) {
      candidates.push({
        signalType: 'SENSITIVE_DATA_EXPOSURE',
        source: 'HTTP_RESPONSE',
        endpointId: endpoint.id,
        parameterId: null,
        identityIds: [],
        objectRef: null,
        confidence: 0.65,
        summary: `Response of ${endpoint.canonical_path} contains candidate sensitive information (${hits.join(', ')}) — false positives expected (spec §64)`,
        metadata: { indicators: hits, status: response.status },
        evidenceIds: [],
        fingerprint: signalFingerprint('SENSITIVE_DATA_EXPOSURE', `${endpoint.id}|${hits.join(',').slice(0, 120)}`),
      });
    }
  }
  return candidates;
}

export function unexpectedRedirectSignal(
  endpoint: EndpointRecord,
  response: { redirectTo: string | null; identityId: string | null; authenticated: boolean },
): SignalCandidate | null {
  if (!response.redirectTo) return null;
  const loginish = /login|signin|sign-in|auth|session\/?|sso/i.test(response.redirectTo);
  if (!loginish) return null;
  if (!response.authenticated) return null; // anonymous -> login redirect is normal
  return {
    signalType: 'UNEXPECTED_REDIRECT',
    source: 'HTTP_RESPONSE',
    endpointId: endpoint.id,
    parameterId: null,
    identityIds: response.identityId ? [response.identityId] : [],
    objectRef: null,
    confidence: 0.7,
    summary: `Authenticated identity was redirected to a login-like target (${bounded(response.redirectTo, 160)}) from ${endpoint.canonical_path}`,
    metadata: { redirect_to: bounded(response.redirectTo, 512), authenticated: true },
    evidenceIds: [],
    fingerprint: signalFingerprint('UNEXPECTED_REDIRECT', endpoint.id),
  };
}

export function reflectionSignal(
  endpoint: EndpointRecord,
  reflections: Array<{ name: string; value: string; location: string; excerpt: string }>,
  parameterIds: Record<string, string>,
): SignalCandidate | null {
  if (reflections.length === 0) return null;
  const reflection = reflections[0]!;
  return {
    signalType: 'REFLECTED_INPUT',
    source: 'HTTP_RESPONSE',
    endpointId: endpoint.id,
    parameterId: parameterIds[reflection.name] ?? null,
    identityIds: [],
    objectRef: null,
    confidence: 0.75,
    summary: `Input "${reflection.name}" is reflected in the ${reflection.location} of ${endpoint.canonical_path} — reflection is not automatically XSS (spec §65)`,
    metadata: {
      reflected: reflections.slice(0, 8).map((entry) => ({ name: entry.name, location: entry.location })),
      note: 'exact locations recorded; client/server separation tracked via location',
    },
    evidenceIds: [],
    fingerprint: signalFingerprint('REFLECTED_INPUT', `${endpoint.id}|${reflections.map((entry) => entry.name).sort().join(',')}`),
  };
}

export function tokenPatternSignal(
  endpoint: EndpointRecord,
  token: { facts: JwtFacts; sourceSummary: string },
): SignalCandidate {
  return {
    signalType: 'TOKEN_PATTERN',
    source: 'HTTP_RESPONSE',
    endpointId: endpoint.id,
    parameterId: null,
    identityIds: [],
    objectRef: null,
    confidence: 0.8,
    summary: `JWT-like token observed (${token.sourceSummary}) on ${endpoint.canonical_path}: alg=${token.facts.algorithm ?? 'unknown'}, signature=${token.facts.signature_present ? 'present' : 'absent'} — decode is not verification (spec §59)`,
    metadata: {
      algorithm: token.facts.algorithm,
      signature_present: token.facts.signature_present,
      signature_verified: false,
      claims: token.facts.claims.slice(0, 16),
      expired: token.facts.expired,
      warnings: token.facts.warnings,
    },
    evidenceIds: [],
    fingerprint: signalFingerprint('TOKEN_PATTERN', `${endpoint.id}|${token.facts.algorithm}|${token.facts.claims.map((claim) => claim.name).sort().join(',')}`),
  };
}

export function tokenComparisonSignals(comparison: TokenComparisonResult): SignalCandidate[] {
  const candidates: SignalCandidate[] = [];
  if (comparison.role_claims.length > 0 && comparison.identity_claims.length > 0) {
    const overlapping = comparison.role_claims.filter((claim) => comparison.identity_claims.includes(claim));
    if (overlapping.length > 0) {
      candidates.push({
        signalType: 'TOKEN_PATTERN',
        source: 'TOKEN_COMPARISON',
        endpointId: null,
        parameterId: null,
        identityIds: [],
        objectRef: null,
        confidence: 0.7,
        summary: `Role claims (${overlapping.join(', ')}) differ across identities — expected for RBAC, relevant for authorization reasoning`,
        metadata: { identity_claims: comparison.identity_claims, role_claims: comparison.role_claims },
        evidenceIds: [],
        fingerprint: signalFingerprint('TOKEN_PATTERN', `roles|${overlapping.sort().join(',')}`),
      });
    }
  }
  return candidates;
}

// ---------------------------------------------------------------------------
// Workflow + method + auth signals (§21-§22, §36, §42).
// ---------------------------------------------------------------------------

export function authStateChangeSignal(input: {
  endpointId: string | null;
  identityId: string;
  change: 'LOGIN' | 'LOGOUT' | 'EXPIRATION' | 'SESSION_ESTABLISHED';
  detail: string;
  evidenceIds: string[];
}): SignalCandidate {
  return {
    signalType: 'AUTH_STATE_CHANGE',
    source: 'SESSION',
    endpointId: input.endpointId,
    parameterId: null,
    identityIds: [input.identityId],
    objectRef: null,
    confidence: 0.9,
    summary: `Authentication state change (${input.change}) for identity ${input.identityId}: ${bounded(input.detail, 300)}`,
    metadata: { change: input.change, detail: bounded(input.detail, 1000) },
    evidenceIds: input.evidenceIds.slice(0, 32),
    fingerprint: signalFingerprint('AUTH_STATE_CHANGE', `${input.identityId}|${input.change}`),
  };
}

export function stateTransitionAnomalySignal(input: {
  workflowId: string;
  identityId: string | null;
  triggerSummary: string;
  anomaly: 'PREREQUISITE_MISSING' | 'UNEXPECTED_STATE' | 'SKIPPED_TRANSITION';
  detail: string;
  evidenceIds: string[];
}): SignalCandidate {
  return {
    signalType: 'STATE_TRANSITION_ANOMALY',
    source: 'WORKFLOW',
    endpointId: null,
    parameterId: null,
    identityIds: input.identityId ? [input.identityId] : [],
    objectRef: null,
    confidence: 0.75,
    summary: `Workflow anomaly (${input.anomaly}) at "${bounded(input.triggerSummary, 200)}": ${bounded(input.detail, 400)}`,
    metadata: {
      workflow_id: input.workflowId,
      anomaly: input.anomaly,
      trigger: bounded(input.triggerSummary, 512),
      detail: bounded(input.detail, 1000),
    },
    evidenceIds: input.evidenceIds.slice(0, 32),
    fingerprint: signalFingerprint('STATE_TRANSITION_ANOMALY', `${input.workflowId}|${input.anomaly}|${input.triggerSummary.slice(0, 200)}`),
  };
}

export function unexpectedMethodSignal(endpoint: EndpointRecord, method: string): SignalCandidate | null {
  const stateChanging = ['POST', 'PUT', 'PATCH', 'DELETE'];
  if (!stateChanging.includes(method)) return null;
  return {
    signalType: 'UNEXPECTED_METHOD_BEHAVIOR',
    source: 'ENDPOINT',
    endpointId: endpoint.id,
    parameterId: null,
    identityIds: [],
    objectRef: null,
    confidence: 0.6,
    summary: `Endpoint ${endpoint.canonical_path} also accepted ${method} — method surface broader than the navigation-implied one`,
    metadata: { method, known_methods: endpoint.methods.map((entry) => entry.method) },
    evidenceIds: [],
    fingerprint: signalFingerprint('UNEXPECTED_METHOD_BEHAVIOR', `${endpoint.id}|${method}`),
  };
}

// ---------------------------------------------------------------------------
// Differential-driven signals (§24-§25).
// ---------------------------------------------------------------------------

export function unusualResponseDifferenceSignal(input: {
  endpointId: string | null;
  baselineIdentity: string | null;
  candidateIdentity: string | null;
  summary: DifferentialSummary;
  evidenceIds: string[];
}): SignalCandidate | null {
  const { summary } = input;
  const interesting =
    summary.schema_changed ||
    summary.status_changed ||
    summary.fields_removed.length > 0 ||
    summary.fields_added.length > 0 ||
    (summary.values_changed.filter((change) => !change.volatile).length > 0 && summary.body_similarity < 0.9);
  if (!interesting) return null;
  const identityPair = `${input.baselineIdentity ?? 'ANONYMOUS'}|${input.candidateIdentity ?? 'ANONYMOUS'}`;
  return {
    signalType: 'UNUSUAL_RESPONSE_DIFFERENCE',
    source: 'DIFFERENTIAL',
    endpointId: input.endpointId,
    parameterId: null,
    identityIds: [input.baselineIdentity, input.candidateIdentity].filter((id): id is string => id !== null),
    objectRef: null,
    confidence: 0.7,
    summary: `Responses differ semantically between ${input.baselineIdentity ?? 'ANONYMOUS'} and ${input.candidateIdentity ?? 'ANONYMOUS'}: status=${summary.status_baseline}->${summary.status_candidate}, schema_changed=${summary.schema_changed}, similarity=${summary.body_similarity.toFixed(2)} — differences are not vulnerabilities by themselves (spec §61)`,
    metadata: {
      status_changed: summary.status_changed,
      schema_changed: summary.schema_changed,
      fields_added: summary.fields_added.slice(0, 16),
      fields_removed: summary.fields_removed.slice(0, 16),
      nonvolatile_changes: summary.values_changed.filter((change) => !change.volatile).slice(0, 16),
      body_similarity: summary.body_similarity,
    },
    evidenceIds: input.evidenceIds.slice(0, 32),
    fingerprint: signalFingerprint('UNUSUAL_RESPONSE_DIFFERENCE', `${input.endpointId ?? 'none'}|${identityPair}`),
  };
}

// ---------------------------------------------------------------------------
// Object-driven helper (§96-§97).
// ---------------------------------------------------------------------------

export function objectSignalCandidates(_objects: ObjectCandidateRecord[]): SignalCandidate[] {
  // Object candidates themselves are not signals; the OBJECT_IDENTIFIER
  // signal comes from parameters. This helper exists for lifecycle maturity:
  // an object with create+read+update+delete evidence is a workflow surface.
  return [];
}

function bounded(text: string, max: number): string {
  return text.length > max ? `${text.slice(0, max)}…` : text;
}
