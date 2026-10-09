/**
 * Part 4 unit tests (spec §125) — deterministic reasoning primitives:
 * endpoint normalization/canonicalization, parameter extraction and
 * classification, fingerprints, JSON/HTML/binary diff, volatile filtering,
 * JWT parsing, object detection, workflow transitions, hypothesis
 * candidates, test fingerprints, signal generation, mutation strategies,
 * authorization classification, verification, evidence strength,
 * prioritization and information gain.
 */
import { describe, expect, it } from 'vitest';
import {
  analyzeValue,
  classifyParameterName,
  isSensitiveParameterName,
  objectNameFromParameter,
  objectKindFromName,
  observedTypeOf,
  looksLikeFileValue,
} from '../../services/reasoning/src/value-analysis.js';
import {
  canonicalizePath,
  pathShape,
  endpointFingerprint,
  parseUrlParts,
  isIdentifierSegment,
  resourceFamilyOf,
  apiVersionOf,
  deriveEndpoint,
  canonicalUpgrade,
} from '../../services/reasoning/src/endpoint-extractor.js';
import {
  extractRequestParameters,
  extractWsParameters,
  pathParameterNames,
  crossEndpointRelationships,
  parameterFingerprint,
} from '../../services/reasoning/src/parameter-extractor.js';
import { compareResponses, isVolatileField, findReflection, differentialFingerprint } from '../../services/reasoning/src/differential.js';
import { analyzeJwt, compareTokens, scanForJwtTokens, looksLikeJwt } from '../../services/reasoning/src/token-analysis.js';
import {
  transitionsFromSequence,
  stateNameForStep,
  segmentByIdentity,
  prerequisiteAnomalies,
  triggerSummaryFor,
} from '../../services/reasoning/src/workflow-engine.js';
import { hypothesisGroupsFromSignals } from '../../services/reasoning/src/hypothesis-candidates.js';
import {
  signalsFromMatrix,
  signalsFromParameters,
  signalsFromResponse,
  authStateChangeSignal,
  unexpectedRedirectSignal,
  reflectionSignal,
  tokenPatternSignal,
  stateTransitionAnomalySignal,
  unexpectedMethodSignal,
  unusualResponseDifferenceSignal,
  objectSignalCandidates,
} from '../../services/reasoning/src/signal-engine.js';
import { generateMutations } from '../../services/reasoning/src/mutation-strategies.js';
import {
  classifyOutcome,
  classifyAuthSurface,
  objectRefForRequest,
  objectRefsFromParameters,
  matrixFingerprint,
  authBoundaryFor,
  authenticationObserved,
} from '../../services/reasoning/src/authorization.js';
import { testFingerprint, expectedInformationGain, planTests } from '../../services/reasoning/src/test-planner.js';
import { rankEndpoints } from '../../services/reasoning/src/prioritization.js';
import { evaluateVerification, deadEndPayload } from '../../services/reasoning/src/verification.js';
import { classifyEvidence, reproductionCountFor } from '../../services/reasoning/src/evidence-strength.js';
import { objectCandidatesFromParameters, objectFingerprint } from '../../services/reasoning/src/object-model.js';
import { detectTransformations, formToRequestFlows, reflectionFlows } from '../../services/reasoning/src/dataflow.js';
import { DEFAULT_REASONING_LIMITS, ReasoningLimitError } from '../../services/reasoning/src/limits.js';
import type {
  EndpointRecord,
  ParameterRecord,
  AuthorizationMatrixRecord,
  SecuritySignalRecord,
  HypothesisRecord,
  ObjectCandidateRecord,
  SemanticCandidateRecord,
} from '@aegis/database';
import type { SignalType } from '@aegis/shared';

// ---------------------------------------------------------------------------
// fixtures — minimal structural records (unit level: no database)
// ---------------------------------------------------------------------------

const NOW = '2026-01-01T00:00:00.000Z';

function endpointFixture(overrides: Partial<EndpointRecord> = {}): EndpointRecord {
  return {
    id: 'EPD_TEST1',
    engagement_id: 'ENG_TEST',
    fingerprint: 'fp-endpoint-1',
    scheme: 'http',
    host: '127.0.0.1',
    port: 8080,
    path: '/api/orders/1',
    canonical_path: '/api/orders/{param}',
    canonical_confidence: 0.9,
    resource_family: '/api/orders',
    api_version: null,
    methods: [{ method: 'GET', observation_count: 2, identity_ids: ['IDN_A'], first_seen: NOW, last_seen: NOW }] as EndpointRecord['methods'],
    content_types: ['application/json'],
    authentication_observed: true,
    identities_observed: ['IDN_A', 'IDN_B'],
    status: 'OBSERVED',
    discovery_source: 'IMPORTED_TRAFFIC',
    confidence_category: 'OBSERVED',
    confidence: 1,
    observed_urls: ['http://127.0.0.1:8080/api/orders/1', 'http://127.0.0.1:8080/api/orders/2'],
    observation_count: 2,
    signal_count: 0,
    evidence_ids: [],
    merged_into: null,
    first_seen: NOW,
    last_seen: NOW,
    created_at: NOW,
    updated_at: NOW,
    ...overrides,
  };
}

function parameterFixture(overrides: Partial<ParameterRecord> = {}): ParameterRecord {
  return {
    id: 'PRM_TEST1',
    engagement_id: 'ENG_TEST',
    endpoint_id: 'EPD_TEST1',
    fingerprint: 'fp-param-1',
    name: 'order_id',
    location: 'PATH',
    observed_type: 'number',
    example_values: ['1', '2'],
    value_characteristics: ['NUMERIC'],
    semantic_candidates: [{ semantic: 'IDENTIFIER', confidence: 0.9, reason: 'name' }] as SemanticCandidateRecord[],
    identity_association: [],
    is_sensitive: false,
    confidence: 1,
    observation_count: 2,
    first_seen: NOW,
    last_seen: NOW,
    created_at: NOW,
    updated_at: NOW,
    ...overrides,
  };
}

function matrixFixture(overrides: Partial<AuthorizationMatrixRecord> = {}): AuthorizationMatrixRecord {
  return {
    id: 'AMX_TEST1',
    engagement_id: 'ENG_TEST',
    endpoint_id: 'EPD_TEST1',
    identity_id: null,
    object_ref: '1',
    action: 'READ',
    outcome: 'ALLOWED',
    status_code: 200,
    request_id: 'REQ_1',
    evidence_ids: [],
    observation_count: 1,
    fingerprint: 'fp-matrix-1',
    first_seen: NOW,
    last_seen: NOW,
    ...overrides,
  };
}

function signalFixture(overrides: Partial<SecuritySignalRecord> = {}): SecuritySignalRecord {
  return {
    id: 'SIG_TEST1',
    engagement_id: 'ENG_TEST',
    signal_type: 'CROSS_IDENTITY_OBJECT_REFERENCE' as SignalType,
    source: 'AUTHORIZATION_MATRIX',
    endpoint_id: 'EPD_TEST1',
    parameter_id: 'PRM_TEST1',
    identity_ids: ['IDN_A', 'IDN_B'],
    object_ref: '42',
    confidence: 0.8,
    summary: 'Object 42 accessible to two identities',
    metadata: {},
    status: 'NEW',
    evidence_ids: ['REQ_1', 'REQ_2'],
    fingerprint: 'fp-signal-1',
    created_at: NOW,
    updated_at: NOW,
    ...overrides,
  };
}

function hypothesisFixture(overrides: Partial<HypothesisRecord> = {}): HypothesisRecord {
  return {
    id: 'HYP_TEST1',
    engagement_id: 'ENG_TEST',
    type: 'AUTHORIZATION',
    statement: 'Endpoint /api/orders/{id} may not enforce ownership',
    status: 'ACTIVE',
    confidence: 0.6,
    priority: 0.7,
    source: 'system',
    parent_hypothesis_id: null,
    created_at: NOW,
    updated_at: NOW,
    confirmed_at: null,
    disproved_at: null,
    ...overrides,
  };
}

function objectFixture(overrides: Partial<ObjectCandidateRecord> = {}): ObjectCandidateRecord {
  return {
    id: 'OBJ_TEST1',
    engagement_id: 'ENG_TEST',
    name: 'order',
    kind: 'TRANSACTION',
    parameter_id: 'PRM_TEST1',
    endpoint_id: 'EPD_TEST1',
    example_values: ['1', '2'],
    owner_identity_id: 'IDN_A',
    lifecycle: {},
    confidence: 0.8,
    observation_count: 2,
    evidence_ids: [],
    fingerprint: 'fp-object-1',
    first_seen: NOW,
    last_seen: NOW,
    created_at: NOW,
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// §7-§8, §86-§87: endpoint normalization + canonicalization + fingerprints
// ---------------------------------------------------------------------------

describe('endpoint canonicalization (§7-§8, §86-§87)', () => {
  it('templates identifier-looking segments conservatively', () => {
    expect(canonicalizePath('/api/user/12').canonicalPath).toBe('/api/user/{param}');
    // short static words are NOT identifiers (avoids over-generalization)
    expect(canonicalizePath('/api/user/me').canonicalPath).toBe('/api/user/me');
    expect(canonicalizePath('/api/v1/orders/550e8400-e29b-41d4-a716-446655440000').canonicalPath).toBe(
      '/api/v1/orders/{param}',
    );
  });

  it('isIdentifierSegment accepts numeric/uuid/hex/long-opaque, rejects short words', () => {
    expect(isIdentifierSegment('123')).toBe(true);
    expect(isIdentifierSegment('550e8400-e29b-41d4-a716-446655440000')).toBe(true);
    expect(isIdentifierSegment('abc')).toBe(false);
    expect(isIdentifierSegment('orders')).toBe(false);
  });

  it('pathShape merges concrete ids into one canonical form (§7)', () => {
    expect(pathShape('/api/user/1')).toBe(pathShape('/api/user/2'));
    expect(pathShape('/api/user/1')).not.toBe(pathShape('/api/user/profile'));
  });

  it('endpoint fingerprints are deterministic and ignore volatile id values', () => {
    const partsA = parseUrlParts('http://127.0.0.1:8080/api/orders/1')!;
    const partsB = parseUrlParts('http://127.0.0.1:8080/api/orders/2')!;
    expect(endpointFingerprint(partsA, pathShape('/api/orders/1'))).toBe(
      endpointFingerprint(partsB, pathShape('/api/orders/2')),
    );
    // different host -> different fingerprint
    const partsC = parseUrlParts('http://elsewhere.test/api/orders/1')!;
    expect(endpointFingerprint(partsA, pathShape('/api/orders/1'))).not.toBe(
      endpointFingerprint(partsC, pathShape('/api/orders/1')),
    );
  });

  it('deriveEndpoint produces OBSERVED records with conservative templating (§13)', () => {
    const derived = deriveEndpoint({
      engagementId: 'ENG_TEST',
      url: 'http://127.0.0.1:8080/api/orders/1',
      method: 'GET',
      contentType: 'application/json',
      identityId: null,
      discoverySource: 'IMPORTED_TRAFFIC',
      evidenceId: null,
      at: NOW,
    })!;
    expect(derived.canonicalPath).toBe('/api/orders/{param}');
    expect(derived.canonicalConfidence).toBeLessThan(1); // single observation -> candidate only
    expect(derived.confidenceCategory).toBe('OBSERVED');
    expect(derived.confidence).toBe(1); // existence is a fact
  });

  it('canonicalUpgrade rises with distinct identifier observations (§7)', () => {
    const existing = endpointFixture({ observed_urls: ['http://127.0.0.1:8080/api/orders/1'] });
    const upgrade = canonicalUpgrade(existing, 'http://127.0.0.1:8080/api/orders/2')!;
    expect(upgrade.canonicalPath).toBe('/api/orders/{param}');
    expect(upgrade.canonicalConfidence).toBeGreaterThan(0.6);
    // differing NON-identifier segment -> no upgrade warranted
    expect(canonicalUpgrade(existing, 'http://127.0.0.1:8080/api/orders/1/items')).toBeNull();
  });

  it('clusters resource families and detects API versions (§86-§87)', () => {
    expect(resourceFamilyOf('/api/users/{param}/orders')).toBe('/api/users');
    expect(apiVersionOf('/api/v2/orders')).toBe('v2');
    expect(apiVersionOf('/api/internal/admin')).toBe('internal');
    expect(apiVersionOf('/api/orders')).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// §14-§18: parameter extraction + classification
// ---------------------------------------------------------------------------

describe('parameter extraction (§14-§15)', () => {
  it('extracts query, JSON, form, header and cookie parameters', () => {
    const extracted = extractRequestParameters({
      method: 'POST',
      url: 'http://127.0.0.1:8080/api/echo?tag=alpha&page=2',
      query: [
        { name: 'tag', value: 'alpha' },
        { name: 'page', value: '2' },
      ],
      headers: [
        { name: 'cookie', value: 'session=abc123; theme=dark' },
        { name: 'x-trace-id', value: 'trace-9' },
      ],
      bodyType: 'JSON',
      bodyParsed: { user_id: 10, note: 'hello' },
    });
    const names = extracted.map((parameter) => parameter.name);
    expect(names).toContain('tag');
    expect(names).toContain('page');
    expect(names).toContain('user_id');
    expect(names).toContain('note');
    // Cookie names become parameters with REDACTED values (§115)
    const cookieParam = extracted.find((parameter) => parameter.name === 'session' && parameter.location === 'COOKIE');
    expect(cookieParam?.exampleValue).toBe('«redacted»');
    expect(cookieParam?.isSensitive).toBe(true);
  });

  it('path parameter names come from the canonical path', () => {
    const names = pathParameterNames('/api/orders/{param}/items/{param}');
    expect(names).toHaveLength(2);
    expect(names[0]!.name).toBe('order_id'); // derived from the resource segment
    expect(pathParameterNames('/api/orders')).toHaveLength(0);
  });

  it('WebSocket message fields become parameters (§14)', () => {
    const fields = extractWsParameters(JSON.stringify({ type: 'SUBSCRIBE', channel: 'orders', since: 123 }));
    expect(fields.map((f) => f.name)).toContain('channel');
    expect(fields.map((f) => f.name)).toContain('type');
  });

  it('cross-endpoint relationships link shared names (§18)', () => {
    const relations = crossEndpointRelationships([
      { endpointFingerprint: 'A', names: ['user_id', 'tag'] },
      { endpointFingerprint: 'B', names: ['user_id', 'order_id'] },
    ]);
    expect(relations.some((r) => r.name === 'user_id' && r.endpoints.length === 2)).toBe(true);
  });

  it('parameter fingerprints are deterministic per endpoint+location+name', () => {
    expect(parameterFingerprint('EP', 'QUERY', 'q')).toBe(parameterFingerprint('EP', 'QUERY', 'q'));
    expect(parameterFingerprint('EP', 'QUERY', 'q')).not.toBe(parameterFingerprint('EP', 'JSON', 'q'));
  });
});

describe('parameter classification (§16-§17)', () => {
  it('detects deterministic value characteristics before any LLM (§17)', () => {
    expect(analyzeValue('550e8400-e29b-41d4-a716-446655440000').characteristics).toContain('UUID');
    expect(analyzeValue('user@example.test').characteristics).toContain('EMAIL');
    expect(analyzeValue('https://example.test/x').characteristics).toContain('URL');
    expect(analyzeValue('42').characteristics).toContain('NUMERIC');
    expect(analyzeValue('1700000000').characteristics).toContain('TIMESTAMP');
    expect(analyzeValue('{"a":1}').characteristics).toContain('JSON');
    expect(analyzeValue('eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sig').characteristics).toContain('JWT_LIKE');
    expect(analyzeValue('deadbeefdeadbeef').characteristics).toContain('HEXADECIMAL');
  });

  it('classifies obvious semantics as candidates with confidence (§16)', () => {
    const userId = classifyParameterName('user_id');
    expect(userId.some((candidate) => candidate.semantic === 'IDENTIFIER')).toBe(true);
    expect(classifyParameterName('redirect_url').some((c) => c.semantic === 'URL')).toBe(true);
    expect(classifyParameterName('csrf_token').some((c) => c.semantic === 'AUTHENTICATION')).toBe(true);
    // unknown names produce no strong claims
    expect(classifyParameterName('zzz').length).toBe(0);
  });

  it('flags sensitive parameter names (§15)', () => {
    expect(isSensitiveParameterName('password')).toBe(true);
    expect(isSensitiveParameterName('api_key')).toBe(true);
    expect(isSensitiveParameterName('session_id')).toBe(true);
    expect(isSensitiveParameterName('quantity')).toBe(false);
  });

  it('observed types map scalars and structures', () => {
    expect(observedTypeOf(5)).toBe('number');
    expect(observedTypeOf('x')).toBe('string');
    expect(observedTypeOf([1])).toBe('array');
    expect(observedTypeOf(null)).toBe('null');
    expect(observedTypeOf({})).toBe('object');
  });

  it('file-value heuristics stay conservative', () => {
    expect(looksLikeFileValue('report.pdf')).toBe(true);
    expect(looksLikeFileValue('hello')).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// §25-§28: differential comparison
// ---------------------------------------------------------------------------

function jsonResponse(body: string, status = 200, headers: Array<{ name: string; value: string }> = []) {
  return {
    status,
    headers,
    contentType: 'application/json',
    contentKind: 'JSON',
    bodyPreview: body,
    bodySha256: null,
    contentLength: body.length,
    truncated: false,
    timingMs: 100,
    redirectTo: null,
  };
}

describe('response comparison (§25-§28)', () => {
  it('represents JSON differences structurally (§26)', () => {
    const outcome = compareResponses(
      jsonResponse('{"id": 10, "name": "A", "note": "x"}'),
      jsonResponse('{"id": 11, "name": "A", "note": "x"}'),
    );
    expect(outcome.summary.schema_changed).toBe(false);
    expect(outcome.summary.values_changed.length).toBeGreaterThan(0);
    expect(outcome.summary.values_changed.some((change) => change.path.includes('id'))).toBe(true);
    expect(outcome.summary.body_similarity).toBeGreaterThan(0.5);
    expect(outcome.summary.body_similarity).toBeLessThan(1);
  });

  it('detects added and removed fields (schema change)', () => {
    const outcome = compareResponses(
      jsonResponse('{"id": 10}'),
      jsonResponse('{"id": 10, "debug": "stack trace data"}'),
    );
    expect(outcome.summary.schema_changed).toBe(true);
    expect(outcome.summary.fields_added).toContain('debug');
    expect(compareResponses(jsonResponse('{"a":1,"b":2}'), jsonResponse('{"a":1}')).summary.fields_removed).toContain('b');
  });

  it('marks volatile fields instead of deleting them (§27)', () => {
    expect(isVolatileField('timestamp', 1, 2)).toBe(true);
    expect(isVolatileField('request_id', 'a', 'b')).toBe(true);
    expect(isVolatileField('name', 'A', 'B')).toBe(false);
    const outcome = compareResponses(
      jsonResponse('{"id": 10, "timestamp": 1700000000}'),
      jsonResponse('{"id": 10, "timestamp": 1700000001}'),
    );
    expect(outcome.summary.volatile_fields.some((f) => f.includes('timestamp'))).toBe(true);
  });

  it('detects status, redirect and timing changes', () => {
    const outcome = compareResponses(jsonResponse('{}', 200), jsonResponse('{}', 403));
    expect(outcome.summary.status_changed).toBe(true);
    expect(outcome.summary.status_baseline).toBe(200);
    expect(outcome.summary.status_candidate).toBe(403);

    const redirected = compareResponses(
      { ...jsonResponse(''), redirectTo: null },
      { ...jsonResponse(''), redirectTo: '/login' },
    );
    expect(redirected.summary.redirect_changed).toBe(true);

    const slow = compareResponses(
      { ...jsonResponse('{}'), timingMs: 100 },
      { ...jsonResponse('{}'), timingMs: 900 },
    );
    expect(slow.summary.timing_changed).toBe(true);
  });

  it('binary comparison uses hashes (§26)', () => {
    const binary = (sha: string) => ({
      status: 200,
      headers: [],
      contentType: 'application/octet-stream',
      contentKind: 'BINARY',
      bodyPreview: null,
      bodySha256: sha,
      contentLength: 16,
      truncated: false,
      timingMs: 10,
      redirectTo: null,
    });
    const same = compareResponses(binary('a'.repeat(64)), binary('a'.repeat(64)));
    const diff = compareResponses(binary('a'.repeat(64)), binary('b'.repeat(64)));
    expect(same.detail['binary_equal']).toBe(true);
    expect(diff.detail['binary_equal']).toBe(false);
  });

  it('finds reflections with exact locations (§65)', () => {
    const reflections = findReflection([{ name: 'q', value: '<probe-1234>' }], {
      status: 200,
      headers: [{ name: 'x-echo', value: 'value <probe-1234> here' }],
      contentType: 'application/json',
      contentKind: 'JSON',
      bodyPreview: '{"echo": "<probe-1234>"}',
      bodySha256: null,
      contentLength: 20,
      truncated: false,
      timingMs: 5,
      redirectTo: null,
    });
    expect(reflections.length).toBeGreaterThan(0);
    expect(reflections[0]!.location).toBe('response_body');
    expect(reflections[0]!.excerpt).toContain('<probe-1234>');
  });

  it('differential fingerprints are deterministic and order-sensitive', () => {
    expect(differentialFingerprint('REQ_1', 'REQ_2')).toBe(differentialFingerprint('REQ_1', 'REQ_2'));
    expect(differentialFingerprint('REQ_1', 'REQ_2')).not.toBe(differentialFingerprint('REQ_2', 'REQ_1'));
  });
});

// ---------------------------------------------------------------------------
// §59-§60: JWT / token analysis
// ---------------------------------------------------------------------------

function makeJwt(header: Record<string, unknown>, payload: Record<string, unknown>): string {
  const enc = (obj: unknown) => Buffer.from(JSON.stringify(obj)).toString('base64url');
  return `${enc(header)}.${enc(payload)}.c2lnbmF0dXJl`;
}

describe('JWT analysis (§59-§60)', () => {
  it('decodes header/claims WITHOUT claiming verification (§59)', () => {
    const token = makeJwt({ alg: 'HS256', typ: 'JWT' }, { iss: 'lab', aud: 'app', sub: 'usera', exp: 4102444800, iat: 1700000000, role: 'user' });
    expect(looksLikeJwt(token)).toBe(true);
    const facts = analyzeJwt(token)!;
    expect(facts.algorithm).toBe('HS256');
    expect(facts.issuer).toBe('lab');
    expect(facts.audience).toBe('app');
    expect(facts.subject).toBe('usera');
    expect(facts.signature_present).toBe(true);
    expect(facts.signature_verified).toBe(false); // decoding != verification
    expect(facts.claims.some((c) => c.name === 'role')).toBe(true);
  });

  it('flags expired tokens and non-JWT shapes', () => {
    const expired = makeJwt({ alg: 'HS256' }, { exp: 1000 });
    expect(analyzeJwt(expired)?.expired).toBe(true);
    expect(looksLikeJwt('not-a-jwt')).toBe(false);
    expect(analyzeJwt('not-a-jwt')).toBeNull();
  });

  it('compares tokens across identities: stable vs identity-specific claims (§60)', () => {
    const tokenA = makeJwt({ alg: 'HS256' }, { iss: 'lab', role: 'user', sub: 'usera' });
    const tokenB = makeJwt({ alg: 'HS256' }, { iss: 'lab', role: 'user', sub: 'userb' });
    const comparison = compareTokens([
      { identityId: 'IDN_A', kind: 'RESPONSE_BODY', facts: analyzeJwt(tokenA)!, sourceSummary: 'A' },
      { identityId: 'IDN_B', kind: 'RESPONSE_BODY', facts: analyzeJwt(tokenB)!, sourceSummary: 'B' },
    ])!;
    expect(comparison.stable_claims).toContain('iss');
    expect(comparison.subject_claims).toContain('sub');
    expect(comparison.stable_claims).not.toContain('sub');
  });

  it('scans untrusted text for JWT patterns', () => {
    const token = makeJwt({ alg: 'HS256' }, { sub: 'x' });
    const found = scanForJwtTokens(`Authorization: Bearer ${token} and noise`);
    expect(found.length).toBe(1);
    expect(found[0]!.token).toBe(token);
    expect(found[0]!.facts.algorithm).toBe('HS256');
  });
});

// ---------------------------------------------------------------------------
// §19, §96-§97: object model
// ---------------------------------------------------------------------------

describe('object detection (§19, §96-§97)', () => {
  it('derives object names from identifier parameters', () => {
    expect(objectNameFromParameter('order_id')).toBe('order');
    expect(objectNameFromParameter('document_id')).toBe('document');
    expect(objectNameFromParameter('quantity')).toBeNull();
    expect(objectKindFromName('invoice')).toBe('TRANSACTION');
    expect(objectKindFromName('user')).toBe('USER');
  });

  it('creates candidates only from identifierish non-sensitive parameters (§19)', () => {
    const candidates = objectCandidatesFromParameters(
      [
        parameterFixture({ id: 'PRM_1', name: 'order_id', semantic_candidates: [{ semantic: 'IDENTIFIER', confidence: 0.9, reason: 'n' }] as unknown as SemanticCandidateRecord[] }),
        parameterFixture({ id: 'PRM_2', name: 'password', is_sensitive: true }),
        parameterFixture({ id: 'PRM_3', name: 'search', semantic_candidates: [], value_characteristics: [], example_values: ['hello world'] }),
      ],
      [endpointFixture()],
    );
    expect(candidates).toHaveLength(1);
    expect(candidates[0]!.name).toBe('order');
    expect(candidates[0]!.kind).toBe('TRANSACTION');
  });

  it('object fingerprints are deterministic (§111)', () => {
    expect(objectFingerprint('order', '/api/orders')).toBe(objectFingerprint('order', '/api/orders'));
    expect(objectFingerprint('order', '/api/orders')).not.toBe(objectFingerprint('note', '/api/notes'));
  });
});

// ---------------------------------------------------------------------------
// §30-§35: workflow engine
// ---------------------------------------------------------------------------

const seq = (steps: Array<[string, string, number | null, string | null]>): Array<Parameters<typeof stateNameForStep>[0] & Record<string, unknown>> =>
  steps.map(([path, method, status, identityId], index) => ({
    requestId: `REQ_${index}`,
    method,
    path,
    status,
    identityId,
    at: NOW,
    endpointId: `EPD_${index}`,
    evidenceId: null,
  }));

describe('workflow reconstruction (§30-§35)', () => {
  it('builds candidate transitions from observed sequences (§34)', () => {
    const steps = seq([
      ['/login', 'POST', 200, 'IDN_A'],
      ['/dashboard', 'GET', 200, 'IDN_A'],
      ['/api/orders', 'GET', 200, 'IDN_A'],
      ['/api/orders/1/pay', 'POST', 200, 'IDN_A'],
      ['/api/orders/1/confirm', 'POST', 200, 'IDN_A'],
    ]);
    const { transitions, states } = transitionsFromSequence(steps);
    expect(transitions.length).toBeGreaterThan(0);
    expect(states.size).toBeGreaterThanOrEqual(3);
    // POST /api/orders/1/pay names the state ORDER_PAY (resource+verb)
    expect([...states.keys()]).toContain('ORDER_PAY');
    expect([...states.keys()]).toContain('ORDER_CONFIRM');
    // transitions are deduplicated by fingerprint (§111)
    const fingerprints = new Set(transitions.map((transition) => transition.fingerprint));
    expect(fingerprints.size).toBe(transitions.length);
  });

  it('segments sequences by identity (§34)', () => {
    const steps = seq([
      ['/a', 'GET', 200, 'IDN_A'],
      ['/b', 'GET', 200, 'IDN_B'],
      ['/c', 'GET', 200, 'IDN_A'],
    ]);
    const segments = segmentByIdentity(steps);
    const all = Array.from(segments.values()).flat();
    expect(all).toHaveLength(3); // no steps lost
    expect(Array.from(segments.keys()).some((key) => key.startsWith('IDN_A#'))).toBe(true);
    expect(Array.from(segments.keys()).some((key) => key.startsWith('IDN_B#'))).toBe(true);
  });

  it('detects prerequisite anomalies (business-logic signals §36)', () => {
    // ORDER_CONFIRM observed WITHOUT preceding ORDER_PAY or ORDER_CREATED transitions
    const { transitions } = transitionsFromSequence(
      seq([
        ['/api/orders', 'POST', 201, 'IDN_A'],
        ['/api/orders/1/confirm', 'POST', 200, 'IDN_A'],
      ]),
    );
    const anomalies = prerequisiteAnomalies(transitions);
    expect(anomalies.length).toBe(2); // ORDER_PAY missing AND ORDER_CREATED missing
    for (const anomaly of anomalies) {
      expect(anomaly.anomaly).toBe('PREREQUISITE_MISSING');
      expect(anomaly.detail.length).toBeGreaterThan(0);
    }
  });

  it('satisfied prerequisites produce no anomalies (§36 negative control)', () => {
    const { transitions } = transitionsFromSequence(
      seq([
        ['/dashboard', 'GET', 200, 'IDN_A'],
        ['/api/orders', 'POST', 201, 'IDN_A'],
        ['/api/orders/1/pay', 'POST', 200, 'IDN_A'],
        ['/api/orders/1/confirm', 'POST', 200, 'IDN_A'],
      ]),
    );
    expect(prerequisiteAnomalies(transitions)).toHaveLength(0);
  });

  it('trigger summaries are bounded and informative', () => {
    const summary = triggerSummaryFor({ requestId: 'R', method: 'POST', path: '/api/payment', status: 200, identityId: 'IDN_A', at: NOW, endpointId: null, evidenceId: null });
    expect(summary).toContain('POST');
    expect(summary).toContain('/api/payment');
  });
});

// ---------------------------------------------------------------------------
// §42-§43: signal engine
// ---------------------------------------------------------------------------

describe('security signal generation (§42-§43)', () => {
  it('cross-identity matrix differences produce signals (§23)', () => {
    const signals = signalsFromMatrix(
      endpointFixture(),
      [
        matrixFixture({ identity_id: 'IDN_A', outcome: 'ALLOWED', object_ref: '1' }),
        matrixFixture({ identity_id: 'IDN_B', outcome: 'ALLOWED', object_ref: '1' }),
        matrixFixture({ identity_id: null, outcome: 'DENIED', object_ref: '1', status_code: 401 }),
      ],
    );
    expect(signals.length).toBeGreaterThan(0);
    expect(signals[0]!.signalType).toBe('CROSS_IDENTITY_DIFFERENCE');
    expect(signals[0]!.endpointId).toBe('EPD_TEST1');
    expect(signals[0]!.confidence).toBeGreaterThan(0);
  });

  it('same-outcome matrices produce no difference signals', () => {
    const signals = signalsFromMatrix(endpointFixture(), [
      matrixFixture({ identity_id: 'IDN_A', outcome: 'DENIED' }),
      matrixFixture({ identity_id: 'IDN_B', outcome: 'DENIED' }),
    ]);
    expect(signals).toHaveLength(0);
  });

  it('token-bearing parameters produce OBJECT_IDENTIFIER signals, not conclusions (§19)', () => {
    const signals = signalsFromParameters(endpointFixture(), [
      parameterFixture({ name: 'order_id', location: 'QUERY', example_values: ['1'], semantic_candidates: [{ semantic: 'IDENTIFIER', confidence: 0.9, reason: 'name' }] as unknown as SemanticCandidateRecord[] }),
    ]);
    expect(signals.some((signal) => signal.signalType === 'OBJECT_IDENTIFIER')).toBe(true);
    const identifierSignal = signals.find((signal) => signal.signalType === 'OBJECT_IDENTIFIER')!;
    expect(identifierSignal.metadata['note']).toContain('not an authorization vulnerability');
  });

  it('privilege/monetary parameters produce CLIENT_CONTROLLED_VALUE signals', () => {
    const signals = signalsFromParameters(endpointFixture(), [
      parameterFixture({
        id: 'PRM_ROLE',
        name: 'role',
        location: 'JSON',
        semantic_candidates: [{ semantic: 'PRIVILEGE', confidence: 0.8, reason: 'role' }] as unknown as SemanticCandidateRecord[],
      }),
    ]);
    expect(signals.some((signal) => signal.signalType === 'CLIENT_CONTROLLED_VALUE')).toBe(true);
  })

  it('plain text parameters produce no signals (noise control)', () => {
    const signals = signalsFromParameters(endpointFixture(), [
      parameterFixture({ id: 'PRM_Q', name: 'search', location: 'QUERY', semantic_candidates: [], value_characteristics: [] }),
    ]);
    expect(signals).toHaveLength(0);
  });

  it('error disclosure is a signal, never a conclusion (§63)', () => {
    const signals = signalsFromResponse(endpointFixture(), {
      status: 500,
      contentKind: 'HTML',
      bodyPreview: 'Traceback (most recent call last): File "/app/main.py"',
      redirectTo: null,
    });
    expect(signals.some((signal) => signal.signalType === 'ERROR_DISCLOSURE')).toBe(true);
    const disclosure = signals.find((signal) => signal.signalType === 'ERROR_DISCLOSURE')!;
    expect(disclosure.metadata['indicators']).toContain('STACK_TRACE');
  });

  it('auth state changes and redirects become signals (§22)', () => {
    const authSignal = authStateChangeSignal({
      endpointId: 'EPD_LOGIN',
      identityId: 'IDN_A',
      change: 'LOGIN',
      detail: 'session established',
      evidenceIds: ['REQ_1'],
    });
    expect(authSignal?.signalType).toBe('AUTH_STATE_CHANGE');

    // Authenticated identity redirected to a login-like target (suspicious)
    const redirectSignal = unexpectedRedirectSignal(endpointFixture(), {
      redirectTo: '/login?next=/admin',
      identityId: 'IDN_A',
      authenticated: true,
    });
    expect(redirectSignal?.signalType).toBe('UNEXPECTED_REDIRECT');
    // Anonymous -> login redirect is NORMAL (no signal)
    expect(
      unexpectedRedirectSignal(endpointFixture(), { redirectTo: '/login', identityId: null, authenticated: false }),
    ).toBeNull();
  });

  it('reflections and token patterns become signals (§65, §59)', () => {
    const reflection = reflectionSignal(
      endpointFixture(),
      [{ name: 'q', value: '<probe-1>', location: 'response_body', excerpt: '...' }],
      { q: 'PRM_Q' },
    );
    expect(reflection?.signalType).toBe('REFLECTED_INPUT');
    expect(reflection?.summary).toContain('not automatically XSS');

    const token = makeJwt({ alg: 'HS256' }, { sub: 'usera' });
    const tokenSignal = tokenPatternSignal(endpointFixture(), {
      facts: analyzeJwt(token)!,
      sourceSummary: 'response body',
    });
    expect(tokenSignal.signalType).toBe('TOKEN_PATTERN');
    expect(tokenSignal.metadata['signature_verified']).toBe(false);
  });

  it('state transition anomalies and unexpected methods become signals (§36)', () => {
    const anomaly = stateTransitionAnomalySignal({
      workflowId: 'WFL_1',
      identityId: 'IDN_A',
      triggerSummary: 'POST /api/orders/1/confirm',
      anomaly: 'PREREQUISITE_MISSING',
      detail: 'ORDER_PAID not observed before confirmation',
      evidenceIds: ['REQ_1'],
    });
    expect(anomaly?.signalType).toBe('STATE_TRANSITION_ANOMALY');

    const methodSignal = unexpectedMethodSignal(endpointFixture(), 'DELETE');
    expect(methodSignal?.signalType).toBe('UNEXPECTED_METHOD_BEHAVIOR');
    // GET is not state-changing — no signal
    expect(unexpectedMethodSignal(endpointFixture(), 'GET')).toBeNull();
  });

  it('unusual response differences produce signals bounded by identity presence (§24)', () => {
    const signal = unusualResponseDifferenceSignal({
      endpointId: 'EPD_TEST1',
      baselineIdentity: 'IDN_A',
      candidateIdentity: 'IDN_B',
      summary: {
        status_changed: true,
        status_baseline: 200,
        status_candidate: 403,
        headers_changed: [],
        schema_changed: false,
        fields_added: [],
        fields_removed: [],
        values_changed: [],
        body_similarity: 0.9,
        redirect_changed: false,
        timing_changed: false,
        volatile_fields: [],
      },
      evidenceIds: ['REQ_1', 'REQ_2'],
    });
    expect(signal?.signalType).toBe('UNUSUAL_RESPONSE_DIFFERENCE');
  });

  it('object candidates alone are not signals — OBJECT_IDENTIFIER comes from parameters (§19, §121)', () => {
    // Honest no-op: the deterministic layer refuses to call an object
    // reference a signal by itself (OBSERVATION != VULNERABILITY).
    const signals = objectSignalCandidates([objectFixture({ example_values: ['1', '2'], owner_identity_id: 'IDN_A' })]);
    expect(signals).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------
// §44-§47: hypothesis candidates
// ---------------------------------------------------------------------------

describe('hypothesis candidates (§44-§47)', () => {
  it('produces PRIMARY + COMPETING interpretations, never one (§45)', () => {
    const groups = hypothesisGroupsFromSignals([
      signalFixture({ signal_type: 'CROSS_IDENTITY_OBJECT_REFERENCE', summary: 'Order 42 visible to userb' }),
    ]);
    expect(groups.length).toBe(1);
    const group = groups[0]!;
    expect(group.primary.statement.length).toBeGreaterThan(10);
    expect(group.competitors.length).toBeGreaterThanOrEqual(2); // H2 public, H3 shared, ... (§45)
    expect(group.distinguishingTests.length).toBeGreaterThan(0); // §46/§47
    expect(group.primary.signal_id).toBe('SIG_TEST1');
  });

  it('requires evidence lists before promotion (§46)', () => {
    const groups = hypothesisGroupsFromSignals([signalFixture()]);
    for (const group of groups) {
      expect(group.primary.required_evidence.length).toBeGreaterThan(0);
    }
  });
});

// ---------------------------------------------------------------------------
// §48-§57: mutation strategies
// ---------------------------------------------------------------------------

describe('mutation strategies (§51-§57)', () => {
  const context = {
    canonicalPath: '/api/orders/{param}',
    observedUrl: 'http://127.0.0.1:8080/api/orders/1',
    parameters: [
      parameterFixture({ name: 'order_id', location: 'PATH' }),
      parameterFixture({ id: 'PRM_2', name: 'quantity', location: 'JSON', observed_type: 'number', example_values: ['2'] }),
    ],
    objectValues: [
      { name: 'order_id', value: '1' },
      { name: 'order_id', value: '2' },
    ],
    identityOptions: [
      { identityId: 'IDN_A', label: 'usera' },
      { identityId: 'IDN_B', label: 'userb' },
    ],
    allowDestructive: false,
  };

  it('IDENTIFIER mutations swap only CONTROLLED observed values (§52)', () => {
    const plans = generateMutations('IDENTIFIER', context);
    expect(plans.length).toBeGreaterThan(0);
    for (const plan of plans) {
      expect(plan.category).toBe('IDENTIFIER');
      for (const mutation of plan.mutations) {
        const value = String(mutation.value ?? '');
        expect(['1', '2']).toContain(value); // never uncontrolled values
      }
    }
  });

  it('BOUNDARY mutations are bounded per call (§54)', () => {
    const plans = generateMutations('BOUNDARY', context);
    expect(plans.length).toBeLessThanOrEqual(4);
  });

  it('TYPE mutations stay scalar (§53)', () => {
    const plans = generateMutations('TYPE', context);
    for (const plan of plans) {
      for (const mutation of plan.mutations) {
        expect(['string', 'number', 'boolean', 'undefined', 'object', 'null']).toContain(typeof mutation.value);
        if (mutation.value !== null && typeof mutation.value === 'object') {
          expect(Array.isArray(mutation.value)).toBe(false);
        }
      }
    }
  });

  it('STRUCTURE mutations remove fields, never blind fuzz (§55)', () => {
    const plans = generateMutations('STRUCTURE', context);
    expect(plans.some((plan) => plan.mutations.some((m) => m.operation === 'remove'))).toBe(true);
  });

  it('AUTHORIZATION mutations reference identities, never credentials (§57)', () => {
    const plans = generateMutations('AUTHORIZATION', context);
    expect(plans.length).toBeGreaterThan(0);
    for (const plan of plans) {
      if (plan.identityId !== null) {
        expect(['IDN_A', 'IDN_B']).toContain(plan.identityId);
      }
      expect(JSON.stringify(plan)).not.toContain('password');
      expect(JSON.stringify(plan)).not.toContain('secret');
    }
  });
});

// ---------------------------------------------------------------------------
// §20, §23, §98: authorization mapping
// ---------------------------------------------------------------------------

describe('authorization mapping (§20, §23, §98)', () => {
  it('classifies outcomes per identity (§23)', () => {
    expect(classifyOutcome({ status: 200, redirectTo: null, identityId: 'A' })).toBe('ALLOWED');
    expect(classifyOutcome({ status: 401, redirectTo: null, identityId: null })).toBe('DENIED');
    expect(classifyOutcome({ status: 403, redirectTo: null, identityId: 'B' })).toBe('DENIED');
    expect(classifyOutcome({ status: 302, redirectTo: '/login', identityId: null })).toBe('REDIRECTED');
    expect(classifyOutcome({ status: 500, redirectTo: null, identityId: 'A' })).toBe('ERROR');
    expect(classifyOutcome({ status: null, redirectTo: null, identityId: 'A' })).toBe('UNKNOWN');
  });

  it('maps the authentication surface (§21-§22)', () => {
    expect(classifyAuthSurface('POST', '/login', 200)).toBe('LOGIN_SUBMIT');
    expect(classifyAuthSurface('GET', '/login', 200)).toBe('LOGIN_PAGE');
    expect(classifyAuthSurface('POST', '/logout', 200)).toBe('LOGOUT');
    expect(classifyAuthSurface('POST', '/register', 201)).toBe('REGISTRATION');
    expect(classifyAuthSurface('GET', '/api/orders', 401)).toBe('SESSION_EXPIRATION');
    expect(classifyAuthSurface('GET', '/password-reset', 200)).toBe('PASSWORD_RESET');
  })

  it('object refs derive from templated path positions (§19, §98)', () => {
    const endpoint = endpointFixture({ canonical_path: '/api/orders/{param}' });
    expect(objectRefForRequest(endpoint, 'http://127.0.0.1:8080/api/orders/42')).toBe('order:42');
    expect(
      objectRefForRequest(endpointFixture({ canonical_path: '/api/orders' }), 'http://127.0.0.1:8080/api/orders'),
    ).toBeNull();
  });

  it('object refs also derive from identifier parameters', () => {
    expect(
      objectRefsFromParameters(endpointFixture(), [
        { name: 'invoice_id', location: 'QUERY', exampleValues: ['381'], identifierish: true },
        { name: 'search', location: 'QUERY', exampleValues: ['x'], identifierish: false },
      ]),
    ).toEqual(['invoice:381']);
  });

  it('matrix fingerprints are identity+endpoint+object+action keyed (§111)', () => {
    expect(matrixFingerprint('EPD', 'IDN', 'order:1', 'READ')).toBe(matrixFingerprint('EPD', 'IDN', 'order:1', 'READ'));
    expect(matrixFingerprint('EPD', 'IDN', 'order:1', 'READ')).not.toBe(matrixFingerprint('EPD', 'IDN2', 'order:1', 'READ'));
    // Outcome deliberately excluded: cells track latest outcome over time
    expect(matrixFingerprint('EPD', 'IDN', 'order:1', 'READ')).toBe(matrixFingerprint('EPD', 'IDN', 'order:1', 'READ'));
  });

  it('authentication boundaries are detected from login/logout outcomes (§22)', () => {
    expect(authBoundaryFor('LOGIN_SUBMIT', 'POST', 200)).toEqual({ before: 'ANONYMOUS', after: 'AUTHENTICATED' });
    expect(authBoundaryFor('LOGOUT', 'POST', 200)).toEqual({ before: 'AUTHENTICATED', after: 'ANONYMOUS' });
    expect(authBoundaryFor('LOGIN_SUBMIT', 'POST', 401)).toBeNull();
    expect(authenticationObserved([matrixFixture({ identity_id: 'IDN_A', outcome: 'ALLOWED' })])).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// §48-§50: test planning
// ---------------------------------------------------------------------------

describe('test planning (§48-§50)', () => {
  it('test fingerprints are deterministic and exclude volatile object refs (§50)', () => {
    const fp = testFingerprint({
      hypothesisId: 'HYP_1',
      endpointFingerprint: 'EPD_FP',
      identity: 'IDN_A',
      mutationCategory: 'AUTHORIZATION',
      relevantParameter: 'order_id',
    });
    expect(fp).toBe(
      testFingerprint({
        hypothesisId: 'HYP_1',
        endpointFingerprint: 'EPD_FP',
        identity: 'IDN_A',
        mutationCategory: 'AUTHORIZATION',
        relevantParameter: 'order_id',
      }),
    );
    // identity and category are semantic inputs -> different fingerprints
    expect(fp).not.toBe(
      testFingerprint({
        hypothesisId: 'HYP_1',
        endpointFingerprint: 'EPD_FP',
        identity: 'IDN_B',
        mutationCategory: 'AUTHORIZATION',
        relevantParameter: 'order_id',
      }),
    );
    expect(fp).not.toBe(
      testFingerprint({
        hypothesisId: 'HYP_1',
        endpointFingerprint: 'EPD_FP',
        identity: 'IDN_A',
        mutationCategory: 'BOUNDARY',
        relevantParameter: 'order_id',
      }),
    );
  });

  it('information gain ranks distinguishing tests (§47)', () => {
    // AUTHZ-failure vs intentional-public: anonymous replay separates them
    const gain = expectedInformationGain(['AUTHORIZATION', 'CONFIGURATION'], 'ANONYMOUS_REPLAY');
    const lowGain = expectedInformationGain(['AUTHORIZATION'], 'MUTATION');
    expect(gain).toBeGreaterThan(lowGain);
    expect(gain).toBeGreaterThan(0.4);
  });

  it('plans candidates with preconditions and duplicate suppression (§49, §118)', () => {
    const plan = planTests({
      engagementId: 'ENG_TEST',
      hypotheses: [hypothesisFixture()],
      endpoints: [endpointFixture()],
      matrix: [
        matrixFixture({ identity_id: 'IDN_A', outcome: 'ALLOWED', object_ref: 'order:1' }),
        matrixFixture({ identity_id: 'IDN_B', outcome: 'ALLOWED', object_ref: 'order:1' }),
      ],
      objects: [objectFixture()],
      parametersByEndpoint: new Map([['EPD_TEST1', [parameterFixture()]]]),
      identities: [
        { id: 'IDN_A', name: 'usera', role: 'user' },
        { id: 'IDN_B', name: 'userb', role: 'user' },
      ],
      existingFingerprints: new Set(),
      allowDestructive: false,
    });
    expect(plan.candidates.length).toBeGreaterThan(0);
    for (const candidate of plan.candidates) {
      expect(candidate.fingerprint.length).toBeGreaterThan(0);
      expect(candidate.estimated_cost).toBeGreaterThanOrEqual(1);
      expect(candidate.expected_information_gain).toBeGreaterThanOrEqual(0);
      expect(candidate.preconditions.duplicate_absent).toBe(true);
    }
    // cross-identity comparison is planned when 2+ identities exist (§61)
    expect(plan.candidates.some((candidate) => candidate.test_type === 'IDENTITY_COMPARISON')).toBe(true);
    // anonymous replay is planned — it distinguishes public vs authz (§47)
    expect(plan.candidates.some((candidate) => candidate.test_type === 'ANONYMOUS_ACCESS')).toBe(true);

    // Re-planning with recorded fingerprints dedups (§49 duplicate precondition)
    const replan = planTests({
      engagementId: 'ENG_TEST',
      hypotheses: [hypothesisFixture()],
      endpoints: [endpointFixture()],
      matrix: [
        matrixFixture({ identity_id: 'IDN_A', outcome: 'ALLOWED', object_ref: 'order:1' }),
        matrixFixture({ identity_id: 'IDN_B', outcome: 'ALLOWED', object_ref: 'order:1' }),
      ],
      objects: [objectFixture()],
      parametersByEndpoint: new Map([['EPD_TEST1', [parameterFixture()]]]),
      identities: [
        { id: 'IDN_A', name: 'usera', role: 'user' },
        { id: 'IDN_B', name: 'userb', role: 'user' },
      ],
      existingFingerprints: new Set(plan.candidates.map((c) => c.fingerprint)),
      allowDestructive: false,
    });
    expect(replan.candidates.every((candidate) => !candidate.preconditions.duplicate_absent)).toBe(true);
  });

  it('recommends REQUIRES_IDENTITY for authz hypotheses with a single identity (§131)', () => {
    const plan = planTests({
      engagementId: 'ENG_TEST',
      hypotheses: [hypothesisFixture()],
      endpoints: [endpointFixture()],
      matrix: [matrixFixture({ identity_id: 'IDN_A', outcome: 'ALLOWED', object_ref: 'order:1' })],
      objects: [objectFixture()],
      parametersByEndpoint: new Map([['EPD_TEST1', [parameterFixture()]]]),
      identities: [{ id: 'IDN_A', name: 'usera', role: 'user' }],
      existingFingerprints: new Set(),
      allowDestructive: false,
    });
    expect(plan.stopRecommendations.some((r) => r.recommendation === 'REQUIRES_IDENTITY')).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// §84-§85: prioritization
// ---------------------------------------------------------------------------

describe('attack-surface prioritization (§84-§85)', () => {
  it('prioritizes object/privilege endpoints over /about (§85)', () => {
    const about = endpointFixture({
      id: 'EPD_ABOUT',
      canonical_path: '/about',
      path: '/about',
      resource_family: '/',
      authentication_observed: false,
      identities_observed: [],
      methods: [{ method: 'GET', observation_count: 1, identity_ids: [], first_seen: NOW, last_seen: NOW }] as EndpointRecord['methods'],
    });
    const orders = endpointFixture(); // /api/orders/{param}, auth, 2 identities
    const admin = endpointFixture({
      id: 'EPD_ADMIN',
      canonical_path: '/api/admin/users',
      path: '/api/admin/users',
    });
    const ranked = rankEndpoints([about, orders, admin], {
      parametersByEndpoint: new Map([
        ['EPD_TEST1', [parameterFixture()]],
        ['EPD_ADMIN', []],
        ['EPD_ABOUT', []],
      ]),
      objects: [objectFixture()],
      workflowTriggerEndpointIds: new Set(),
      authenticationObserved: new Set(['EPD_TEST1', 'EPD_ADMIN']),
    });
    expect(ranked[0]!.endpoint.id).not.toBe('EPD_ABOUT');
    const byId = new Map(ranked.map((r) => [r.endpoint.id, r.priority]));
    expect(byId.get('EPD_TEST1')!).toBeGreaterThan(byId.get('EPD_ABOUT')!);
    expect(byId.get('EPD_ADMIN')!).toBeGreaterThan(byId.get('EPD_ABOUT')!);
    expect(ranked[0]!.reason.length).toBeGreaterThan(0);
  });
});

// ---------------------------------------------------------------------------
// §70-§75: verification + evidence strength
// ---------------------------------------------------------------------------

describe('verification engine (§70-§75)', () => {
  it('REFUTES when the object is anonymously public (§72 alternative explanation)', () => {
    const outcome = evaluateVerification({
      hypothesis: hypothesisFixture(),
      endpoint: endpointFixture(),
      matrix: [
        matrixFixture({ identity_id: null, outcome: 'ALLOWED', object_ref: 'order:42', status_code: 200 }),
        matrixFixture({ identity_id: 'IDN_A', outcome: 'ALLOWED', object_ref: 'order:42' }),
        matrixFixture({ identity_id: 'IDN_B', outcome: 'ALLOWED', object_ref: 'order:42' }),
      ],
      differentials: [],
      anonymousOutcome: 'ALLOWED',
    });
    expect(outcome.status).toBe('REFUTED');
    // IS_OBJECT_PUBLIC check PASSES (the object IS public) -> blocks promotion
    expect(outcome.checklist.some((check) => check.check === 'IS_OBJECT_PUBLIC' && check.status === 'PASS')).toBe(true);
    expect(outcome.alternatives.some((a) => a.explanation.includes('public') && !a.refuted)).toBe(true);
    expect(outcome.result['promotion']).toBe(false);
  });

  it('VERIFIES when the non-owner receives owner-identical protected content (§99)', () => {
    const outcome = evaluateVerification({
      hypothesis: hypothesisFixture(),
      endpoint: endpointFixture(),
      matrix: [
        // the NON-OWNER's permissive access, reproduced twice
        matrixFixture({ identity_id: 'IDN_B', outcome: 'ALLOWED', object_ref: 'order:42', observation_count: 2 }),
        matrixFixture({ identity_id: null, outcome: 'DENIED', object_ref: 'order:42', status_code: 401 }),
      ],
      differentials: [
        {
          id: 'DFR_1',
          engagement_id: 'ENG_TEST',
          test_id: null,
          hypothesis_id: 'HYP_TEST1',
          baseline_request_id: 'REQ_1',
          candidate_request_id: 'REQ_2',
          baseline_identity: 'IDN_A',
          candidate_identity: 'IDN_B',
          // owner and non-owner responses are semantically identical except
          // a volatile timestamp — the protected content reached the
          // non-owner unchanged (non-volatile diff is empty)
          summary: {
            status_changed: false,
            status_baseline: 200,
            status_candidate: 200,
            headers_changed: [],
            schema_changed: false,
            fields_added: [],
            fields_removed: [],
            values_changed: [{ path: 'server_time', baseline: '1700000000', candidate: '1700000001', volatile: true }],
            body_similarity: 0.95,
            redirect_changed: false,
            timing_changed: false,
            volatile_fields: ['server_time'],
          },
          detail: {},
          created_at: NOW,
        },
      ],
      anonymousOutcome: 'DENIED',
    });
    expect(outcome.status).toBe('VERIFIED');
    expect(outcome.result['promotion']).toBe(true);
    expect(outcome.evidenceIds).toContain('DFR_1');
    expect(outcome.checklist.some((check) => check.check === 'DOES_BASELINE_DIFFER' && check.status === 'FAIL')).toBe(true);
  });

  it('REFUTES when responses differ (access appears differentiated, §72)', () => {
    const outcome = evaluateVerification({
      hypothesis: hypothesisFixture(),
      endpoint: endpointFixture(),
      matrix: [
        matrixFixture({ identity_id: 'IDN_A', outcome: 'ALLOWED', object_ref: 'order:42', observation_count: 2 }),
        matrixFixture({ identity_id: 'IDN_B', outcome: 'DENIED', object_ref: 'order:42', status_code: 403 }),
        matrixFixture({ identity_id: null, outcome: 'DENIED', object_ref: 'order:42', status_code: 401 }),
      ],
      differentials: [
        {
          id: 'DFR_2',
          engagement_id: 'ENG_TEST',
          test_id: null,
          hypothesis_id: 'HYP_TEST1',
          baseline_request_id: 'REQ_1',
          candidate_request_id: 'REQ_2',
          baseline_identity: 'IDN_A',
          candidate_identity: 'IDN_B',
          summary: {
            status_changed: true,
            status_baseline: 200,
            status_candidate: 403,
            headers_changed: [],
            schema_changed: false,
            fields_added: [],
            fields_removed: [],
            values_changed: [],
            body_similarity: 0.2,
            redirect_changed: false,
            timing_changed: false,
            volatile_fields: [],
          },
          detail: {},
          created_at: NOW,
        },
      ],
      anonymousOutcome: 'DENIED',
    });
    expect(outcome.status).toBe('REFUTED');
    expect(String(outcome.result['reason'])).toContain('differentiated');
    expect(outcome.result['promotion']).toBe(false);
  });

  it('INCONCLUSIVE is a valid outcome when evidence is thin (§103)', () => {
    const outcome = evaluateVerification({
      hypothesis: hypothesisFixture(),
      endpoint: null,
      matrix: [matrixFixture({ identity_id: 'IDN_A', outcome: 'ALLOWED' })],
      differentials: [],
      anonymousOutcome: null,
    });
    expect(outcome.status).toBe('INCONCLUSIVE');
    expect(Array.isArray(outcome.result['missing_evidence'])).toBe(true);
  });

  it('dead-end payloads record why the hypothesis failed (§75)', () => {
    const outcome = evaluateVerification({
      hypothesis: hypothesisFixture({ status: 'DISPROVED' }),
      endpoint: endpointFixture(),
      matrix: [matrixFixture({ identity_id: null, outcome: 'ALLOWED' })],
      differentials: [],
      anonymousOutcome: 'ALLOWED',
    });
    const payload = deadEndPayload(
      {
        id: 'VER_1',
        engagement_id: 'ENG_TEST',
        hypothesis_id: 'HYP_TEST1',
        kind: 'AUTHORIZATION',
        status: 'REFUTED',
        alternatives: outcome.alternatives,
        checklist: outcome.checklist,
        result: outcome.result,
        evidence_ids: [],
        created_at: NOW,
        completed_at: NOW,
      },
      hypothesisFixture(),
    );
    expect(payload.description.length).toBeGreaterThan(0);
    expect(payload.reason.length).toBeGreaterThan(0);
    expect(payload.tests.length).toBeGreaterThanOrEqual(0);
  });

  it('evidence strength is explainable (§70)', () => {
    const strong = classifyEvidence({
      reproductionCount: 3,
      crossIdentityEvidence: true,
      objectLevelEvidence: true,
      baselineDifferential: null,
      anonymousOutcome: 'DENIED',
    });
    expect(['MODERATE', 'STRONG', 'CONFIRMATORY']).toContain(strong.level);
    expect(strong.reasons.length).toBeGreaterThan(0);
    const weak = classifyEvidence({
      reproductionCount: 0,
      crossIdentityEvidence: false,
      objectLevelEvidence: false,
      baselineDifferential: null,
      anonymousOutcome: null,
    });
    expect(weak.level).toBe('WEAK');
    expect(reproductionCountFor([matrixFixture({ object_ref: '1' }), matrixFixture({ object_ref: '1' })], 'EPD_TEST1', '1', 'ALLOWED')).toBe(2);
  });
});

// ---------------------------------------------------------------------------
// §37-§41: data flow
// ---------------------------------------------------------------------------

describe('data-flow model (§37-§41)', () => {
  it('correlates form fields to request parameters (§92)', () => {
    const flows = formToRequestFlows(
      [{ inputName: 'email', formAction: '/login', pageUrl: 'http://127.0.0.1:8080/login' }],
      {
        url: 'http://127.0.0.1:8080/api/register',
        method: 'POST',
        bodyType: 'JSON',
        parameters: [{ name: 'email', location: 'JSON' }],
      },
      endpointFixture(),
    );
    expect(flows.length).toBeGreaterThan(0);
    expect(flows[0]!.source['kind']).toBe('FORM_FIELD');
    expect(flows[0]!.sink['name']).toBe('email');
    expect(flows[0]!.fingerprint.length).toBeGreaterThan(0);
  });

  it('unmatched form fields produce no flows (noise control)', () => {
    const flows = formToRequestFlows(
      [{ inputName: 'csrf_token', formAction: '/login', pageUrl: null }],
      {
        url: 'http://127.0.0.1:8080/api/register',
        method: 'POST',
        bodyType: 'JSON',
        parameters: [{ name: 'email', location: 'JSON' }],
      },
      null,
    );
    expect(flows).toHaveLength(0);
  });

  it('reflection flows track input to output location (§41, §65)', () => {
    const flows = reflectionFlows(
      [parameterFixture({ name: 'q', location: 'QUERY' })],
      [{ name: 'q', value: '<probe-1>', location: 'response_body', excerpt: '...' }],
      endpointFixture(),
    );
    expect(flows.length).toBeGreaterThan(0);
    expect(flows[0]!.sink['kind']).toBe('HTTP_RESPONSE');
  });

  it('detects deterministic transformations (§39)', () => {
    expect(detectTransformations('eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sig')).toContain('JWT_ENCODED');
    expect(detectTransformations('QUJDREVGR0hJSktMTU5OPQ==')).toContain('BASE64');
    expect(detectTransformations('deadbeefdeadbeef')).toContain('HEX');
    expect(detectTransformations('hello%20world')).toContain('URL_ENCODED');
    expect(detectTransformations('plain text')).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------
// §113: resource limits
// ---------------------------------------------------------------------------

describe('reasoning limits (§113)', () => {
  it('exposes finite default limits for pathological targets', () => {
    expect(DEFAULT_REASONING_LIMITS.maxGraphNodes).toBeGreaterThan(0);
    expect(DEFAULT_REASONING_LIMITS.maxSignals).toBeGreaterThan(0);
    expect(DEFAULT_REASONING_LIMITS.maxComparisonBytes).toBeGreaterThan(0);
    const error = new ReasoningLimitError('maxGraphNodes', 100_000);
    expect(error).toBeInstanceOf(Error);
    expect(error.name).toBe('ReasoningLimitError');
    expect(error.message).toContain('maxGraphNodes');
  });
});
