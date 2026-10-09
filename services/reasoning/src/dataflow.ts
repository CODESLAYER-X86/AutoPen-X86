/**
 * Data-flow engine (spec §37-§41, §90-§92).
 *
 * Source -> transformation -> sink relationships from deterministic
 * correlations: form-to-request (§92), script-to-endpoint (§91),
 * storage-to-request (§90), input-to-output reflection (§41, §65).
 * Causality is never claimed from temporal proximity alone (§95).
 */
import { createHash } from 'node:crypto';
import type { EndpointRecord, ParameterRecord } from '@aegis/database';

export interface FlowFact {
  source: Record<string, unknown>;
  transformations: string[];
  sink: Record<string, unknown>;
  correlation: 'FORM_TO_REQUEST' | 'SCRIPT_TO_ENDPOINT' | 'STORAGE_TO_REQUEST' | 'INPUT_TO_OUTPUT' | 'WS_REQUEST_RESPONSE';
  confidence: number;
  evidenceIds: string[];
  fingerprint: string;
}

export function flowFingerprint(correlation: string, sourceKey: string, sinkKey: string): string {
  return createHash('sha256').update(`${correlation}|${sourceKey}|${sinkKey}`).digest('hex').slice(0, 40);
}

/**
 * Form-to-request correlation (§92): a DOM form input name that appears as
 * a request parameter on a plausible submit endpoint.
 */
export function formToRequestFlows(
  forms: Array<{ inputName: string; formAction: string | null; pageUrl: string | null }>,
  request: { url: string; method: string; bodyType: string | null; parameters: Array<{ name: string; location: string }> },
  endpoint: EndpointRecord | null,
): FlowFact[] {
  const flows: FlowFact[] = [];
  if (request.method !== 'POST' && request.method !== 'PUT' && request.method !== 'PATCH') return flows;
  const parameterNames = new Set(request.parameters.map((parameter) => parameter.name.toLowerCase()));
  for (const form of forms.slice(0, 64)) {
    const name = form.inputName.toLowerCase();
    if (!parameterNames.has(name)) continue;
    flows.push({
      source: {
        kind: 'FORM_FIELD',
        name: form.inputName,
        endpoint_id: null,
        page_url: bounded(form.pageUrl ?? form.formAction ?? '', 512),
      },
      transformations: ['FORM_ENCODED'],
      sink: {
        kind: 'REQUEST_PARAMETER',
        name: form.inputName,
        endpoint_id: endpoint?.id ?? null,
        location: request.bodyType === 'JSON' ? 'JSON' : 'FORM',
      },
      correlation: 'FORM_TO_REQUEST',
      confidence: 0.7,
      evidenceIds: [],
      fingerprint: flowFingerprint('FORM_TO_REQUEST', `${form.pageUrl ?? 'page'}:${name}`, `${endpoint?.id ?? request.url}:${name}`),
    });
  }
  return flows.slice(0, 32);
}

/**
 * Script-to-endpoint correlation (§91): DOM scripts whose src path matches
 * an observed endpoint, or endpoints referenced by page URLs.
 */
export function scriptToEndpointFlows(
  scripts: Array<{ src: string | null; pageUrl: string | null }>,
  endpoints: EndpointRecord[],
): FlowFact[] {
  const flows: FlowFact[] = [];
  for (const script of scripts.slice(0, 64)) {
    if (!script.src) continue;
    const scriptPath = extractPath(script.src);
    if (scriptPath === null) continue;
    const match = endpoints.find((endpoint) => endpoint.path === scriptPath || endpoint.canonical_path === scriptPath);
    if (!match) continue;
    flows.push({
      source: { kind: 'BROWSER_STATE', name: `script:${bounded(script.src, 200)}`, endpoint_id: null, page_url: bounded(script.pageUrl ?? '', 512) },
      transformations: [],
      sink: { kind: 'APPLICATION_STATE', name: 'script_loaded', endpoint_id: match.id },
      correlation: 'SCRIPT_TO_ENDPOINT',
      confidence: 0.8,
      evidenceIds: [],
      fingerprint: flowFingerprint('SCRIPT_TO_ENDPOINT', bounded(script.src, 200), match.id),
    });
  }
  return flows.slice(0, 32);
}

/**
 * Storage-to-request correlation (§90): sensitive browser storage keys and
 * requests carrying authorization headers.
 */
export function storageToRequestFlows(
  storageKeys: Array<{ key: string; area: string; identityId: string | null; pageUrl: string | null }>,
  request: { url: string; hasAuthorizationHeader: boolean; identityId: string | null },
  endpoint: EndpointRecord | null,
): FlowFact[] {
  if (!request.hasAuthorizationHeader) return [];
  const flows: FlowFact[] = [];
  for (const entry of storageKeys.slice(0, 32)) {
    if (!/token|auth|jwt|session|key/i.test(entry.key)) continue;
    flows.push({
      source: { kind: 'STORAGE', name: `${entry.area.toLowerCase()}:${entry.key}`, endpoint_id: null, page_url: bounded(entry.pageUrl ?? '', 512) },
      transformations: ['JWT_ENCODED'],
      sink: { kind: 'REQUEST_PARAMETER', name: 'authorization_header', endpoint_id: endpoint?.id ?? null },
      correlation: 'STORAGE_TO_REQUEST',
      confidence: 0.6,
      evidenceIds: [],
      fingerprint: flowFingerprint('STORAGE_TO_REQUEST', entry.key, endpoint?.id ?? request.url),
    });
  }
  return flows.slice(0, 16);
}

/**
 * Input-to-output reflection flows (§41, §65): request parameter values
 * appearing in the response. Reflection location is recorded exactly (§66).
 */
export function reflectionFlows(
  parameters: ParameterRecord[],
  reflections: Array<{ name: string; value: string; location: string; excerpt: string }>,
  endpoint: EndpointRecord | null,
): FlowFact[] {
  const flows: FlowFact[] = [];
  for (const reflection of reflections.slice(0, 16)) {
    const parameter = parameters.find((entry) => entry.name === reflection.name);
    flows.push({
      source: {
        kind: parameter?.location === 'QUERY' ? 'URL_PARAM' : 'JSON_FIELD',
        name: reflection.name,
        endpoint_id: parameter?.endpoint_id ?? null,
        page_url: null,
      },
      transformations: [],
      sink: {
        kind: reflection.location === 'redirect' ? 'REDIRECT' : 'HTTP_RESPONSE',
        name: reflection.location,
        endpoint_id: endpoint?.id ?? null,
        excerpt: bounded(reflection.excerpt, 200),
      },
      correlation: 'INPUT_TO_OUTPUT',
      confidence: 0.75,
      evidenceIds: [],
      fingerprint: flowFingerprint('INPUT_TO_OUTPUT', `${endpoint?.id ?? 'none'}:${reflection.name}`, reflection.location),
    });
  }
  return flows;
}

/** Detect deterministic transformations on values (§39). */
export function detectTransformations(value: string): string[] {
  const transformations: string[] = [];
  if (value.includes('%20') || value.includes('%22') || /%[0-9A-F]{2}/i.test(value)) transformations.push('URL_ENCODED');
  if (/^ey[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/.test(value)) transformations.push('JWT_ENCODED');
  if (/^[A-Za-z0-9+/=]{20,}$/.test(value)) transformations.push('BASE64');
  if (/^[0-9a-f]{16,}$/i.test(value)) transformations.push('HEX');
  return transformations;
}

function extractPath(url: string): string | null {
  try {
    return new URL(url).pathname || '/';
  } catch {
    return null;
  }
}

function bounded(text: string, max: number): string {
  return text.length > max ? text.slice(0, max) : text;
}

export function toInsertInput(fact: FlowFact, engagementId: string): {
  engagementId: string;
  source: Record<string, unknown>;
  transformations: string[];
  sink: Record<string, unknown>;
  correlation: FlowFact['correlation'];
  confidence: number;
  evidenceIds: string[];
  fingerprint: string;
} {
  return {
    engagementId,
    source: fact.source,
    transformations: fact.transformations,
    sink: fact.sink,
    correlation: fact.correlation,
    confidence: fact.confidence,
    evidenceIds: fact.evidenceIds,
    fingerprint: fact.fingerprint,
  };
}
