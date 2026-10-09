/**
 * Parameter intelligence (spec §14-§18, §92).
 *
 * Deterministic extraction from HTTP requests (query/path/JSON/form/multipart/
 * headers/cookies), DOM forms, and WebSocket payloads. Value characteristics
 * and semantic candidates come from value-analysis (§16-§17). Sensitive
 * example values are stored redacted (§115).
 */
import { createHash } from 'node:crypto';
import type { ParameterLocation, ValueCharacteristic } from '@aegis/shared';
import type { SemanticCandidateRecord } from '@aegis/database';
import { analyzeValue, classifyParameterName, isSensitiveParameterName, observedTypeOf } from './value-analysis.js';

const COMMON_HEADERS = new Set([
  'host',
  'user-agent',
  'accept',
  'accept-encoding',
  'accept-language',
  'accept-charset',
  'connection',
  'content-length',
  'content-type',
  'cache-control',
  'origin',
  'referer',
  'upgrade-insecure-requests',
  'te',
  'dnt',
]);

export interface ExtractedParameter {
  name: string;
  location: ParameterLocation;
  observedType: string | null;
  /** Redacted when the name is sensitive (§115). */
  exampleValue: string | null;
  valueCharacteristics: ValueCharacteristic[];
  semanticCandidates: SemanticCandidateRecord[];
  isSensitive: boolean;
}

export interface RequestLikeInput {
  method: string;
  url: string;
  query: Array<{ name: string; value: string }>;
  headers: Array<{ name: string; value: string }>;
  bodyType: string | null;
  bodyParsed: unknown;
}

export function parameterFingerprint(endpointFingerprint: string, location: ParameterLocation, name: string): string {
  return createHash('sha256')
    .update(`${endpointFingerprint}|${location}|${name}`)
    .digest('hex')
    .slice(0, 40);
}

/**
 * Path parameter names derived from the canonical path (§14 PATH location).
 * REST heuristic: /api/orders/{param}/confirm -> "order_id". Falls back to
 * path_{index} when no usable preceding segment exists.
 */
export function pathParameterNames(canonicalPath: string): Array<{ name: string; segmentIndex: number }> {
  const segments = canonicalPath.split('/').filter((segment) => segment.length > 0);
  const results: Array<{ name: string; segmentIndex: number }> = [];
  segments.forEach((segment, index) => {
    if (segment !== '{param}') return;
    const previous = index > 0 ? segments[index - 1]! : null;
    if (previous && !/^v\d+$/i.test(previous) && previous !== 'api') {
      const base = previous.replace(/s$/, '');
      if (base.length >= 2) {
        results.push({ name: `${base}_id`, segmentIndex: index });
        return;
      }
    }
    results.push({ name: `path_${index}`, segmentIndex: index });
  });
  return results;
}

/** Extract parameters from a normalized HTTP request (§14). */
export function extractRequestParameters(request: RequestLikeInput): ExtractedParameter[] {
  const parameters: ExtractedParameter[] = [];
  const push = (
    location: ParameterLocation,
    name: string,
    value: unknown,
  ): void => {
    if (parameters.length >= 64 || name.length === 0 || name.length > 256) return;
    const analysis = analyzeValue(value);
    const sensitive = isSensitiveParameterName(name);
    const exampleValue =
      analysis.text !== null
        ? sensitive
          ? '«redacted»'
          : analysis.text.slice(0, 256)
        : value === null
          ? 'null'
          : null;
    parameters.push({
      name,
      location,
      observedType: observedTypeOf(value),
      exampleValue,
      valueCharacteristics: analysis.characteristics,
      semanticCandidates: classifyParameterName(name),
      isSensitive: sensitive,
    });
  };

  // Query parameters.
  for (const param of request.query.slice(0, 32)) {
    push('QUERY', param.name, param.value);
  }

  // Cookies (names as parameters; values stay redacted).
  for (const header of request.headers) {
    if (header.name.toLowerCase() !== 'cookie') continue;
    for (const part of header.value.split(';')) {
      const name = part.split('=')[0]?.trim() ?? '';
      if (name.length > 0) push('COOKIE', name, '«redacted»');
    }
  }

  // Non-standard headers.
  for (const header of request.headers.slice(0, 64)) {
    const lower = header.name.toLowerCase();
    if (COMMON_HEADERS.has(lower) || lower.startsWith('sec-')) continue;
    if (lower === 'cookie') continue;
    push('HEADER', header.name.toLowerCase(), header.value);
  }

  // Body parameters by serialization format (§53: understand the format).
  if (request.bodyType === 'JSON' && request.bodyParsed !== null && request.bodyParsed !== undefined) {
    collectJsonFields(request.bodyParsed, '', push);
  } else if (
    (request.bodyType === 'FORM_URLENCODED' || request.bodyType === 'MULTIPART') &&
    Array.isArray(request.bodyParsed)
  ) {
    for (const field of (request.bodyParsed as Array<{ name: string; value: string }>).slice(0, 32)) {
      push(request.bodyType === 'FORM_URLENCODED' ? 'FORM' : 'MULTIPART', field.name, field.value);
    }
  }

  return parameters;
}

/** Walk JSON bodies recursively; dotted paths become names (§14 JSON). */
function collectJsonFields(
  value: unknown,
  prefix: string,
  push: (location: ParameterLocation, name: string, value: unknown) => void,
  depth = 0,
): void {
  if (depth > 4) return; // bounded depth (§113)
  if (Array.isArray(value)) {
    value.slice(0, 8).forEach((item) => collectJsonFields(item, `${prefix}[]`, push, depth + 1));
    return;
  }
  if (value !== null && typeof value === 'object') {
    for (const [key, child] of Object.entries(value as Record<string, unknown>).slice(0, 32)) {
      collectJsonFields(child, prefix ? `${prefix}.${key}` : key, push, depth + 1);
    }
    return;
  }
  if (prefix.length === 0) return;
  push('JSON', prefix, value);
}

/**
 * Extract HTML form input names from a DOM snapshot (§14 HTML_FORM, §92
 * form-to-request correlation source).
 */
export function extractFormParameters(
  snapshot: Record<string, unknown>,
): Array<{ name: string; type: string; formAction: string | null; formMethod: string | null }> {
  const elements = Array.isArray(snapshot.elements) ? (snapshot.elements as Array<Record<string, unknown>>) : [];
  const results: Array<{ name: string; type: string; formAction: string | null; formMethod: string | null }> = [];
  for (const element of elements.slice(0, 500)) {
    const forms = Array.isArray(element.forms) ? (element.forms as Array<Record<string, unknown>>) : [];
    for (const form of forms.slice(0, 8)) {
      const action = typeof form.action === 'string' ? form.action : null;
      const method = typeof form.method === 'string' ? form.method : null;
      const inputs = Array.isArray(form.inputs) ? (form.inputs as Array<Record<string, unknown>>) : [];
      for (const input of inputs.slice(0, 32)) {
        const name = typeof input.name === 'string' ? input.name : '';
        const type = typeof input.type === 'string' ? input.type : 'text';
        if (name.length > 0 && name.length <= 256) {
          results.push({ name, type, formAction: action, formMethod: method });
        }
      }
    }
  }
  return results.slice(0, 128);
}

/** Extract WebSocket message payload fields (§14 WEBSOCKET, §89). */
export function extractWsParameters(
  payloadPreview: string | null,
): Array<{ name: string; value: unknown; characteristics: ValueCharacteristic[] }> {
  if (!payloadPreview) return [];
  try {
    const parsed: unknown = JSON.parse(payloadPreview);
    if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) return [];
    const results: Array<{ name: string; value: unknown; characteristics: ValueCharacteristic[] }> = [];
    for (const [key, value] of Object.entries(parsed as Record<string, unknown>).slice(0, 32)) {
      const analysis = analyzeValue(value);
      const sensitive = isSensitiveParameterName(key);
      results.push({
        name: key,
        value: sensitive ? '«redacted»' : analysis.text,
        characteristics: analysis.characteristics,
      });
    }
    return results;
  } catch {
    return [];
  }
}

/**
 * Cross-endpoint parameter relationships (§18): same parameter name across
 * different endpoint fingerprints.
 */
export function crossEndpointRelationships(
  parametersByEndpoint: Array<{ endpointFingerprint: string; names: string[] }>,
): Array<{ name: string; endpoints: string[] }> {
  const byName = new Map<string, Set<string>>();
  for (const group of parametersByEndpoint) {
    for (const name of group.names) {
      if (!byName.has(name)) byName.set(name, new Set());
      byName.get(name)!.add(group.endpointFingerprint);
    }
  }
  const relationships: Array<{ name: string; endpoints: string[] }> = [];
  for (const [name, endpoints] of byName) {
    if (endpoints.size >= 2) relationships.push({ name, endpoints: [...endpoints] });
  }
  return relationships.sort((a, b) => b.endpoints.length - a.endpoints.length).slice(0, 64);
}
