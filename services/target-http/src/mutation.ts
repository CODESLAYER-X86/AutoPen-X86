/**
 * Controlled mutation engine (spec Part 3 §20-§22, §69-§72).
 *
 * Mutations are STRUCTURED operations on a recorded request — never raw
 * string editing. The engine applies mutations to produce a NEW request
 * input; the original record stays immutable (§21).
 *
 * Safety (§22): the mutated request passes the same scope / size / method /
 * identity gates as any fresh request when it is executed. Mutating the
 * destination to an out-of-scope target is impossible because execution
 * re-validates scope on the mutated URL.
 */
import { ValidationError, type HttpMethod } from '@aegis/shared';
import type { HttpBodyInput, HttpMutation } from '@aegis/contracts';
import { canonicalizeJson, findHeader, type PlainHeader } from './normalize.js';

export class MutationError extends ValidationError {
  constructor(message: string, code: string, details?: unknown) {
    super(message, code, Array.isArray(details) ? details : undefined);
    this.name = 'MutationError';
  }
}

export interface MutableRequest {
  method: string;
  url: string;
  headers: PlainHeader[];
  body: HttpBodyInput | null;
}

export interface MutationResult {
  request: MutableRequest;
  applied: Array<{ location: string; name?: string; operation: string }>;
}

/**
 * Apply structured mutations to a mutable request view. The base record is
 * never modified: callers deep-clone into a MutableRequest first.
 */
export function applyMutations(base: MutableRequest, mutations: HttpMutation[]): MutationResult {
  let current: MutableRequest = cloneRequest(base);
  const applied: MutationResult['applied'] = [];

  for (const mutation of mutations) {
    current = applyOne(current, mutation);
    applied.push({ location: mutation.location, name: mutation.name, operation: mutation.operation });
  }

  return { request: current, applied };
}

function cloneRequest(req: MutableRequest): MutableRequest {
  return {
    method: req.method,
    url: req.url,
    headers: req.headers.map((h) => ({ ...h })),
    body: req.body ? deepCloneBody(req.body) : null,
  };
}

function deepCloneBody(body: HttpBodyInput): HttpBodyInput {
  switch (body.body_type) {
    case 'JSON':
      return { body_type: 'JSON', data: structuredClone(body.data) };
    case 'FORM_URLENCODED':
      return { body_type: 'FORM_URLENCODED', fields: body.fields.map((f) => ({ ...f })) };
    case 'MULTIPART':
      return {
        body_type: 'MULTIPART',
        fields: body.fields.map((f) => ({ ...f })),
        files: (body.files ?? []).map((f) => ({ ...f })),
      };
    case 'TEXT':
      return { body_type: 'TEXT', text: body.text };
    case 'XML':
      return { body_type: 'XML', text: body.text };
    case 'BINARY':
      return { body_type: 'BINARY', content_b64: body.content_b64, content_type: body.content_type };
    case 'EMPTY':
      return { body_type: 'EMPTY' };
  }
}

function requireName(mutation: HttpMutation): string {
  if (!mutation.name || mutation.name.length === 0) {
    throw new MutationError(
      `Mutation on '${mutation.location}' requires a 'name'`,
      'MUTATION_NAME_REQUIRED',
    );
  }
  return mutation.name;
}

function applyOne(req: MutableRequest, mutation: HttpMutation): MutableRequest {
  switch (mutation.location) {
    case 'query':
      return mutateQuery(req, mutation);
    case 'path':
      return mutatePath(req, mutation);
    case 'header':
      return mutateHeader(req, mutation);
    case 'cookie':
      return mutateCookieHeader(req, mutation);
    case 'body_json':
      return mutateBodyJson(req, mutation);
    case 'body_form':
      return mutateBodyForm(req, mutation);
    case 'method':
      return mutateMethod(req, mutation);
  }
}

// -- query (§70) ------------------------------------------------------------

function mutateQuery(req: MutableRequest, m: HttpMutation): MutableRequest {
  const url = new URL(req.url);
  const params = url.searchParams;
  const name = requireName(m);

  switch (m.operation) {
    case 'add': {
      const value = stringifyValue(m.value);
      params.append(name, value);
      break;
    }
    case 'replace': {
      if (!params.has(name)) {
        throw new MutationError(`Query parameter '${name}' does not exist`, 'MUTATION_TARGET_MISSING');
      }
      params.set(name, stringifyValue(m.value));
      break;
    }
    case 'remove': {
      if (!params.has(name)) {
        throw new MutationError(`Query parameter '${name}' does not exist`, 'MUTATION_TARGET_MISSING');
      }
      params.delete(name);
      break;
    }
    case 'duplicate': {
      const existing = params.get(name);
      if (existing === null) {
        throw new MutationError(`Query parameter '${name}' does not exist`, 'MUTATION_TARGET_MISSING');
      }
      params.append(name, existing);
      break;
    }
    case 'reorder': {
      // Reorder ALL query params alphabetically (deterministic reorder op).
      const all: Array<[string, string]> = [];
      params.forEach((value, key) => all.push([key, value]));
      all.sort(([a], [b]) => a.localeCompare(b));
      url.search = '';
      for (const [k, v] of all) url.searchParams.append(k, v);
      return { ...req, url: url.toString() };
    }
  }
  return { ...req, url: url.toString() };
}

// -- path segments (§20 change_path_segment) --------------------------------

function mutatePath(req: MutableRequest, m: HttpMutation): MutableRequest {
  const url = new URL(req.url);
  const segments = url.pathname.split('/').filter((s) => s !== '');

  switch (m.operation) {
    case 'replace': {
      const name = requireName(m);
      const index = segments.indexOf(name);
      if (index === -1) {
        throw new MutationError(`Path segment '${name}' not found`, 'MUTATION_TARGET_MISSING');
      }
      segments[index] = stringifyValue(m.value);
      break;
    }
    case 'add': {
      segments.push(stringifyValue(m.value));
      break;
    }
    case 'remove': {
      const name = requireName(m);
      const index = segments.indexOf(name);
      if (index === -1) {
        throw new MutationError(`Path segment '${name}' not found`, 'MUTATION_TARGET_MISSING');
      }
      segments.splice(index, 1);
      break;
    }
    case 'duplicate': {
      const name = requireName(m);
      const index = segments.indexOf(name);
      if (index === -1) {
        throw new MutationError(`Path segment '${name}' not found`, 'MUTATION_TARGET_MISSING');
      }
      segments.splice(index, 0, name);
      break;
    }
    case 'reorder': {
      // Full-segment replacement (deterministic): use provided segments.
      if (!m.segments || m.segments.length === 0) {
        throw new MutationError('Path reorder requires explicit segments', 'MUTATION_SEGMENTS_REQUIRED');
      }
      return { ...req, url: rebuildUrl(url, m.segments).toString() };
    }
  }
  return { ...req, url: rebuildUrl(url, segments).toString() };
}

function rebuildUrl(url: URL, segments: string[]): URL {
  const clone = new URL(url.toString());
  clone.pathname = `/${segments.join('/')}`;
  return clone;
}

// -- headers (§71) -----------------------------------------------------------

function mutateHeader(req: MutableRequest, m: HttpMutation): MutableRequest {
  const name = requireName(m);
  const lower = name.toLowerCase();
  const exists = req.headers.some((h) => h.name.toLowerCase() === lower);

  switch (m.operation) {
    case 'add':
    case 'replace': {
      const value = stringifyValue(m.value);
      if (m.operation === 'replace' && !exists) {
        throw new MutationError(`Header '${name}' does not exist`, 'MUTATION_TARGET_MISSING');
      }
      const headers = m.operation === 'add'
        ? [...req.headers, { name, value }]
        : req.headers.map((h) => (h.name.toLowerCase() === lower ? { name: h.name, value } : h));
      return { ...req, headers };
    }
    case 'remove': {
      if (!exists) {
        throw new MutationError(`Header '${name}' does not exist`, 'MUTATION_TARGET_MISSING');
      }
      return { ...req, headers: req.headers.filter((h) => h.name.toLowerCase() !== lower) };
    }
    case 'duplicate': {
      const existing = findHeader(req.headers, name);
      if (!existing) {
        throw new MutationError(`Header '${name}' does not exist`, 'MUTATION_TARGET_MISSING');
      }
      return { ...req, headers: [...req.headers, { name, value: existing.value }] };
    }
    case 'reorder': {
      const headers = [...req.headers].sort((a, b) => a.name.localeCompare(b.name));
      return { ...req, headers };
    }
  }
}

// -- cookie header (§20 change_cookie_reference) ------------------------------

function mutateCookieHeader(req: MutableRequest, m: HttpMutation): MutableRequest {
  const name = requireName(m);
  const existing = findHeader(req.headers, 'cookie');
  const cookies = existing
    ? existing.value.split(';').map((c) => c.trim()).filter((c) => c !== '')
    : [];
  const index = cookies.findIndex((c) => c.split('=')[0]?.trim() === name);

  switch (m.operation) {
    case 'add': {
      const cookie = `${name}=${stringifyValue(m.value)}`;
      if (index !== -1) cookies[index] = cookie;
      else cookies.push(cookie);
      break;
    }
    case 'replace': {
      if (index === -1) {
        throw new MutationError(`Cookie '${name}' not present in the cookie header`, 'MUTATION_TARGET_MISSING');
      }
      cookies[index] = `${name}=${stringifyValue(m.value)}`;
      break;
    }
    case 'remove': {
      if (index === -1) {
        throw new MutationError(`Cookie '${name}' not present in the cookie header`, 'MUTATION_TARGET_MISSING');
      }
      cookies.splice(index, 1);
      break;
    }
    case 'duplicate': {
      if (index === -1) {
        throw new MutationError(`Cookie '${name}' not present in the cookie header`, 'MUTATION_TARGET_MISSING');
      }
      cookies.splice(index, 0, cookies[index]!);
      break;
    }
    case 'reorder': {
      cookies.sort();
      break;
    }
  }

  const value = cookies.join('; ');
  const headers = value === ''
    ? req.headers.filter((h) => h.name.toLowerCase() !== 'cookie')
    : upsertHeader(req.headers, 'cookie', value);
  return { ...req, headers };
}

function upsertHeader(headers: PlainHeader[], name: string, value: string): PlainHeader[] {
  const lower = name.toLowerCase();
  const exists = headers.some((h) => h.name.toLowerCase() === lower);
  if (exists) {
    return headers.map((h) => (h.name.toLowerCase() === lower ? { name: h.name, value } : h));
  }
  return [...headers, { name, value }];
}

// -- JSON body by path (§69 — structure-aware, never string replacement) -----

function mutateBodyJson(req: MutableRequest, m: HttpMutation): MutableRequest {
  if (!req.body || req.body.body_type !== 'JSON') {
    throw new MutationError(
      'body_json mutation requires a request with a JSON body',
      'MUTATION_BODY_TYPE_MISMATCH',
    );
  }
  const data = structuredClone(req.body.data);
  const path = m.path ?? m.name;
  if (!path) {
    throw new MutationError('body_json mutation requires a path (dot notation) or name', 'MUTATION_PATH_REQUIRED');
  }

  const segments = path.split('.').filter((s) => s !== '');
  let cursor: unknown = data;
  for (let i = 0; i < segments.length - 1; i += 1) {
    const seg = segments[i]!;
    if (cursor === null || typeof cursor !== 'object') {
      throw new MutationError(
        `Cannot traverse path '${path}': segment '${seg}' is not an object`,
        'MUTATION_PATH_INVALID',
      );
    }
    const container = cursor as Record<string, unknown>;
    if (!(seg in container)) {
      if (m.operation === 'add') {
        container[seg] = {};
      } else {
        throw new MutationError(`Path '${path}' does not exist (missing '${seg}')`, 'MUTATION_TARGET_MISSING');
      }
    }
    cursor = container[seg];
  }

  const leafKey = segments[segments.length - 1]!;
  if (cursor === null || typeof cursor !== 'object' || Array.isArray(cursor)) {
    throw new MutationError(
      `Cannot set '${leafKey}': parent path '${path}' resolves to a non-object`,
      'MUTATION_PATH_INVALID',
    );
  }
  const target = cursor as Record<string, unknown>;

  switch (m.operation) {
    case 'add':
    case 'replace': {
      if (m.operation === 'replace' && !(leafKey in target)) {
        throw new MutationError(`JSON field '${path}' does not exist`, 'MUTATION_TARGET_MISSING');
      }
      target[leafKey] = m.value ?? null;
      break;
    }
    case 'remove': {
      if (!(leafKey in target)) {
        throw new MutationError(`JSON field '${path}' does not exist`, 'MUTATION_TARGET_MISSING');
      }
      delete target[leafKey];
      break;
    }
    case 'duplicate': {
      if (!(leafKey in target)) {
        throw new MutationError(`JSON field '${path}' does not exist`, 'MUTATION_TARGET_MISSING');
      }
      const copyKey = `${leafKey}_copy`;
      target[copyKey] = structuredClone(target[leafKey]);
      break;
    }
    case 'reorder': {
      // Canonical reorder: re-serialize the whole object with sorted keys.
      return {
        ...req,
        body: { body_type: 'JSON', data: JSON.parse(canonicalizeJson(data)) as unknown },
      };
    }
  }

  return { ...req, body: { body_type: 'JSON', data } };
}

// -- form body (§20 change_form_field) -----------------------------------------

function mutateBodyForm(req: MutableRequest, m: HttpMutation): MutableRequest {
  if (!req.body || (req.body.body_type !== 'FORM_URLENCODED' && req.body.body_type !== 'MULTIPART')) {
    throw new MutationError(
      'body_form mutation requires a form-urlencoded or multipart body',
      'MUTATION_BODY_TYPE_MISMATCH',
    );
  }
  const name = requireName(m);
  const fields = [...req.body.fields];
  const index = fields.findIndex((f) => f.name === name);

  switch (m.operation) {
    case 'add': {
      fields.push({ name, value: stringifyValue(m.value) });
      break;
    }
    case 'replace': {
      if (index === -1) {
        throw new MutationError(`Form field '${name}' does not exist`, 'MUTATION_TARGET_MISSING');
      }
      fields[index] = { name, value: stringifyValue(m.value) };
      break;
    }
    case 'remove': {
      if (index === -1) {
        throw new MutationError(`Form field '${name}' does not exist`, 'MUTATION_TARGET_MISSING');
      }
      fields.splice(index, 1);
      break;
    }
    case 'duplicate': {
      if (index === -1) {
        throw new MutationError(`Form field '${name}' does not exist`, 'MUTATION_TARGET_MISSING');
      }
      fields.splice(index, 0, { ...fields[index]! });
      break;
    }
    case 'reorder': {
      fields.sort((a, b) => a.name.localeCompare(b.name));
      break;
    }
  }

  return { ...req, body: { ...req.body, fields } };
}

// -- method (§72) ---------------------------------------------------------------

function mutateMethod(req: MutableRequest, m: HttpMutation): MutableRequest {
  if (m.operation !== 'replace') {
    throw new MutationError(
      `Method mutation supports only 'replace' (got '${m.operation}')`,
      'MUTATION_OPERATION_INVALID',
    );
  }
  const value = stringifyValue(m.value).toUpperCase();
  const allowed: HttpMethod[] = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS'];
  if (!allowed.includes(value as HttpMethod)) {
    throw new MutationError(`Method '${value}' is not supported`, 'MUTATION_METHOD_INVALID');
  }
  return { ...req, method: value };
}

function stringifyValue(value: string | number | boolean | null | undefined): string {
  if (value === null || value === undefined) return '';
  if (typeof value === 'string') return value;
  return String(value);
}
