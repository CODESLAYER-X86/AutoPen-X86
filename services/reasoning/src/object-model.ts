/**
 * Object/resource model (spec §19, §96-§97).
 *
 * Object candidates come from identifier-like parameters and templated path
 * positions (§19). A candidate having an identifier is never an
 * authorization vulnerability by itself. Owner attribution is the FIRST
 * identity observed referencing the object; lifecycle candidates derive
 * from resource-family methods (§97).
 */
import { createHash } from 'node:crypto';
import type { EndpointRecord, ObjectCandidateRecord, ParameterRecord } from '@aegis/database';
import { objectKindFromName, objectNameFromParameter } from './value-analysis.js';

export function objectFingerprint(name: string, resourceFamily: string | null): string {
  return createHash('sha256')
    .update(`${name.toLowerCase()}|${resourceFamily ?? ''}`)
    .digest('hex')
    .slice(0, 40);
}

export interface ObjectCandidateInput {
  name: string;
  kind: string;
  parameterId: string | null;
  endpointId: string | null;
  exampleValue: string | null;
  ownerIdentityId: string | null;
  lifecycle: Record<string, unknown>;
  confidence: number;
  evidenceId: string | null;
  resourceFamily: string | null;
  at: string;
}

/**
 * Derive object candidates from parameters (§19). Only identifier-semantics
 * or identifier-characteristic parameters produce candidates.
 */
export function objectCandidatesFromParameters(
  parameters: ParameterRecord[],
  endpoints: EndpointRecord[],
): ObjectCandidateInput[] {
  const endpointById = new Map(endpoints.map((endpoint) => [endpoint.id, endpoint]));
  const candidates: ObjectCandidateInput[] = [];
  for (const parameter of parameters.slice(0, 256)) {
    if (parameter.location === 'HEADER' || parameter.location === 'COOKIE') continue;
    if (parameter.is_sensitive) continue;
    const identifierish =
      parameter.semantic_candidates.some((candidate) => candidate.semantic === 'IDENTIFIER' && candidate.confidence >= 0.5) ||
      parameter.value_characteristics.includes('UUID') ||
      parameter.value_characteristics.includes('IDENTIFIER') ||
      parameter.value_characteristics.includes('NUMERIC');
    if (!identifierish) continue;
    const name = objectNameFromParameter(parameter.name) ?? parameter.name.replace(/[_-]id$/i, '');
    if (name.length < 2) continue;
    const endpoint = parameter.endpoint_id ? (endpointById.get(parameter.endpoint_id) ?? null) : null;
    const exampleValue = parameter.example_values.find((value) => value !== '«redacted»' && value.length > 0) ?? null;
    candidates.push({
      name,
      kind: objectKindFromName(name),
      parameterId: parameter.id,
      endpointId: parameter.endpoint_id,
      exampleValue,
      ownerIdentityId: parameter.identity_association[0] ?? null,
      lifecycle: lifecycleFromEndpoint(endpoint),
      confidence: 0.6,
      evidenceId: null,
      resourceFamily: endpoint?.resource_family ?? null,
      at: parameter.last_seen,
    });
  }
  // Dedup by fingerprint keeping the richest candidate.
  const byFingerprint = new Map<string, ObjectCandidateInput>();
  for (const candidate of candidates) {
    const fingerprint = objectFingerprint(candidate.name, candidate.resourceFamily);
    const existing = byFingerprint.get(fingerprint);
    if (!existing || (candidate.exampleValue !== null && existing.exampleValue === null)) {
      byFingerprint.set(fingerprint, candidate);
    }
  }
  return [...byFingerprint.values()].slice(0, 128);
}

/**
 * Object lifecycle candidates (§97): create/read/update/delete evidence
 * from the resource family's observed methods.
 */
export function lifecycleFromEndpoint(endpoint: EndpointRecord | null): Record<string, unknown> {
  if (!endpoint) return {};
  const lifecycle: Record<string, string[]> = {};
  for (const method of endpoint.methods) {
    const operation = methodToOperation(method.method);
    if (!operation) continue;
    if (!lifecycle[operation]) lifecycle[operation] = [];
    lifecycle[operation]!.push(endpoint.canonical_path);
  }
  return lifecycle;
}

function methodToOperation(method: string): 'create' | 'read' | 'update' | 'delete' | null {
  switch (method) {
    case 'POST':
      return 'create';
    case 'GET':
      return 'read';
    case 'PUT':
    case 'PATCH':
      return 'update';
    case 'DELETE':
      return 'delete';
    default:
      return null;
  }
}

/** Merge lifecycle evidence for existing candidates (§97). */
export function mergeObjectLifecycle(
  existing: ObjectCandidateRecord,
  additions: Record<string, unknown>,
): Record<string, unknown> {
  const merged: Record<string, unknown> = { ...existing.lifecycle };
  for (const [key, value] of Object.entries(additions)) {
    const current = merged[key];
    if (Array.isArray(current) && Array.isArray(value)) {
      merged[key] = [...new Set([...(current as string[]), ...(value as string[])])].slice(0, 32);
    } else if (value !== undefined && value !== null) {
      merged[key] = value;
    }
  }
  return merged;
}
