/**
 * Part 4 repositories — attack-surface registries (spec §5-§19, §42).
 *
 * All upserts are idempotent via deterministic fingerprints (§111): processing
 * the same observation twice produces no duplicate endpoint, parameter,
 * matrix cell, signal or object.
 */
import type { Pool } from 'pg';
import { generateId } from '@aegis/shared';
import type {
  AccessOutcome,
  ConfidenceCategory,
  DiscoverySource,
  EndpointStatus,
  ParameterLocation,
  ParameterSemantic,
  SignalStatus,
  SignalType,
  ValueCharacteristic,
} from '@aegis/shared';
import type {
  AuthorizationMatrixRecord,
  EndpointMethodRecord,
  EndpointRecord,
  ObjectCandidateRecord,
  ParameterRecord,
  SecuritySignalRecord,
  SemanticCandidateRecord,
} from '../types.js';
import { iso } from './util.js';

// -- Endpoints (§7-§13) ------------------------------------------------------

export interface UpsertEndpointInput {
  engagementId: string;
  fingerprint: string;
  scheme: string;
  host: string;
  port: number;
  path: string;
  canonicalPath: string;
  canonicalConfidence: number;
  resourceFamily: string | null;
  apiVersion: string | null;
  method: string;
  contentType: string | null;
  identityId: string | null;
  status: EndpointStatus;
  discoverySource: DiscoverySource;
  confidenceCategory: ConfidenceCategory;
  confidence: number;
  observedUrl: string;
  evidenceId: string | null;
  at: string;
}

export interface UpdateEndpointPatch {
  methods?: EndpointMethodRecord[];
  content_types?: string[];
  identities_observed?: string[];
  observed_urls?: string[];
  evidence_ids?: string[];
  observation_count?: number;
  canonical_path?: string;
  canonical_confidence?: number;
  fingerprint?: string;
  resource_family?: string;
  status?: EndpointStatus;
  confidence?: number;
  merged_into?: string;
  last_seen?: string;
  /** Sticky: once an authenticated identity reached it, it stays true (§11). */
  authentication_observed?: boolean;
}

export class EndpointsRepository {
  constructor(readonly pool: Pool) {}

  async findByFingerprint(engagementId: string, fingerprint: string): Promise<EndpointRecord | null> {
    const result = await this.pool.query(
      'SELECT * FROM endpoints WHERE engagement_id = $1 AND fingerprint = $2',
      [engagementId, fingerprint],
    );
    return result.rows[0] ? mapEndpointRow(result.rows[0]) : null;
  }

  async findById(id: string): Promise<EndpointRecord | null> {
    const result = await this.pool.query('SELECT * FROM endpoints WHERE id = $1', [id]);
    return result.rows[0] ? mapEndpointRow(result.rows[0]) : null;
  }

  async listByEngagement(
    engagementId: string,
    options: { statuses?: EndpointStatus[]; limit?: number; offset?: number } = {},
  ): Promise<EndpointRecord[]> {
    const limit = Math.min(Math.max(options.limit ?? 100, 1), 1000);
    const offset = Math.max(options.offset ?? 0, 0);
    const statuses = options.statuses?.length ? options.statuses : null;
    const result = await this.pool.query(
      `SELECT * FROM endpoints
       WHERE engagement_id = $1 ${statuses ? 'AND status = ANY($2::text[])' : ''}
       ORDER BY observation_count DESC, last_seen DESC
       LIMIT ${statuses ? '$3' : '$2'} OFFSET ${statuses ? '$4' : '$3'}`,
      statuses ? [engagementId, statuses, limit, offset] : [engagementId, limit, offset],
    );
    return result.rows.map(mapEndpointRow);
  }

  async listByHost(engagementId: string, host: string): Promise<EndpointRecord[]> {
    const result = await this.pool.query(
      'SELECT * FROM endpoints WHERE engagement_id = $1 AND host = $2 AND merged_into IS NULL ORDER BY last_seen DESC',
      [engagementId, host],
    );
    return result.rows.map(mapEndpointRow);
  }

  async countByEngagement(engagementId: string): Promise<number> {
    const result = await this.pool.query(
      'SELECT count(*)::int AS total FROM endpoints WHERE engagement_id = $1 AND merged_into IS NULL',
      [engagementId],
    );
    return (result.rows[0] as { total: number }).total;
  }

  async upsert(input: UpsertEndpointInput): Promise<{ record: EndpointRecord; created: boolean }> {
    const existing = await this.findByFingerprint(input.engagementId, input.fingerprint);
    if (existing) {
      const patch = mergeEndpoint(existing, input);
      const record = await this.update(existing.id, patch);
      return { record, created: false };
    }
    const id = generateId('EPD');
    const result = await this.pool.query(
      `INSERT INTO endpoints (id, engagement_id, fingerprint, scheme, host, port, path, canonical_path,
         canonical_confidence, resource_family, api_version, methods, content_types, authentication_observed,
         identities_observed, status, discovery_source, confidence_category, confidence, observed_urls,
         observation_count, evidence_ids, first_seen, last_seen)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12::jsonb,$13::jsonb,$14,$15::jsonb,$16,$17,$18,$19,$20::jsonb,1,$21::jsonb,$22,$22)
       RETURNING *`,
      [
        id,
        input.engagementId,
        input.fingerprint,
        input.scheme,
        input.host,
        input.port,
        input.path,
        input.canonicalPath,
        input.canonicalConfidence,
        input.resourceFamily,
        input.apiVersion,
        JSON.stringify([
          {
            method: input.method,
            observation_count: 1,
            identity_ids: input.identityId ? [input.identityId] : [],
            first_seen: input.at,
            last_seen: input.at,
          },
        ]),
        JSON.stringify(input.contentType ? [input.contentType] : []),
        input.identityId !== null,
        JSON.stringify(input.identityId ? [input.identityId] : []),
        input.status,
        input.discoverySource,
        input.confidenceCategory,
        input.confidence,
        JSON.stringify([input.observedUrl]),
        JSON.stringify(input.evidenceId ? [input.evidenceId] : []),
        input.at,
      ],
    );
    return { record: mapEndpointRow(result.rows[0]!), created: true };
  }

  async update(id: string, patch: UpdateEndpointPatch): Promise<EndpointRecord> {
    const result = await this.pool.query(
      `UPDATE endpoints SET
         methods = COALESCE($2::jsonb, methods),
         content_types = COALESCE($3::jsonb, content_types),
         identities_observed = COALESCE($4::jsonb, identities_observed),
         observed_urls = COALESCE($5::jsonb, observed_urls),
         evidence_ids = COALESCE($6::jsonb, evidence_ids),
         observation_count = COALESCE($7, observation_count),
         canonical_path = COALESCE($8, canonical_path),
         canonical_confidence = COALESCE($9, canonical_confidence),
         fingerprint = COALESCE($10, fingerprint),
         resource_family = COALESCE($11, resource_family),
         status = COALESCE($12, status),
         confidence = COALESCE($13, confidence),
         merged_into = COALESCE($14, merged_into),
         last_seen = COALESCE($15, last_seen),
         authentication_observed = COALESCE($16, authentication_observed),
         updated_at = now()
       WHERE id = $1
       RETURNING *`,
      [
        id,
        patch.methods ? JSON.stringify(patch.methods) : null,
        patch.content_types ? JSON.stringify(patch.content_types) : null,
        patch.identities_observed ? JSON.stringify(patch.identities_observed) : null,
        patch.observed_urls ? JSON.stringify(patch.observed_urls) : null,
        patch.evidence_ids ? JSON.stringify(patch.evidence_ids) : null,
        patch.observation_count ?? null,
        patch.canonical_path ?? null,
        patch.canonical_confidence ?? null,
        patch.fingerprint ?? null,
        patch.resource_family ?? null,
        patch.status ?? null,
        patch.confidence ?? null,
        patch.merged_into ?? null,
        patch.last_seen ?? null,
        patch.authentication_observed ?? null,
      ],
    );
    if (!result.rows[0]) throw new Error(`Endpoint ${id} update failed`);
    return mapEndpointRow(result.rows[0]);
  }

  async updateStatus(id: string, status: EndpointStatus): Promise<void> {
    await this.pool.query('UPDATE endpoints SET status = $1, updated_at = now() WHERE id = $2', [status, id]);
  }

  async incrementSignalCount(id: string): Promise<void> {
    await this.pool.query('UPDATE endpoints SET signal_count = signal_count + 1 WHERE id = $1', [id]);
  }

  async markMerged(id: string, intoEndpointId: string): Promise<void> {
    await this.pool.query(
      'UPDATE endpoints SET merged_into = $1, status = $2, updated_at = now() WHERE id = $3',
      [intoEndpointId, 'IGNORED', id],
    );
  }
}

function mergeEndpoint(existing: EndpointRecord, input: UpsertEndpointInput): UpdateEndpointPatch {
  const methods = [...existing.methods];
  const methodIdx = methods.findIndex((m) => m.method === input.method);
  if (methodIdx >= 0) {
    const m = methods[methodIdx]!;
    methods[methodIdx] = {
      ...m,
      observation_count: m.observation_count + 1,
      identity_ids: mergeUnique(m.identity_ids, input.identityId ? [input.identityId] : []),
      last_seen: input.at,
    };
  } else {
    methods.push({
      method: input.method,
      observation_count: 1,
      identity_ids: input.identityId ? [input.identityId] : [],
      first_seen: input.at,
      last_seen: input.at,
    });
  }
  return {
    methods,
    identities_observed: mergeUnique(existing.identities_observed, input.identityId ? [input.identityId] : []),
    authentication_observed: existing.authentication_observed || input.identityId !== null,
    observed_urls: mergeUniqueBounded(existing.observed_urls, [input.observedUrl], 16),
    content_types: mergeUnique(existing.content_types, input.contentType ? [input.contentType] : []),
    evidence_ids: mergeUniqueBounded(existing.evidence_ids, input.evidenceId ? [input.evidenceId] : [], 64),
    observation_count: existing.observation_count + 1,
    last_seen: input.at,
  };
}

// -- Parameters (§14-§18) -----------------------------------------------------

export interface UpsertParameterInput {
  engagementId: string;
  endpointId: string | null;
  fingerprint: string;
  name: string;
  location: ParameterLocation;
  observedType: string | null;
  exampleValue: string | null;
  valueCharacteristics: ValueCharacteristic[];
  semanticCandidates: SemanticCandidateRecord[];
  identityId: string | null;
  isSensitive: boolean;
  confidence: number;
  at: string;
}

export class ParametersRepository {
  constructor(readonly pool: Pool) {}

  async upsert(input: UpsertParameterInput): Promise<{ record: ParameterRecord; created: boolean }> {
    const existing = await this.findByFingerprint(input.engagementId, input.fingerprint);
    if (existing) {
      const exampleValues = input.exampleValue !== null && !existing.example_values.includes(input.exampleValue)
        ? mergeUniqueBounded(existing.example_values, [input.exampleValue], 8)
        : existing.example_values;
      const result = await this.pool.query(
        `UPDATE parameters SET
           observed_type = COALESCE($2, observed_type),
           example_values = $3::jsonb,
           value_characteristics = $4::jsonb,
           identity_association = $5::jsonb,
           observation_count = observation_count + 1,
           last_seen = $6,
           updated_at = now()
         WHERE id = $1 RETURNING *`,
        [
          existing.id,
          input.observedType,
          JSON.stringify(exampleValues),
          JSON.stringify(mergeUnique(existing.value_characteristics, input.valueCharacteristics)),
          JSON.stringify(mergeUnique(existing.identity_association, input.identityId ? [input.identityId] : [])),
          input.at,
        ],
      );
      return { record: mapParameterRow(result.rows[0]!), created: false };
    }
    const id = generateId('PRM');
    const result = await this.pool.query(
      `INSERT INTO parameters (id, engagement_id, endpoint_id, fingerprint, name, location, observed_type,
         example_values, value_characteristics, semantic_candidates, identity_association, is_sensitive,
         confidence, first_seen, last_seen)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8::jsonb,$9::jsonb,$10::jsonb,$11::jsonb,$12,$13,$14,$14)
       RETURNING *`,
      [
        id,
        input.engagementId,
        input.endpointId,
        input.fingerprint,
        input.name,
        input.location,
        input.observedType,
        JSON.stringify(input.exampleValue !== null ? [input.exampleValue] : []),
        JSON.stringify(input.valueCharacteristics),
        JSON.stringify(input.semanticCandidates),
        JSON.stringify(input.identityId ? [input.identityId] : []),
        input.isSensitive,
        input.confidence,
        input.at,
      ],
    );
    return { record: mapParameterRow(result.rows[0]!), created: true };
  }

  async findByFingerprint(engagementId: string, fingerprint: string): Promise<ParameterRecord | null> {
    const result = await this.pool.query(
      'SELECT * FROM parameters WHERE engagement_id = $1 AND fingerprint = $2',
      [engagementId, fingerprint],
    );
    return result.rows[0] ? mapParameterRow(result.rows[0]) : null;
  }

  async findById(id: string): Promise<ParameterRecord | null> {
    const result = await this.pool.query('SELECT * FROM parameters WHERE id = $1', [id]);
    return result.rows[0] ? mapParameterRow(result.rows[0]) : null;
  }

  async listByEngagement(engagementId: string, limit = 200): Promise<ParameterRecord[]> {
    const result = await this.pool.query(
      'SELECT * FROM parameters WHERE engagement_id = $1 ORDER BY observation_count DESC, name LIMIT $2',
      [engagementId, Math.min(Math.max(limit, 1), 1000)],
    );
    return result.rows.map(mapParameterRow);
  }

  async listByEndpoint(endpointId: string): Promise<ParameterRecord[]> {
    const result = await this.pool.query(
      'SELECT * FROM parameters WHERE endpoint_id = $1 ORDER BY observation_count DESC, name',
      [endpointId],
    );
    return result.rows.map(mapParameterRow);
  }

  async listByName(engagementId: string, name: string): Promise<ParameterRecord[]> {
    const result = await this.pool.query(
      'SELECT * FROM parameters WHERE engagement_id = $1 AND name = $2 ORDER BY first_seen',
      [engagementId, name],
    );
    return result.rows.map(mapParameterRow);
  }

  async countByEngagement(engagementId: string): Promise<number> {
    const result = await this.pool.query(
      'SELECT count(*)::int AS total FROM parameters WHERE engagement_id = $1',
      [engagementId],
    );
    return (result.rows[0] as { total: number }).total;
  }
}

// -- Authorization matrix (§23, §98) -------------------------------------------

export interface UpsertMatrixInput {
  engagementId: string;
  endpointId: string;
  identityId: string | null;
  objectRef: string | null;
  action: string | null;
  outcome: AccessOutcome;
  statusCode: number | null;
  requestId: string | null;
  evidenceId: string | null;
  fingerprint: string;
  at: string;
}

export class AuthorizationMatrixRepository {
  constructor(readonly pool: Pool) {}

  async upsert(input: UpsertMatrixInput): Promise<{ record: AuthorizationMatrixRecord; created: boolean }> {
    const id = generateId('AZM');
    const result = await this.pool.query(
      `INSERT INTO authorization_matrix (id, engagement_id, endpoint_id, identity_id, object_ref, action,
         outcome, status_code, request_id, evidence_ids, fingerprint, first_seen, last_seen)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10::jsonb,$11,$12,$12)
       ON CONFLICT (engagement_id, fingerprint) DO UPDATE SET
         outcome = EXCLUDED.outcome,
         status_code = EXCLUDED.status_code,
         request_id = EXCLUDED.request_id,
         observation_count = authorization_matrix.observation_count + 1,
         last_seen = EXCLUDED.last_seen
       RETURNING *`,
      [
        id,
        input.engagementId,
        input.endpointId,
        input.identityId,
        input.objectRef,
        input.action,
        input.outcome,
        input.statusCode,
        input.requestId,
        JSON.stringify(input.evidenceId ? [input.evidenceId] : []),
        input.fingerprint,
        input.at,
      ],
    );
    const row = result.rows[0]!;
    const created = (row.observation_count as number) === 1;
    return { record: mapMatrixRow(row), created };
  }

  async listByEngagement(engagementId: string, limit = 500): Promise<AuthorizationMatrixRecord[]> {
    const result = await this.pool.query(
      'SELECT * FROM authorization_matrix WHERE engagement_id = $1 ORDER BY last_seen DESC LIMIT $2',
      [engagementId, Math.min(Math.max(limit, 1), 2000)],
    );
    return result.rows.map(mapMatrixRow);
  }

  async listByEndpoint(endpointId: string): Promise<AuthorizationMatrixRecord[]> {
    const result = await this.pool.query(
      'SELECT * FROM authorization_matrix WHERE endpoint_id = $1 ORDER BY identity_id NULLS FIRST, last_seen DESC',
      [endpointId],
    );
    return result.rows.map(mapMatrixRow);
  }

  async listByObject(engagementId: string, objectRef: string): Promise<AuthorizationMatrixRecord[]> {
    const result = await this.pool.query(
      'SELECT * FROM authorization_matrix WHERE engagement_id = $1 AND object_ref = $2 ORDER BY last_seen',
      [engagementId, objectRef],
    );
    return result.rows.map(mapMatrixRow);
  }

  async countByEngagement(engagementId: string): Promise<number> {
    const result = await this.pool.query(
      'SELECT count(*)::int AS total FROM authorization_matrix WHERE engagement_id = $1',
      [engagementId],
    );
    return (result.rows[0] as { total: number }).total;
  }
}

// -- Security signals (§42-§43) --------------------------------------------------

export interface InsertSignalInput {
  engagementId: string;
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

export class SecuritySignalsRepository {
  constructor(readonly pool: Pool) {}

  async insert(input: InsertSignalInput): Promise<{ record: SecuritySignalRecord; created: boolean }> {
    const id = generateId('SIG');
    const result = await this.pool.query(
      `INSERT INTO security_signals (id, engagement_id, signal_type, source, endpoint_id, parameter_id,
         identity_ids, object_ref, confidence, summary, metadata, evidence_ids, fingerprint)
       VALUES ($1,$2,$3,$4,$5,$6,$7::jsonb,$8,$9,$10,$11::jsonb,$12::jsonb,$13)
       ON CONFLICT (engagement_id, fingerprint) DO UPDATE SET updated_at = now()
       RETURNING *`,
      [
        id,
        input.engagementId,
        input.signalType,
        input.source,
        input.endpointId,
        input.parameterId,
        JSON.stringify(input.identityIds),
        input.objectRef,
        input.confidence,
        input.summary,
        JSON.stringify(input.metadata),
        JSON.stringify(input.evidenceIds),
        input.fingerprint,
      ],
    );
    const row = result.rows[0]!;
    const created = (row.id as string) === id;
    return { record: mapSignalRow(row), created };
  }

  async listByEngagement(
    engagementId: string,
    options: { statuses?: SignalStatus[]; types?: SignalType[]; limit?: number } = {},
  ): Promise<SecuritySignalRecord[]> {
    const limit = Math.min(Math.max(options.limit ?? 100, 1), 1000);
    const statuses = options.statuses?.length ? options.statuses : null;
    const types = options.types?.length ? options.types : null;
    const clauses: string[] = [];
    const params: unknown[] = [engagementId];
    if (statuses) {
      params.push(statuses);
      clauses.push(`status = ANY($${params.length}::text[])`);
    }
    if (types) {
      params.push(types);
      clauses.push(`signal_type = ANY($${params.length}::text[])`);
    }
    params.push(limit);
    const where = clauses.length > 0 ? `AND ${clauses.join(' AND ')}` : '';
    const result = await this.pool.query(
      `SELECT * FROM security_signals WHERE engagement_id = $1 ${where} ORDER BY created_at DESC LIMIT $${params.length}`,
      params,
    );
    return result.rows.map(mapSignalRow);
  }

  async listByEndpoint(endpointId: string, limit = 50): Promise<SecuritySignalRecord[]> {
    const result = await this.pool.query(
      'SELECT * FROM security_signals WHERE endpoint_id = $1 ORDER BY created_at DESC LIMIT $2',
      [endpointId, Math.min(Math.max(limit, 1), 500)],
    );
    return result.rows.map(mapSignalRow);
  }

  async listNew(engagementId: string, limit = 50): Promise<SecuritySignalRecord[]> {
    return this.listByEngagement(engagementId, { statuses: ['NEW'], limit });
  }

  async markStatus(id: string, status: SignalStatus): Promise<void> {
    await this.pool.query('UPDATE security_signals SET status = $1, updated_at = now() WHERE id = $2', [status, id]);
  }

  async countByEngagement(engagementId: string): Promise<{ total: number; new: number }> {
    const result = await this.pool.query(
      'SELECT count(*)::int AS total, count(*) FILTER (WHERE status = $2)::int AS new FROM security_signals WHERE engagement_id = $1',
      [engagementId, 'NEW'],
    );
    const row = result.rows[0] as { total: number; new: number };
    return { total: row.total, new: row.new };
  }
}

// -- Object candidates (§19, §96-§97) ---------------------------------------------

export interface UpsertObjectInput {
  engagementId: string;
  name: string;
  kind: string;
  parameterId: string | null;
  endpointId: string | null;
  exampleValue: string | null;
  ownerIdentityId: string | null;
  lifecycle: Record<string, unknown>;
  confidence: number;
  evidenceId: string | null;
  fingerprint: string;
  at: string;
}

export class ObjectCandidatesRepository {
  constructor(readonly pool: Pool) {}

  async upsert(input: UpsertObjectInput): Promise<{ record: ObjectCandidateRecord; created: boolean }> {
    const existing = await this.findByFingerprint(input.engagementId, input.fingerprint);
    if (existing) {
      const exampleValues =
        input.exampleValue !== null && !existing.example_values.includes(input.exampleValue)
          ? mergeUniqueBounded(existing.example_values, [input.exampleValue], 8)
          : existing.example_values;
      const result = await this.pool.query(
        `UPDATE object_candidates SET
           example_values = $2::jsonb,
           owner_identity_id = COALESCE(owner_identity_id, $3),
           lifecycle = $4::jsonb,
           observation_count = observation_count + 1,
           last_seen = $5
         WHERE id = $1 RETURNING *`,
        [
          existing.id,
          JSON.stringify(exampleValues),
          input.ownerIdentityId,
          JSON.stringify(mergeLifecycle(existing.lifecycle, input.lifecycle)),
          input.at,
        ],
      );
      return { record: mapObjectRow(result.rows[0]!), created: false };
    }
    const id = generateId('OBJ');
    const result = await this.pool.query(
      `INSERT INTO object_candidates (id, engagement_id, name, kind, parameter_id, endpoint_id, example_values,
         owner_identity_id, lifecycle, confidence, evidence_ids, fingerprint, first_seen, last_seen)
       VALUES ($1,$2,$3,$4,$5,$6,$7::jsonb,$8,$9::jsonb,$10,$11::jsonb,$12,$13,$13)
       RETURNING *`,
      [
        id,
        input.engagementId,
        input.name,
        input.kind,
        input.parameterId,
        input.endpointId,
        JSON.stringify(input.exampleValue !== null ? [input.exampleValue] : []),
        input.ownerIdentityId,
        JSON.stringify(input.lifecycle),
        input.confidence,
        JSON.stringify(input.evidenceId ? [input.evidenceId] : []),
        input.fingerprint,
        input.at,
      ],
    );
    return { record: mapObjectRow(result.rows[0]!), created: true };
  }

  async findByFingerprint(engagementId: string, fingerprint: string): Promise<ObjectCandidateRecord | null> {
    const result = await this.pool.query(
      'SELECT * FROM object_candidates WHERE engagement_id = $1 AND fingerprint = $2',
      [engagementId, fingerprint],
    );
    return result.rows[0] ? mapObjectRow(result.rows[0]) : null;
  }

  async listByEngagement(engagementId: string, limit = 100): Promise<ObjectCandidateRecord[]> {
    const result = await this.pool.query(
      'SELECT * FROM object_candidates WHERE engagement_id = $1 ORDER BY observation_count DESC, name LIMIT $2',
      [engagementId, Math.min(Math.max(limit, 1), 500)],
    );
    return result.rows.map(mapObjectRow);
  }

  async countByEngagement(engagementId: string): Promise<number> {
    const result = await this.pool.query(
      'SELECT count(*)::int AS total FROM object_candidates WHERE engagement_id = $1',
      [engagementId],
    );
    return (result.rows[0] as { total: number }).total;
  }
}

// -- Row mappers -------------------------------------------------------------------

function mapEndpointRow(row: Record<string, unknown>): EndpointRecord {
  return {
    id: row.id as string,
    engagement_id: row.engagement_id as string,
    fingerprint: row.fingerprint as string,
    scheme: row.scheme as string,
    host: row.host as string,
    port: row.port as number,
    path: row.path as string,
    canonical_path: row.canonical_path as string,
    canonical_confidence: Number(row.canonical_confidence),
    resource_family: (row.resource_family as string | null) ?? null,
    api_version: (row.api_version as string | null) ?? null,
    methods: (row.methods as EndpointMethodRecord[]) ?? [],
    content_types: (row.content_types as string[]) ?? [],
    authentication_observed: Boolean(row.authentication_observed),
    identities_observed: (row.identities_observed as string[]) ?? [],
    status: row.status as EndpointStatus,
    discovery_source: row.discovery_source as DiscoverySource,
    confidence_category: row.confidence_category as ConfidenceCategory,
    confidence: Number(row.confidence),
    observed_urls: (row.observed_urls as string[]) ?? [],
    observation_count: row.observation_count as number,
    signal_count: row.signal_count as number,
    evidence_ids: (row.evidence_ids as string[]) ?? [],
    merged_into: (row.merged_into as string | null) ?? null,
    first_seen: iso(row.first_seen as Date) ?? '',
    last_seen: iso(row.last_seen as Date) ?? '',
    created_at: iso(row.created_at as Date) ?? '',
    updated_at: iso(row.updated_at as Date) ?? '',
  };
}

function mapParameterRow(row: Record<string, unknown>): ParameterRecord {
  return {
    id: row.id as string,
    engagement_id: row.engagement_id as string,
    endpoint_id: (row.endpoint_id as string | null) ?? null,
    fingerprint: row.fingerprint as string,
    name: row.name as string,
    location: row.location as ParameterLocation,
    observed_type: (row.observed_type as string | null) ?? null,
    example_values: (row.example_values as string[]) ?? [],
    value_characteristics: (row.value_characteristics as ValueCharacteristic[]) ?? [],
    semantic_candidates: (row.semantic_candidates as SemanticCandidateRecord[]) ?? [],
    identity_association: (row.identity_association as string[]) ?? [],
    is_sensitive: Boolean(row.is_sensitive),
    confidence: Number(row.confidence),
    observation_count: row.observation_count as number,
    first_seen: iso(row.first_seen as Date) ?? '',
    last_seen: iso(row.last_seen as Date) ?? '',
    created_at: iso(row.created_at as Date) ?? '',
    updated_at: iso(row.updated_at as Date) ?? '',
  };
}

function mapMatrixRow(row: Record<string, unknown>): AuthorizationMatrixRecord {
  return {
    id: row.id as string,
    engagement_id: row.engagement_id as string,
    endpoint_id: row.endpoint_id as string,
    identity_id: (row.identity_id as string | null) ?? null,
    object_ref: (row.object_ref as string | null) ?? null,
    action: (row.action as string | null) ?? null,
    outcome: row.outcome as AccessOutcome,
    status_code: (row.status_code as number | null) ?? null,
    request_id: (row.request_id as string | null) ?? null,
    evidence_ids: (row.evidence_ids as string[]) ?? [],
    observation_count: row.observation_count as number,
    fingerprint: row.fingerprint as string,
    first_seen: iso(row.first_seen as Date) ?? '',
    last_seen: iso(row.last_seen as Date) ?? '',
  };
}

function mapSignalRow(row: Record<string, unknown>): SecuritySignalRecord {
  return {
    id: row.id as string,
    engagement_id: row.engagement_id as string,
    signal_type: row.signal_type as SignalType,
    source: row.source as string,
    endpoint_id: (row.endpoint_id as string | null) ?? null,
    parameter_id: (row.parameter_id as string | null) ?? null,
    identity_ids: (row.identity_ids as string[]) ?? [],
    object_ref: (row.object_ref as string | null) ?? null,
    confidence: Number(row.confidence),
    summary: row.summary as string,
    metadata: (row.metadata as Record<string, unknown>) ?? {},
    status: row.status as SignalStatus,
    evidence_ids: (row.evidence_ids as string[]) ?? [],
    fingerprint: row.fingerprint as string,
    created_at: iso(row.created_at as Date) ?? '',
    updated_at: iso(row.updated_at as Date) ?? '',
  };
}

function mapObjectRow(row: Record<string, unknown>): ObjectCandidateRecord {
  return {
    id: row.id as string,
    engagement_id: row.engagement_id as string,
    name: row.name as string,
    kind: row.kind as string,
    parameter_id: (row.parameter_id as string | null) ?? null,
    endpoint_id: (row.endpoint_id as string | null) ?? null,
    example_values: (row.example_values as string[]) ?? [],
    owner_identity_id: (row.owner_identity_id as string | null) ?? null,
    lifecycle: (row.lifecycle as Record<string, unknown>) ?? {},
    confidence: Number(row.confidence),
    observation_count: row.observation_count as number,
    evidence_ids: (row.evidence_ids as string[]) ?? [],
    fingerprint: row.fingerprint as string,
    first_seen: iso(row.first_seen as Date) ?? '',
    last_seen: iso(row.last_seen as Date) ?? '',
    created_at: iso(row.created_at as Date) ?? '',
  };
}

// -- Merge helpers (bounded, deterministic) --------------------------------------------

export function mergeUnique(existing: string[], additions: string[]): string[] {
  const set = new Set(existing);
  for (const item of additions) set.add(item);
  return [...set];
}

export function mergeUniqueBounded(existing: string[], additions: string[], max: number): string[] {
  const merged = mergeUnique(existing, additions);
  return merged.slice(0, max);
}

function mergeLifecycle(
  existing: Record<string, unknown>,
  additions: Record<string, unknown>,
): Record<string, unknown> {
  const merged: Record<string, unknown> = { ...existing };
  for (const [key, value] of Object.entries(additions)) {
    const current = merged[key];
    if (Array.isArray(current) && Array.isArray(value)) {
      merged[key] = mergeUniqueBounded(current as string[], value as string[], 32);
    } else if (value !== undefined && value !== null) {
      merged[key] = value;
    }
  }
  return merged;
}

export type { ParameterSemantic };
