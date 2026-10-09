/**
 * Observation ingestion processor (spec §1, §109-§112, §124 step 1).
 *
 * Subscribes to Part 3 events, dispatches to deterministic extractors, and
 * persists derived observations. Guarantees:
 *  - RAW events stay durable even when an extractor fails (§110)
 *  - processing is idempotent (§111)
 *  - a crashing extractor NEVER crashes the engagement (§112)
 *  - processing happens after persistence (§110)
 */
import { createHash } from 'node:crypto';
import type { PlatformEvent } from '@aegis/contracts';
import type { Logger } from '@aegis/logging';
import type {
  EndpointRecord,
  ParameterRecord,
  Repositories,
  SecuritySignalRecord,
  WorkflowRecord,
} from '@aegis/database';
import { iso } from '@aegis/database';
import type { EventBus } from '@aegis/events';
import { generateId } from '@aegis/shared';
import { mapRequestRow, mapResponseRow } from '@aegis/target-http';
import { canonicalUpgrade, deriveEndpoint } from './endpoint-extractor.js';
import {
  extractFormParameters,
  extractRequestParameters,
  extractWsParameters,
  parameterFingerprint,
  pathParameterNames,
} from './parameter-extractor.js';
import {
  compareResponses,
  differentialFingerprint,
  findReflection,
  responseRowToComparison,
} from './differential.js';
import { scanForJwtTokens, compareTokens, type JwtFacts, type TokenObservation } from './token-analysis.js';
import {
  authStateChangeSignal,
  reflectionSignal,
  signalsFromMatrix,
  signalsFromParameters,
  signalsFromResponse,
  stateTransitionAnomalySignal,
  tokenComparisonSignals,
  tokenPatternSignal,
  unexpectedMethodSignal,
  unexpectedRedirectSignal,
  type SignalCandidate,
} from './signal-engine.js';
import { authBoundaryFor, classifyAuthSurface, classifyOutcome, matrixFingerprint, objectRefForRequest } from './authorization.js';
import {
  prerequisiteAnomalies,
  segmentByIdentity,
  transitionsFromSequence,
  workflowNameForHost,
  type SequenceStep,
} from './workflow-engine.js';
import { formToRequestFlows, reflectionFlows, scriptToEndpointFlows, storageToRequestFlows, type FlowFact } from './dataflow.js';
import { AttackSurfaceGraph } from './graph.js';
import { objectFingerprint } from './object-model.js';
import { DEFAULT_REASONING_LIMITS, ReasoningLimitError, type ReasoningLimits } from './limits.js';

export interface ProcessorDeps {
  repos: Repositories;
  eventBus: Pick<EventBus, 'publish'>;
  logger?: Pick<Logger, 'info' | 'warn'>;
  limits?: Partial<ReasoningLimits>;
}

export interface IngestSummary {
  processed: number;
  createdEndpoints: number;
  updatedEndpoints: number;
  createdParameters: number;
  matrixEntries: number;
  signalsCreated: number;
  failures: number;
}

const PROCESSED_SET_CAP = 10_000;
const BATCH_SIGNAL_THRESHOLD = 8;

/**
 * The reasoning ingestion pipeline. One instance per application process;
 * all state lives in the database (in-memory caches are accelerators only).
 */
export class ReasoningEventProcessor {
  private readonly repos: Repositories;
  private readonly eventBus: ProcessorDeps['eventBus'];
  private readonly logger?: ProcessorDeps['logger'];
  private readonly limits: ReasoningLimits;
  private readonly graph: AttackSurfaceGraph;
  private readonly processedRequests = new Map<string, true>();
  private readonly engagementNodes = new Set<string>();
  private readonly endpointPathCache = new Map<string, string>();
  private unsubscribe: (() => void) | null = null;
  private signalCounter = 0;

  constructor(deps: ProcessorDeps) {
    this.repos = deps.repos;
    this.eventBus = deps.eventBus;
    this.logger = deps.logger;
    this.limits = { ...DEFAULT_REASONING_LIMITS, ...deps.limits };
    this.graph = new AttackSurfaceGraph({ nodes: this.repos.attackNodes, edges: this.repos.attackEdges });
  }

  // -------------------------------------------------------------------------
  // Event subscription (§109).
  // -------------------------------------------------------------------------

  subscribe(): () => void {
    if (this.unsubscribe) return this.unsubscribe;
    const bus = this.eventBus as { subscribe?: (handler: (event: PlatformEvent) => void | Promise<void>) => () => void };
    this.unsubscribe = bus.subscribe?.((event) => this.handleEvent(event)) ?? null;
    return () => {
      this.unsubscribe?.();
      this.unsubscribe = null;
    };
  }

  /** Dispatch a single event with failure isolation (§112). */
  async handleEvent(event: PlatformEvent): Promise<void> {
    try {
      switch (event.type) {
        case 'HTTP_REQUEST_RECORDED': {
          const requestId = payloadString(event.payload, 'request_id');
          if (requestId) await this.ingestExchange(requestId, { eventId: event.trace_id ?? null });
          break;
        }
        case 'HTTP_RESPONSE_RECORDED': {
          const requestId = payloadString(event.payload, 'request_id');
          if (requestId && !this.processedRequests.has(requestId)) {
            await this.ingestExchange(requestId, { eventId: event.trace_id ?? null });
          }
          break;
        }
        case 'DOM_SNAPSHOT_CAPTURED': {
          const snapshotId = payloadString(event.payload, 'snapshot_id');
          if (snapshotId && event.engagement_id) await this.ingestDomSnapshot(event.engagement_id, snapshotId);
          break;
        }
        case 'AUTH_WORKFLOW_RECORDED': {
          const identityId = payloadString(event.payload, 'identity_id');
          if (event.engagement_id && identityId) {
            await this.recordAuthBoundary(
              event.engagement_id,
              identityId,
              'SESSION_ESTABLISHED',
              `auth workflow ${payloadString(event.payload, 'workflow_id') ?? ''}`.trim(),
            );
          }
          break;
        }
        case 'SESSION_EXPIRATION_DETECTED': {
          const sessionId = payloadString(event.payload, 'session_id');
          const detail =
            payloadString(event.payload, 'detail') ?? payloadString(event.payload, 'signal') ?? 'session expiration';
          if (event.engagement_id && sessionId) {
            const session = await this.repos.sessions.findById(sessionId).catch(() => null);
            if (session) {
              await this.recordAuthBoundary(event.engagement_id, session.identity_id, 'EXPIRATION', detail);
            }
          }
          break;
        }
        default:
          break;
      }
    } catch (error) {
      await this.recordFailure('event-dispatch', { type: event.type, trace: event.trace_id }, error, event.engagement_id ?? undefined);
    }
  }

  // -------------------------------------------------------------------------
  // HTTP exchange ingestion (the main pipeline).
  // -------------------------------------------------------------------------

  async ingestExchange(requestId: string, options: { eventId: string | null }): Promise<void> {
    const requestRow = await this.repos.httpRequests.findById(requestId);
    if (!requestRow) return;
    const engagementId = requestRow['engagement_id'] as string;
    this.markProcessed(requestId);

    try {
      const request = mapRequestRow(requestRow);
      const responseRow = await this.repos.httpResponses.findByRequestId(requestId);
      const response = responseRow ? mapResponseRow(responseRow) : null;
      const at = request.created_at;

      // 1. Endpoint upsert + canonical upgrade (§7-§13).
      const endpoint = await this.observeEndpoint(request, engagementId, at);
      if (!endpoint) return;

      // 2. Attack graph wiring (§4-§5).
      await this.wireGraphForRequest(engagementId, endpoint, request.identity_id, request.browser_page_id, at);

      // 3. Parameter extraction (§14-§18).
      const parameters = await this.observeParameters(engagementId, endpoint, request, at);

      // 4. Response-driven derived state (§23, §62-§65).
      if (response && responseRow) {
        await this.observeResponse(engagementId, endpoint, request, response, responseRow, parameters, at);
      }

      // 5. Signal refresh batching (§42): cheap during live events.
      this.signalCounter += 1;
      if (this.signalCounter % BATCH_SIGNAL_THRESHOLD === 0) {
        await this.refreshEndpointSignals(engagementId, endpoint);
      }
    } catch (error) {
      await this.recordFailure('ingest-exchange', { type: 'HTTP', trace: options.eventId }, error, engagementId);
    }
  }

  private async observeEndpoint(
    request: { method: string; url: string; source: string; identity_id: string | null },
    engagementId: string,
    at: string,
  ): Promise<EndpointRecord | null> {
    const discoverySource =
      request.source === 'BROWSER' ? 'BROWSER_NETWORK' : request.source === 'IMPORTED' ? 'IMPORTED_TRAFFIC' : 'USER_INPUT';
    const derived = deriveEndpoint({
      engagementId,
      url: request.url,
      method: request.method,
      contentType: null,
      identityId: null,
      discoverySource,
      evidenceId: null,
      at,
    });
    if (!derived) return null;

    // Canonical upgrade path (§7): a concrete endpoint that later sees a
    // distinct identifier value at the same position becomes templated.
    const candidates = await this.repos.endpoints.listByHost(engagementId, derived.host);
    for (const candidate of candidates) {
      if (candidate.fingerprint === derived.fingerprint) continue;
      const upgrade = canonicalUpgrade(candidate, request.url);
      if (!upgrade) continue;
      try {
        const updated = await this.repos.endpoints.update(candidate.id, {
          canonical_path: upgrade.canonicalPath,
          canonical_confidence: upgrade.canonicalConfidence,
          fingerprint: derived.fingerprint,
          resource_family: derived.resourceFamily,
          status: 'OBSERVED',
        });
        const merged = await this.repos.endpoints.upsert({
          engagementId,
          fingerprint: updated.fingerprint,
          scheme: updated.scheme,
          host: updated.host,
          port: updated.port,
          path: updated.path,
          canonicalPath: updated.canonical_path,
          canonicalConfidence: updated.canonical_confidence,
          resourceFamily: updated.resource_family,
          apiVersion: updated.api_version,
          method: request.method,
          contentType: null,
          identityId: null,
          status: updated.status,
          discoverySource,
          confidenceCategory: updated.confidence_category,
          confidence: updated.confidence,
          observedUrl: request.url,
          evidenceId: null,
          at,
        });
        await this.publishDerived('ENDPOINT_MERGED', engagementId, {
          endpoint_id: merged.record.id,
          canonical_path: merged.record.canonical_path,
          merged_observation: request.url,
        });
        return merged.record;
      } catch {
        // Fingerprint conflict: another endpoint already holds the templated
        // fingerprint — mark this one merged into it (§7 dedup).
        const existing = await this.repos.endpoints.findByFingerprint(engagementId, derived.fingerprint);
        if (existing && existing.id !== candidate.id) {
          await this.repos.endpoints.markMerged(candidate.id, existing.id);
          await this.repos.endpoints.upsert({
            engagementId,
            fingerprint: existing.fingerprint,
            scheme: existing.scheme,
            host: existing.host,
            port: existing.port,
            path: existing.path,
            canonicalPath: existing.canonical_path,
            canonicalConfidence: existing.canonical_confidence,
            resourceFamily: existing.resource_family,
            apiVersion: existing.api_version,
            method: request.method,
            contentType: null,
            identityId: null,
            status: existing.status,
            discoverySource,
            confidenceCategory: existing.confidence_category,
            confidence: existing.confidence,
            observedUrl: request.url,
            evidenceId: null,
            at,
          });
          return (await this.repos.endpoints.findByFingerprint(engagementId, existing.fingerprint)) ?? existing;
        }
        throw new Error(`canonical upgrade failed for endpoint ${candidate.id}`);
      }
    }

    const result = await this.repos.endpoints.upsert({
      engagementId,
      fingerprint: derived.fingerprint,
      scheme: derived.scheme,
      host: derived.host,
      port: derived.port,
      path: derived.path,
      canonicalPath: derived.canonicalPath,
      canonicalConfidence: derived.canonicalConfidence,
      resourceFamily: derived.resourceFamily,
      apiVersion: derived.apiVersion,
      method: request.method,
      contentType: null,
      identityId: request.identity_id,
      status: derived.status,
      discoverySource,
      confidenceCategory: derived.confidenceCategory,
      confidence: derived.confidence,
      observedUrl: request.url,
      evidenceId: null,
      at,
    });
    this.endpointPathCache.set(result.record.id, result.record.canonical_path);
    if (result.created) {
      await this.publishDerived('ENDPOINT_DISCOVERED', engagementId, {
        endpoint_id: result.record.id,
        canonical_path: result.record.canonical_path,
        method: request.method,
        discovery_source: discoverySource,
      });
    }
    return result.record;
  }

  private async wireGraphForRequest(
    engagementId: string,
    endpoint: EndpointRecord,
    identityId: string | null,
    pageId: string | null,
    at: string,
  ): Promise<void> {
    try {
      await this.ensureEngagementNodeOnce(engagementId);
      const hostNode = await this.graph.ensureHostNode(engagementId, endpoint.host);
      if (identityId) {
        const identities = await this.repos.identities.listByEngagement(engagementId);
        const identity = identities.find((entry) => entry.id === identityId);
        await this.graph.ensureIdentityNode(engagementId, identityId, identity?.name ?? identityId, identity?.role ?? '');
      }
      await this.graph.wireEndpoint(engagementId, endpoint, { hostNode, identityId, pageId });
    } catch (error) {
      await this.recordFailure('graph-wire', { type: 'GRAPH' }, error, engagementId);
    }
    void at;
  }

  private async observeParameters(
    engagementId: string,
    endpoint: EndpointRecord,
    request: {
      method: string;
      url: string;
      query: Array<{ name: string; value: string }>;
      headers: Array<{ name: string; value: string }>;
      body: { body_type: string; parsed?: unknown } | null;
      identity_id: string | null;
    },
    at: string,
  ): Promise<ParameterRecord[]> {
    const records: ParameterRecord[] = [];
    try {
      const endpointNode = await this.graph.ensureEndpointNode(engagementId, endpoint);

      // Path parameters from the canonical form (§14 PATH).
      for (const entry of pathParameterNames(endpoint.canonical_path)) {
        const fingerprint = parameterFingerprint(endpoint.fingerprint, 'PATH', entry.name);
        const result = await this.repos.parameters.upsert({
          engagementId,
          endpointId: endpoint.id,
          fingerprint,
          name: entry.name,
          location: 'PATH',
          observedType: 'string',
          exampleValue: extractPathValue(request.url, entry.segmentIndex),
          valueCharacteristics: [],
          semanticCandidates: [{ semantic: 'IDENTIFIER', confidence: 0.7, reason: 'templated path position' }],
          identityId: request.identity_id,
          isSensitive: false,
          confidence: 0.7,
          at,
        });
        records.push(result.record);
        if (result.created) {
          await this.publishDerived('PARAMETER_OBSERVED', engagementId, {
            parameter_id: result.record.id,
            name: entry.name,
            location: 'PATH',
            endpoint_id: endpoint.id,
          });
        }
        const parameterNode = await this.graph.ensureParameterNode(engagementId, result.record.id, entry.name, 'PATH');
        await this.graph.link(engagementId, endpointNode, parameterNode, 'accepts', { location: 'PATH' });
      }

      // Request-derived parameters (§14).
      const extracted = extractRequestParameters({
        method: request.method,
        url: request.url,
        query: request.query,
        headers: request.headers,
        bodyType: request.body?.body_type ?? null,
        bodyParsed: request.body?.parsed ?? null,
      });
      for (const parameter of extracted) {
        const fingerprint = parameterFingerprint(endpoint.fingerprint, parameter.location, parameter.name);
        const result = await this.repos.parameters.upsert({
          engagementId,
          endpointId: endpoint.id,
          fingerprint,
          name: parameter.name,
          location: parameter.location,
          observedType: parameter.observedType,
          exampleValue: parameter.exampleValue,
          valueCharacteristics: parameter.valueCharacteristics,
          semanticCandidates: parameter.semanticCandidates,
          identityId: request.identity_id,
          isSensitive: parameter.isSensitive,
          confidence: 0.7,
          at,
        });
        records.push(result.record);
        if (result.created) {
          await this.publishDerived('PARAMETER_OBSERVED', engagementId, {
            parameter_id: result.record.id,
            name: parameter.name,
            location: parameter.location,
            endpoint_id: endpoint.id,
          });
        }
        const parameterNode = await this.graph.ensureParameterNode(
          engagementId,
          result.record.id,
          parameter.name,
          parameter.location,
        );
        await this.graph.link(engagementId, endpointNode, parameterNode, 'accepts', { location: parameter.location });
      }
    } catch (error) {
      await this.recordFailure('parameter-extract', { type: 'PARAMETERS' }, error, engagementId);
    }
    return records;
  }

  private async observeResponse(
    engagementId: string,
    endpoint: EndpointRecord,
    request: { identity_id: string | null; method: string; url: string; query: Array<{ name: string; value: string }> },
    response: { status: number; redirect_to: string | null; content_kind: string },
    responseRow: Record<string, unknown>,
    parameters: ParameterRecord[],
    at: string,
  ): Promise<void> {
    try {
      // Authorization matrix entry (§23, §98).
      const objectRef = objectRefForRequest(endpoint, request.url);
      const outcome = classifyOutcome({
        status: response.status,
        redirectTo: response.redirect_to,
        identityId: request.identity_id,
      });
      await this.repos.authzMatrix.upsert({
        engagementId,
        endpointId: endpoint.id,
        identityId: request.identity_id,
        objectRef,
        action: request.method,
        outcome,
        statusCode: response.status,
        requestId: null,
        evidenceId: null,
        fingerprint: matrixFingerprint(endpoint.fingerprint, request.identity_id, objectRef, request.method),
        at,
      });
      await this.publishDerived('AUTHORIZATION_MATRIX_UPDATED', engagementId, {
        endpoint_id: endpoint.id,
        identity_id: request.identity_id,
        outcome,
        object_ref: objectRef,
      });

      // Object candidate upserts (§19, §96-§97).
      if (objectRef) {
        const [objectName, objectValue] = objectRef.split(':');
        if (objectName && objectValue) {
          await this.repos.objectCandidates.upsert({
            engagementId,
            name: objectName,
            kind: 'RESOURCE',
            parameterId: null,
            endpointId: endpoint.id,
            exampleValue: objectValue,
            ownerIdentityId: request.identity_id,
            lifecycle: {},
            confidence: 0.65,
            evidenceId: null,
            fingerprint: objectFingerprint(objectName, endpoint.resource_family),
            at,
          });
        }
      }

      // Authentication boundary detection (§21-§22).
      const authSurface = classifyAuthSurface(request.method, endpoint.path, response.status);
      const boundary = authBoundaryFor(authSurface, request.method, response.status);
      if (boundary && request.identity_id) {
        await this.recordAuthBoundary(
          engagementId,
          request.identity_id,
          boundary.after === 'AUTHENTICATED' ? 'LOGIN' : 'LOGOUT',
          `${request.method} ${endpoint.path} -> ${response.status}`,
        );
      }

      // Response-driven signals (§62-§65).
      const comparison = responseRowToComparison(responseRow);
      const responseSignals = signalsFromResponse(endpoint, {
        status: response.status,
        contentKind: response.content_kind,
        bodyPreview: comparison.bodyPreview,
        redirectTo: response.redirect_to,
      });
      const redirectSignal = unexpectedRedirectSignal(endpoint, {
        redirectTo: response.redirect_to,
        identityId: request.identity_id,
        authenticated: request.identity_id !== null,
      });
      if (redirectSignal) responseSignals.push(redirectSignal);

      // Reflection detection (§65) + data flows (§41, §92).
      const inputValues = request.query.map((param) => ({ name: param.name, value: param.value }));
      const reflections = findReflection(inputValues, comparison);
      if (reflections.length > 0) {
        const parameterIds: Record<string, string> = {};
        for (const parameter of parameters) parameterIds[parameter.name] = parameter.id;
        const reflection = reflectionSignal(endpoint, reflections, parameterIds);
        if (reflection) responseSignals.push(reflection);
        await this.recordFlows(engagementId, reflectionFlows(parameters, reflections, endpoint));
      }

      // Token scanning (§59-§60) — decoded claims only, never token strings.
      const tokens = scanForJwtTokens(comparison.bodyPreview);
      if (tokens.length > 0) {
        responseSignals.push(tokenPatternSignal(endpoint, { facts: tokens[0]!.facts, sourceSummary: 'response body' }));
      }

      for (const signal of responseSignals) {
        await this.insertSignal(engagementId, signal);
      }

      // Method-surface expansion signal (§42 UNEXPECTED_METHOD_BEHAVIOR).
      if (response.status >= 200 && response.status < 300 && endpoint.methods.length > 1) {
        const methodSignal = unexpectedMethodSignal(endpoint, request.method);
        if (methodSignal) await this.insertSignal(engagementId, methodSignal);
      }

      // Form-to-request correlation (§92).
      const flows = formToRequestFlows(
        parameters
          .filter((parameter) => parameter.location === 'HTML_FORM')
          .map((parameter) => ({ inputName: parameter.name, formAction: null, pageUrl: null })),
        {
          url: request.url,
          method: request.method,
          bodyType: null,
          parameters: parameters.map((parameter) => ({ name: parameter.name, location: parameter.location })),
        },
        endpoint,
      );
      await this.recordFlows(engagementId, flows);
    } catch (error) {
      await this.recordFailure('response-observe', { type: 'RESPONSE' }, error, engagementId);
    }
  }

  // -------------------------------------------------------------------------
  // DOM snapshot ingestion (§109, §91-§92).
  // -------------------------------------------------------------------------

  async ingestDomSnapshot(engagementId: string, snapshotId: string): Promise<void> {
    try {
      const snapshots = await this.repos.domSnapshots.listByEngagement(engagementId, 500);
      const row = snapshots.find((entry) => entry['id'] === snapshotId);
      if (!row) return;
      const snapshot = (row['snapshot'] as Record<string, unknown>) ?? {};
      const url = (row['url'] as string) ?? '';
      const contextId = (row['context_id'] as string) ?? null;
      const at = iso(row['created_at'] as Date) ?? new Date().toISOString();

      await this.ensureEngagementNodeOnce(engagementId);
      await this.graph.ensurePageNode(engagementId, snapshotId, url);

      // HTML form parameters (§14 HTML_FORM) + FORM nodes (§4).
      const forms = extractFormParameters(snapshot);
      const endpoints = await this.repos.endpoints.listByEngagement(engagementId, { limit: 500 });
      for (const form of forms.slice(0, 64)) {
        const fingerprint = parameterFingerprint(`dom:${url}`, 'HTML_FORM', form.name);
        const result = await this.repos.parameters.upsert({
          engagementId,
          endpointId: resolveFormEndpoint(endpoints, form.formAction),
          fingerprint,
          name: form.name,
          location: 'HTML_FORM',
          observedType: form.type,
          exampleValue: null,
          valueCharacteristics: [],
          semanticCandidates: [],
          identityId: null,
          isSensitive: /pass(word)?|secret|token/i.test(form.name),
          confidence: 0.6,
          at,
        });
        if (result.created) {
          await this.publishDerived('PARAMETER_OBSERVED', engagementId, {
            parameter_id: result.record.id,
            name: form.name,
            location: 'HTML_FORM',
            page_url: url,
          });
        }
        await this.graph.ensureFormNode(engagementId, url, form.formAction ?? '');
      }

      // Script inventory -> SCRIPT nodes + script-to-endpoint flows (§91).
      const scripts = (snapshot['scripts'] as Array<Record<string, unknown>>) ?? [];
      const scriptFacts = scripts
        .map((script) => ({
          src: typeof script['src'] === 'string' ? (script['src'] as string) : null,
          pageUrl: url,
        }))
        .filter((entry): entry is { src: string; pageUrl: string } => entry.src !== null);
      for (const script of scriptFacts.slice(0, 64)) {
        await this.graph.ensureScriptNode(engagementId, script.src);
      }
      await this.recordFlows(engagementId, scriptToEndpointFlows(scriptFacts, endpoints));

      // Storage correlation (§90) — authorization-bearing requests.
      if (contextId) {
        await this.correlateStorage(engagementId, contextId, endpoints);
      }
    } catch (error) {
      await this.recordFailure('dom-snapshot', { type: 'DOM', trace: snapshotId }, error, engagementId);
    }
  }

  private async correlateStorage(engagementId: string, contextId: string, endpoints: EndpointRecord[]): Promise<void> {
    try {
      const storage = await this.repos.storageEntries.listByContext(contextId);
      const keys = (storage as Array<Record<string, unknown>>).map((entry) => ({
        key: (entry['key'] as string) ?? '',
        area: (entry['area'] as string) ?? 'LOCAL',
        identityId: (entry['identity_id'] as string | null) ?? null,
        pageUrl: null,
      }));
      const requests = await this.repos.httpRequests.listByEngagement(engagementId, 100, 0);
      for (const request of (requests as Array<Record<string, unknown>>).slice(0, 32)) {
        const headers = (request['headers'] as Array<{ name: string; value: string }>) ?? [];
        const hasAuth = headers.some((header) => header.name.toLowerCase() === 'authorization');
        const url = (request['url'] as string) ?? '';
        const endpoint = endpoints.find((entry) => entry.observed_urls.includes(url)) ?? null;
        const flows = storageToRequestFlows(keys, { url, hasAuthorizationHeader: hasAuth, identityId: null }, endpoint);
        await this.recordFlows(engagementId, flows);
      }
    } catch (error) {
      await this.recordFailure('storage-correlate', { type: 'STORAGE' }, error, engagementId);
    }
  }

  // -------------------------------------------------------------------------
  // WebSocket ingestion (§89, backfill path).
  // -------------------------------------------------------------------------

  async ingestWebsockets(engagementId: string): Promise<void> {
    try {
      const connections = await this.repos.websockets.listConnections(engagementId);
      for (const connection of (connections as Array<Record<string, unknown>>).slice(0, 32)) {
        const connectionId = (connection['id'] as string) ?? '';
        const url = (connection['url'] as string) ?? '';
        await this.graph.ensureWebSocketNode(engagementId, connectionId, url);
        const messages = await this.repos.websockets.listMessages(connectionId, 200);
        const messageRows = messages as Array<Record<string, unknown>>;
        for (const message of messageRows.slice(0, 64)) {
          const preview = (message['payload_preview'] as string | null) ?? null;
          const direction = (message['direction'] as string) ?? 'CLIENT_TO_SERVER';
          for (const field of extractWsParameters(preview)) {
            const fingerprint = parameterFingerprint(`ws:${url}`, 'WEBSOCKET', field.name);
            await this.repos.parameters.upsert({
              engagementId,
              endpointId: null,
              fingerprint,
              name: field.name,
              location: 'WEBSOCKET',
              observedType: typeof field.value === 'string' ? 'string' : 'unknown',
              exampleValue: typeof field.value === 'string' ? field.value : null,
              valueCharacteristics: field.characteristics,
              semanticCandidates: [],
              identityId: null,
              isSensitive: /token|auth|secret/i.test(field.name),
              confidence: 0.6,
              at: new Date().toISOString(),
            });
          }
          // WS echo detection (§41 WS_REQUEST_RESPONSE).
          if (direction === 'CLIENT_TO_SERVER' && preview) {
            const echoed = messageRows.find(
              (candidate) =>
                candidate['direction'] === 'SERVER_TO_CLIENT' &&
                typeof candidate['payload_preview'] === 'string' &&
                (candidate['payload_preview'] as string).includes(preview.slice(0, 64)),
            );
            if (echoed) {
              await this.recordFlows(engagementId, [
                {
                  source: { kind: 'WEBSOCKET_MESSAGE', name: 'client_message', endpoint_id: null, page_url: url },
                  transformations: [],
                  sink: { kind: 'WEBSOCKET', name: 'server_reply', endpoint_id: null },
                  correlation: 'WS_REQUEST_RESPONSE',
                  confidence: 0.75,
                  evidenceIds: [],
                  fingerprint: flowFingerprintOf(`ws|${url}|${preview.slice(0, 64)}`),
                },
              ]);
            }
          }
        }
      }
    } catch (error) {
      await this.recordFailure('websocket-ingest', { type: 'WEBSOCKET' }, error, engagementId);
    }
  }

  // -------------------------------------------------------------------------
  // Workflow reconstruction (§30-§35, §94).
  // -------------------------------------------------------------------------

  async rebuildWorkflows(engagementId: string): Promise<void> {
    try {
      const requests = await this.repos.httpRequests.listByEngagement(engagementId, 500, 0);
      const ordered = [...requests].reverse(); // ASC chronological (§94)
      const endpoints = await this.repos.endpoints.listByEngagement(engagementId, { limit: 1000 });
      const steps: SequenceStep[] = [];
      for (const request of ordered as Array<Record<string, unknown>>) {
        const requestId = (request['id'] as string) ?? '';
        const url = (request['url'] as string) ?? '';
        const endpoint = endpoints.find(
          (entry) => entry.observed_urls.includes(url) || entry.path === extractPathOfUrl(url),
        );
        const response = await this.repos.httpResponses.findByRequestId(requestId).catch(() => null);
        steps.push({
          requestId,
          method: (request['method'] as string) ?? 'GET',
          path: extractPathOfUrl(url) ?? '/',
          status: response ? ((response['status'] as number) ?? null) : null,
          identityId: (request['identity_id'] as string | null) ?? null,
          at: iso(request['created_at'] as Date) ?? new Date().toISOString(),
          endpointId: endpoint?.id ?? null,
          evidenceId: null,
        });
      }

      const segments = segmentByIdentity(steps);
      const hosts = new Set(endpoints.map((endpoint) => endpoint.host));
      const host = [...hosts][0] ?? 'target';
      let workflow: WorkflowRecord | null = await this.repos.workflows.findByName(engagementId, workflowNameForHost(host));
      if (!workflow) {
        workflow = await this.repos.workflows.create({
          engagementId,
          name: workflowNameForHost(host),
          requiredIdentity: null,
          confidence: 0.7,
        });
      }

      const stateIds = new Map<string, string>();
      const allTransitions: Array<ReturnType<typeof transitionsFromSequence>['transitions'][number]> = [];
      for (const [segmentKey, sequence] of segments) {
        const identityId = segmentKey.split('#')[0]!;
        const { states, transitions } = transitionsFromSequence(
          sequence.map((step) => ({ ...step, identityId: identityId === 'ANONYMOUS' ? null : identityId })),
        );
        for (const [name, state] of states) {
          const record = await this.repos.workflowStates.upsert({
            workflowId: workflow.id,
            engagementId,
            name,
            detection: state.detection,
            observed: state.observed,
            confidence: state.confidence,
            at: sequence[0]?.at ?? new Date().toISOString(),
          });
          stateIds.set(name, record.id);
        }
        for (const transition of transitions) {
          const toStateId = stateIds.get(transition.toStateName);
          if (!toStateId) continue;
          const record = await this.repos.workflowTransitions.upsert({
            workflowId: workflow.id,
            engagementId,
            fromStateId: transition.fromStateName ? (stateIds.get(transition.fromStateName) ?? null) : null,
            toStateId,
            triggerEndpointId: transition.triggerEndpointId,
            triggerSummary: transition.triggerSummary,
            identityId: transition.identityId,
            observationKind: transition.observationKind,
            confidence: transition.confidence,
            evidenceIds: transition.evidenceIds,
            fingerprint: transition.fingerprint,
            at: transition.at,
          });
          if (record.created) {
            await this.publishDerived('WORKFLOW_TRANSITION_RECORDED', engagementId, {
              workflow_id: workflow.id,
              transition_id: record.record.id,
              from: transition.fromStateName,
              to: transition.toStateName,
              trigger: transition.triggerSummary,
              identity_id: transition.identityId,
            });
          }
          allTransitions.push(transition);
        }
      }

      // Business-logic signals from prerequisites (§36).
      for (const anomaly of prerequisiteAnomalies(allTransitions)) {
        await this.insertSignal(
          engagementId,
          stateTransitionAnomalySignal({
            workflowId: workflow.id,
            identityId: null,
            triggerSummary: anomaly.triggerSummary,
            anomaly: anomaly.anomaly,
            detail: anomaly.detail,
            evidenceIds: [],
          }),
        );
      }

      const states = await this.repos.workflowStates.listByWorkflow(workflow.id);
      const recorded = await this.repos.workflowTransitions.listByWorkflow(workflow.id);
      await this.repos.workflows.updateCounts(workflow.id, states.length, recorded.length);
      await this.publishDerived('WORKFLOW_RECONSTRUCTED', engagementId, {
        workflow_id: workflow.id,
        states: states.length,
        transitions: recorded.length,
      });

      // Graph wiring (§4 WORKFLOW/STATE nodes).
      await this.ensureEngagementNodeOnce(engagementId);
      const workflowNode = await this.graph.ensureWorkflowNode(engagementId, workflow.id, workflow.name);
      for (const state of states) {
        const stateNode = await this.graph.ensureStateNode(engagementId, state.id, state.name);
        await this.graph.link(engagementId, workflowNode, stateNode, 'contains');
      }
      for (const transition of recorded) {
        if (!transition.from_state_id) continue;
        const fromNode = await this.graph.ensureStateNode(engagementId, transition.from_state_id, `state:${transition.from_state_id}`);
        const toNode = await this.graph.ensureStateNode(engagementId, transition.to_state_id, `state:${transition.to_state_id}`);
        await this.graph.link(engagementId, fromNode, toNode, 'transitions_to', {
          trigger: bounded(transition.trigger_summary, 200),
        });
      }
    } catch (error) {
      await this.recordFailure('workflow-rebuild', { type: 'WORKFLOW' }, error, engagementId);
    }
  }

  // -------------------------------------------------------------------------
  // Backfill (§110, API-driven full pass).
  // -------------------------------------------------------------------------

  async backfill(engagementId: string, limit = 200): Promise<IngestSummary> {
    const summary: IngestSummary = {
      processed: 0,
      createdEndpoints: 0,
      updatedEndpoints: 0,
      createdParameters: 0,
      matrixEntries: 0,
      signalsCreated: 0,
      failures: 0,
    };
    const before = await this.countAll(engagementId);

    const requests = await this.repos.httpRequests.listByEngagement(engagementId, Math.min(limit, 500), 0);
    const ordered = [...requests].reverse();
    for (const request of ordered as Array<Record<string, unknown>>) {
      const requestId = (request['id'] as string) ?? '';
      if (!requestId) continue;
      await this.ingestExchange(requestId, { eventId: null });
      summary.processed += 1;
    }

    // DOM snapshots, websockets, auth workflows (§109 sources).
    const snapshots = await this.repos.domSnapshots.listByEngagement(engagementId, 100);
    for (const snapshot of snapshots as Array<Record<string, unknown>>) {
      const snapshotId = (snapshot['id'] as string) ?? '';
      if (snapshotId) await this.ingestDomSnapshot(engagementId, snapshotId);
    }
    await this.ingestWebsockets(engagementId);
    for (const workflow of (await this.repos.authWorkflows.listByEngagement(engagementId)) as Array<Record<string, unknown>>) {
      const identityId = (workflow['identity_id'] as string) ?? null;
      if (identityId) {
        await this.recordAuthBoundary(engagementId, identityId, 'SESSION_ESTABLISHED', `auth workflow ${workflow['id']}`);
      }
    }

    // Full workflow reconstruction (§34) + token comparison (§60).
    await this.rebuildWorkflows(engagementId);
    await this.compareTokensAcrossIdentities(engagementId);

    // Endpoint-level signal refresh (§42) for the whole engagement.
    const endpoints = await this.repos.endpoints.listByEngagement(engagementId, { limit: 500 });
    for (const endpoint of endpoints.slice(0, 100)) {
      await this.refreshEndpointSignals(engagementId, endpoint);
    }

    const after = await this.countAll(engagementId);
    summary.createdEndpoints = Math.max(0, after.endpoints - before.endpoints);
    summary.createdParameters = Math.max(0, after.parameters - before.parameters);
    summary.matrixEntries = Math.max(0, after.matrix - before.matrix);
    summary.signalsCreated = Math.max(0, after.signals - before.signals);
    summary.failures = Math.max(0, after.failures - before.failures);
    summary.updatedEndpoints = Math.max(0, summary.processed - summary.createdEndpoints);

    await this.publishDerived('REASONING_INGEST_COMPLETED', engagementId, { ...summary, limit });
    return summary;
  }

  private async countAll(engagementId: string): Promise<{
    endpoints: number;
    parameters: number;
    signals: number;
    matrix: number;
    failures: number;
  }> {
    const [endpoints, parameters, signalCounts, matrix, failures] = await Promise.all([
      this.repos.endpoints.countByEngagement(engagementId),
      this.repos.parameters.countByEngagement(engagementId),
      this.repos.securitySignals.countByEngagement(engagementId),
      this.repos.authzMatrix.countByEngagement(engagementId),
      this.repos.reasoningFailures.countByEngagement(engagementId),
    ]);
    return { endpoints, parameters, signals: signalCounts.total, matrix, failures };
  }

  // -------------------------------------------------------------------------
  // Cross-cutting helpers.
  // -------------------------------------------------------------------------

  async refreshEndpointSignals(engagementId: string, endpoint: EndpointRecord): Promise<void> {
    try {
      const matrix = await this.repos.authzMatrix.listByEndpoint(endpoint.id);
      const parameters = await this.repos.parameters.listByEndpoint(endpoint.id);
      const candidates: SignalCandidate[] = [
        ...signalsFromMatrix(endpoint, matrix),
        ...signalsFromParameters(endpoint, parameters),
      ];
      for (const candidate of candidates) {
        await this.insertSignal(engagementId, candidate);
      }
    } catch (error) {
      await this.recordFailure('signal-refresh', { type: 'SIGNALS', trace: endpoint.id }, error, engagementId);
    }
  }

  private async insertSignal(engagementId: string, candidate: SignalCandidate): Promise<SecuritySignalRecord | null> {
    try {
      const total = await this.repos.securitySignals.countByEngagement(engagementId);
      if (total.total >= this.limits.maxSignals) {
        throw new ReasoningLimitError('maxSignals', total.total);
      }
      const canonicalPath = await this.canonicalPathFor(engagementId, candidate.endpointId);
      const result = await this.repos.securitySignals.insert({
        engagementId,
        signalType: candidate.signalType,
        source: candidate.source,
        endpointId: candidate.endpointId,
        parameterId: candidate.parameterId,
        identityIds: candidate.identityIds,
        objectRef: candidate.objectRef,
        confidence: candidate.confidence,
        summary: bounded(candidate.summary, 2000),
        metadata: withCanonicalPath(candidate.metadata, canonicalPath),
        evidenceIds: candidate.evidenceIds,
        fingerprint: candidate.fingerprint,
      });
      if (result.created) {
        if (candidate.endpointId) {
          await this.repos.endpoints.incrementSignalCount(candidate.endpointId).catch(() => undefined);
        }
        await this.publishDerived('SECURITY_SIGNAL_GENERATED', engagementId, {
          signal_id: result.record.id,
          signal_type: candidate.signalType,
          endpoint_id: candidate.endpointId,
          confidence: candidate.confidence,
        });
      }
      return result.record;
    } catch (error) {
      if (error instanceof ReasoningLimitError) {
        await this.recordFailure('signal-limit', { type: 'LIMIT' }, error, engagementId);
        return null;
      }
      await this.recordFailure('signal-insert', { type: 'SIGNALS' }, error, engagementId);
      return null;
    }
  }

  private async canonicalPathFor(engagementId: string, endpointId: string | null): Promise<string | undefined> {
    if (!endpointId) return undefined;
    const cached = this.endpointPathCache.get(endpointId);
    if (cached) return cached;
    const endpoint = await this.repos.endpoints.findById(endpointId).catch(() => null);
    if (!endpoint) return undefined;
    this.endpointPathCache.set(endpointId, endpoint.canonical_path);
    return endpoint.canonical_path;
  }

  private async recordAuthBoundary(
    engagementId: string,
    identityId: string,
    change: 'LOGIN' | 'LOGOUT' | 'EXPIRATION' | 'SESSION_ESTABLISHED',
    detail: string,
  ): Promise<void> {
    try {
      const result = await this.insertSignal(
        engagementId,
        authStateChangeSignal({
          endpointId: null,
          identityId,
          change,
          detail,
          evidenceIds: [],
        }),
      );
      if (result) {
        await this.publishDerived('WORKFLOW_TRANSITION_RECORDED', engagementId, {
          auth_boundary: true,
          identity_id: identityId,
          change,
        });
      }
    } catch (error) {
      await this.recordFailure('auth-boundary', { type: 'AUTH' }, error, engagementId);
    }
  }

  private async recordFlows(engagementId: string, flows: FlowFact[]): Promise<void> {
    for (const flow of flows) {
      try {
        const result = await this.repos.dataFlows.insert({
          engagementId,
          source: flow.source,
          transformations: flow.transformations,
          sink: flow.sink,
          correlation: flow.correlation,
          confidence: flow.confidence,
          evidenceIds: flow.evidenceIds,
          fingerprint: flow.fingerprint,
        });
        if (result.created) {
          await this.publishDerived('DATA_FLOW_RECORDED', engagementId, {
            data_flow_id: result.record.id,
            correlation: flow.correlation,
          });
        }
      } catch (error) {
        await this.recordFailure('flow-record', { type: 'DATA_FLOW' }, error, engagementId);
      }
    }
  }

  /** Token comparison across identities (§60) — decoded claims only. */
  async compareTokensAcrossIdentities(engagementId: string): Promise<void> {
    try {
      const requests = await this.repos.httpRequests.listByEngagement(engagementId, 200, 0);
      const observations: TokenObservation[] = [];
      for (const request of requests as Array<Record<string, unknown>>) {
        const response = await this.repos.httpResponses
          .findByRequestId((request['id'] as string) ?? '')
          .catch(() => null);
        if (!response) continue;
        const preview = (response['body_preview'] as string | null) ?? null;
        const tokens = scanForJwtTokens(preview);
        if (tokens.length > 0) {
          observations.push({
            identityId: (request['identity_id'] as string | null) ?? null,
            kind: 'RESPONSE_BODY',
            facts: tokens[0]!.facts,
            sourceSummary: 'response body',
          });
        }
      }
      if (observations.length >= 2) {
        const comparison = compareTokens(observations);
        if (comparison) {
          for (const candidate of tokenComparisonSignals(comparison)) {
            await this.insertSignal(engagementId, candidate);
          }
        }
      }
    } catch (error) {
      await this.recordFailure('token-compare', { type: 'TOKENS' }, error, engagementId);
    }
  }

  private async ensureEngagementNodeOnce(engagementId: string): Promise<void> {
    if (this.engagementNodes.has(engagementId)) return;
    const engagement = await this.repos.engagements.findById(engagementId).catch(() => null);
    await this.graph.ensureEngagementNode(engagementId, engagement?.name ?? engagementId);
    this.engagementNodes.add(engagementId);
  }

  private markProcessed(requestId: string): void {
    if (this.processedRequests.size >= PROCESSED_SET_CAP) {
      const oldest = this.processedRequests.keys().next().value;
      if (oldest !== undefined) this.processedRequests.delete(oldest);
    }
    this.processedRequests.set(requestId, true);
  }

  private async publishDerived(type: string, engagementId: string, payload: Record<string, unknown>): Promise<void> {
    try {
      await this.eventBus.publish({
        type: type as never,
        engagement_id: engagementId,
        task_id: null,
        trace_id: generateId('TRC'),
        actor_id: null,
        payload,
        occurred_at: new Date().toISOString(),
        dedup_key: null,
      });
    } catch (error) {
      this.logger?.warn?.('reasoning.publish_failed', {
        type,
        error: error instanceof Error ? error.message : 'unknown',
      });
    }
  }

  private async recordFailure(
    processor: string,
    event: { type?: string | null; trace?: string | null },
    error: unknown,
    engagementId?: string,
  ): Promise<void> {
    const detail = {
      message: error instanceof Error ? error.message : 'unknown failure',
      stack: error instanceof Error ? (error.stack ?? '').slice(0, 500) : undefined,
    };
    this.logger?.warn?.('reasoning.processor_failed', { processor, detail });
    if (!engagementId) return;
    try {
      await this.repos.reasoningFailures.insert({
        engagementId,
        processor,
        eventId: event.trace ?? null,
        eventType: event.type ?? null,
        error: detail,
      });
    } catch {
      // Failure recording must never throw (§112).
    }
  }
}

function withCanonicalPath(metadata: Record<string, unknown>, canonicalPath: string | undefined): Record<string, unknown> {
  if (canonicalPath === undefined) return metadata;
  return { ...metadata, canonical_path: canonicalPath };
}

function extractPathValue(url: string, segmentIndex: number): string | null {
  try {
    const path = new URL(url).pathname;
    const segments = path.split('/').filter((segment) => segment.length > 0);
    return segments[segmentIndex] ?? null;
  } catch {
    return null;
  }
}

function extractPathOfUrl(url: string): string | null {
  try {
    return new URL(url).pathname || '/';
  } catch {
    return null;
  }
}

function resolveFormEndpoint(endpoints: EndpointRecord[], action: string | null): string | null {
  if (!action) return null;
  const path = extractPathOfUrl(action);
  if (!path) return null;
  return endpoints.find((endpoint) => endpoint.path === path || endpoint.canonical_path === path)?.id ?? null;
}

function flowFingerprintOf(key: string): string {
  return createHash('sha256').update(key).digest('hex').slice(0, 40);
}

function payloadString(payload: Record<string, unknown> | undefined, key: string): string | null {
  const value = payload?.[key];
  return typeof value === 'string' && value.length > 0 ? value : null;
}

function bounded(text: string, max: number): string {
  return text.length > max ? `${text.slice(0, max)}…` : text;
}

export { compareResponses, differentialFingerprint, responseRowToComparison };
export type { JwtFacts };
