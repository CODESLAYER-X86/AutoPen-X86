/**
 * Part 3 tool factories — the real interaction-layer tools (spec §43-§47,
 * §15-§22, §7-§9, §36-§38, §65, §80).
 *
 * Each tool is a deterministic, zod-schema'd wrapper around the HTTP
 * engine / browser service / session manager. The ToolGateway pipeline
 * (validate -> policy -> scope -> resource -> execute -> normalize ->
 * persist) remains the ONLY execution path; these factories only supply
 * the `execute` step plus honest metadata (§43).
 *
 * Every execution is logged into tool_executions with tool version +
 * configuration version for reproducibility (§78), with REDACTED input.
 */
import { z } from 'zod';
import { AuthorizationError, NotFoundError, generateId, isPlatformError, type RiskLevel, type ToolCapability } from '@aegis/shared';
import type { ToolDefinition, ToolExecutionContext } from '@aegis/tools';
import type { HttpEngine, HttpTrafficRecorder, PlainHeader } from '@aegis/target-http';
import { applyMutations, type MutableRequest } from '@aegis/target-http';
import type { SessionManager } from '@aegis/session-manager';
import type { BrowserService } from '@aegis/browser';
import type { Repositories } from '@aegis/database';
import type { EvidenceService } from '@aegis/evidence';
import type { ObjectStore } from '@aegis/evidence';
import type { HttpBodyInput, HttpRequestInput, HttpReplayInput, HttpMutateInput, BrowserActionRequest, ArtifactReadInput, ArtifactExtractInput, ArtifactSearchInput, WsObservationInput } from '@aegis/contracts';
import { HttpRequestInputSchema, HttpReplayInputSchema, HttpMutateInputSchema, BrowserActionRequestSchema, ArtifactReadInputSchema, ArtifactExtractInputSchema, ArtifactSearchInputSchema, WsObservationInputSchema } from '@aegis/contracts';

export const TOOL_CONFIGURATION_VERSION = 'part3-0.3.0';

export interface ToolboxDeps {
  engine: HttpEngine;
  recorder: HttpTrafficRecorder;
  browser: BrowserService;
  sessionManager: SessionManager;
  evidence: EvidenceService;
  objectStore: ObjectStore;
  repos: Repositories;
  eventBus: {
    publish(event: import('@aegis/contracts').PlatformEvent): Promise<void>;
  };
}

interface ExecutionOutcome {
  output: unknown;
  summary: Record<string, unknown>;
}

/**
 * Wrap a tool execute() with execution logging + redaction (§78, §66).
 */
async function withExecutionLog(
  deps: ToolboxDeps,
  toolName: string,
  toolVersion: string,
  ctx: ToolExecutionContext,
  input: unknown,
  fn: () => Promise<ExecutionOutcome>,
): Promise<unknown> {
  const startedAt = Date.now();
  const correlationId = ctx.requestId ?? generateId('TEX');
  let status: 'SUCCEEDED' | 'FAILED' = 'SUCCEEDED';
  let output: unknown = null;
  let error: unknown = null;
  let summary: Record<string, unknown> = {};
  try {
    const outcome = await fn();
    output = outcome.output;
    summary = outcome.summary;
    return output;
  } catch (err) {
    status = 'FAILED';
    error = isPlatformError(err)
      ? { code: err.code, message: err.message, category: err.category }
      : { code: 'TOOL_EXECUTION_FAILED', message: err instanceof Error ? err.message : 'unknown failure' };
    throw err;
  } finally {
    const durationMs = Date.now() - startedAt;
    try {
      await deps.repos.toolExecutions.insert({
        id: generateId('TEX'),
        engagementId: ctx.engagementId ?? 'unknown',
        taskId: null,
        identityId: ctx.identityId ?? null,
        toolName,
        toolVersion,
        configurationVersion: TOOL_CONFIGURATION_VERSION,
        correlationId,
        status,
        inputRedacted: redactToolInput(input),
        outputSummary: summary,
        error,
        durationMs,
        deadlineMs: 30_000,
      });
      await deps.eventBus.publish({
        type: 'TOOL_EXECUTION_RECORDED',
        engagement_id: ctx.engagementId ?? 'unknown',
        task_id: null,
        trace_id: generateId('TRC'),
        actor_id: null,
        payload: { tool: toolName, version: toolVersion, status, duration_ms: durationMs, correlation_id: correlationId },
        occurred_at: new Date().toISOString(),
        dedup_key: `tool-exec:${correlationId}`,
      });
    } catch {
      // Logging must never break the tool pipeline.
    }
  }
}

function redactToolInput(input: unknown): unknown {
  if (input === null || typeof input !== 'object') return input;
  const clone: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(input as Record<string, unknown>)) {
    clone[key] = /password|token|secret|cookie|authorization|content_b64/i.test(key) ? '«redacted»' : value;
  }
  return clone;
}

// ---------------------------------------------------------------------------
// HTTP tools (§15-§22)
// ---------------------------------------------------------------------------

function bodyFromRecord(record: Record<string, unknown>): HttpBodyInput | null {
  const body = record.body_parsed as unknown;
  const kind = record.body_type as string | null;
  if (!kind || kind === 'EMPTY') return null;
  switch (kind) {
    case 'JSON':
      return { body_type: 'JSON', data: body ?? null };
    case 'FORM_URLENCODED':
      return { body_type: 'FORM_URLENCODED', fields: Array.isArray(body) ? (body as Array<{ name: string; value: string }>) : [] };
    case 'MULTIPART':
      return {
        body_type: 'MULTIPART',
        fields: Array.isArray(body) ? (body as Array<{ name: string; value: string }>) : [],
        files: [],
      };
    case 'TEXT':
      return { body_type: 'TEXT', text: typeof body === 'object' && body !== null ? String((body as { preview?: string }).preview ?? '') : String(body ?? '') };
    case 'XML':
      return { body_type: 'XML', text: typeof body === 'string' ? body : String(body ?? '') };
    case 'BINARY':
      // Binary bodies live in the artifact store; replay via reference is
      // handled by artifact.read + http.request composition.
      return null;
    default:
      return null;
  }
}

function headersFromRecord(record: Record<string, unknown>): PlainHeader[] {
  return (record.headers as PlainHeader[] | undefined) ?? [];
}

/** Common execution: send + record + expiration detection. */
async function executeAndRecord(
  deps: ToolboxDeps,
  ctx: ToolExecutionContext,
  input: {
    engagementId: string;
    method: string;
    url: string;
    headers: PlainHeader[];
    body: HttpBodyInput | null;
    identityId: string | null;
    source: 'HTTP_WORKER' | 'REPLAY';
    parentRequestId: string | null;
    reason: string | null;
  },
): Promise<ExecutionOutcome> {
  const scope = ctx.scope!;
  const applyAuth = async (identityId: string, headers: PlainHeader[]): Promise<PlainHeader[]> => {
    const injection = await deps.sessionManager.resolveForHttp(identityId);
    let updated = [...headers, ...injection.headers];
    if (injection.cookieHeader) {
      updated = [...updated.filter((h) => h.name.toLowerCase() !== 'cookie'), { name: 'cookie', value: injection.cookieHeader }];
    }
    return updated;
  };

  const exchange = await deps.engine.send(
    {
      engagementId: input.engagementId,
      method: input.method as Parameters<typeof deps.engine.send>[0]['method'],
      url: input.url,
      headers: input.headers,
      body: input.body,
      identityId: input.identityId,
      applyAuth,
    },
    scope,
  );

  const recorded = await deps.recorder.recordExchange({
    engagementId: input.engagementId,
    taskId: null,
    identityId: input.identityId,
    exchange,
    source: input.source,
    provenance: {
      source: input.source === 'REPLAY' ? 'replay' : 'worker_task',
      parentTaskId: null,
      hypothesisId: null,
      testId: null,
      reason: input.reason,
    },
    parentRequestId: input.parentRequestId,
    browserContextId: null,
    browserPageId: null,
    correlationId: null,
  });

  // Session expiration detection (§27) — observation, never auto re-auth.
  if (input.identityId) {
    const setCookies = (exchange.response.headers as PlainHeader[])
      .filter((h) => h.name.toLowerCase() === 'set-cookie')
      .map((h) => h.value);
    const detection = deps.sessionManager.detectExpiration({
      status: exchange.response.status,
      location: exchange.response.redirectTo,
      setCookies,
      finalUrl: exchange.response.finalUrl,
    });
    if (detection.signal) {
      const identity = await deps.repos.identities.findById(input.identityId);
      const session = await deps.repos.sessions.findActiveByIdentity(input.identityId);
      if (session) {
        await deps.sessionManager.expireSession(
          session.id,
          detection.signal,
          detection.detail,
          identity?.engagement_id ?? input.engagementId,
        );
      }
    }
  }

  const output = {
    request_id: recorded.request.id,
    response_id: recorded.response?.id ?? null,
    status: exchange.response.status,
    method: exchange.request.method,
    url: recorded.request.normalized_url,
    content_kind: exchange.response.contentKind,
    content_length: exchange.response.bodyBytes.byteLength,
    truncated: exchange.response.truncated,
    timing_ms: exchange.response.timingMs,
    redirects: exchange.redirects.map((r) => ({ status: r.status, url: r.url })),
    body_preview: exchange.response.parsed.textPreview?.slice(0, 2048) ?? null,
    evidence_id: recorded.evidenceId,
    artifact_refs: [recorded.response?.body_artifact_ref, recorded.request.body?.artifact_ref].filter(
      (ref): ref is string => typeof ref === 'string',
    ),
  };
  return {
    output,
    summary: { status: exchange.response.status, method: exchange.request.method, url: recorded.request.normalized_url, request_id: recorded.request.id },
  };
}

async function requireRequestRecord(
  deps: ToolboxDeps,
  ctx: ToolExecutionContext,
  requestId: string,
): Promise<Record<string, unknown>> {
  const record = await deps.repos.httpRequests.findById(requestId);
  if (!record) {
    throw new NotFoundError(`Request '${requestId}'`, 'HTTP_REQUEST_NOT_FOUND');
  }
  if (ctx.engagementId && record.engagement_id !== ctx.engagementId) {
    throw new AuthorizationError('Request belongs to a different engagement', 'REQUEST_ENGAGEMENT_MISMATCH');
  }
  return record;
}

export function createHttpTools(deps: ToolboxDeps): ToolDefinition[] {
  const httpRequest: ToolDefinition = {
    name: 'http.request',
    version: '1.0.0',
    description: 'Sends a single HTTP request to an in-scope URL with structured body support, records the exchange as evidence and returns a sanitized summary.',
    inputSchema: HttpRequestInputSchema,
    outputSchema: z.object({
      request_id: z.string(),
      response_id: z.string().nullable(),
      status: z.number().int(),
      method: z.string(),
      url: z.string(),
      content_kind: z.string(),
      content_length: z.number().int().min(0),
      truncated: z.boolean(),
      timing_ms: z.number().int().min(0),
      redirects: z.array(z.object({ status: z.number().int(), url: z.string() })),
      body_preview: z.string().nullable(),
      evidence_id: z.string(),
      artifact_refs: z.array(z.string()),
    }),
    riskLevel: 'MEDIUM' as RiskLevel,
    capabilities: ['NETWORK', 'READ_ONLY'] as ToolCapability[],
    requiresScope: true,
    urlFields: ['url'],
    implemented: true,
    timeoutMs: 30_000,
    execute: async (input: unknown, ctx: ToolExecutionContext) =>
      withExecutionLog(deps, 'http.request', '1.0.0', ctx, input, async () => {
        const parsed = input as HttpRequestInput;
        return executeAndRecord(deps, ctx, {
          engagementId: ctx.engagementId!,
          method: parsed.method,
          url: parsed.url,
          headers: parsed.headers ?? [],
          body: parsed.body ?? null,
          identityId: parsed.identity_id ?? ctx.identityId ?? null,
          source: 'HTTP_WORKER',
          parentRequestId: null,
          reason: parsed.reason ?? null,
        });
      }),
  };

  const httpReplay: ToolDefinition = {
    name: 'http.replay',
    version: '1.0.0',
    description: 'Replays a previously recorded HTTP request by reference; the session manager injects fresh authentication material for the chosen identity.',
    inputSchema: HttpReplayInputSchema,
    outputSchema: httpRequest.outputSchema,
    riskLevel: 'MEDIUM' as RiskLevel,
    // NOTE: replay is not inherently authenticated — the session manager
    // injects identity material only when an identity is chosen (§19).
    capabilities: ['NETWORK', 'READ_ONLY'] as ToolCapability[],
    requiresScope: true,
    requiresIdentity: false,
    implemented: true,
    timeoutMs: 30_000,
    execute: async (input: unknown, ctx: ToolExecutionContext) =>
      withExecutionLog(deps, 'http.replay', '1.0.0', ctx, input, async () => {
        const parsed = input as HttpReplayInput;
        const record = await requireRequestRecord(deps, ctx, parsed.request_id);
        return executeAndRecord(deps, ctx, {
          engagementId: record.engagement_id as string,
          method: record.method as string,
          url: record.url as string,
          headers: headersFromRecord(record),
          body: bodyFromRecord(record),
          identityId: parsed.identity_id ?? ctx.identityId ?? null,
          source: 'REPLAY',
          parentRequestId: parsed.request_id,
          reason: parsed.reason ?? null,
        });
      }),
  };

  const httpMutate: ToolDefinition = {
    name: 'http.mutate',
    version: '1.0.0',
    description: 'Applies structured mutations (query/header/cookie/JSON-path/form/method/path) to a recorded request, then optionally executes the new request. The original record stays immutable.',
    inputSchema: HttpMutateInputSchema,
    outputSchema: z.object({
      applied: z.array(z.object({ location: z.string(), name: z.string().optional(), operation: z.string() })),
      mutated: z.object({
        method: z.string(),
        url: z.string(),
        header_count: z.number().int(),
        body_type: z.string().nullable(),
      }),
      request_id: z.string().nullable(),
      response_id: z.string().nullable(),
      status: z.number().int().nullable(),
      evidence_id: z.string().nullable(),
      truncated: z.boolean(),
      content_kind: z.string().nullable(),
      timing_ms: z.number().int().nullable(),
    }),
    riskLevel: 'MEDIUM' as RiskLevel,
    capabilities: ['NETWORK', 'MUTATION'] as ToolCapability[],
    requiresScope: true,
    implemented: true,
    timeoutMs: 30_000,
    execute: async (input: unknown, ctx: ToolExecutionContext) =>
      withExecutionLog(deps, 'http.mutate', '1.0.0', ctx, input, async () => {
        const parsed = input as HttpMutateInput;
        const base = await requireRequestRecord(deps, ctx, parsed.base_request_id);

        const mutable: MutableRequest = {
          method: base.method as string,
          url: base.url as string,
          headers: headersFromRecord(base),
          body: bodyFromRecord(base),
        };
        const result = applyMutations(mutable, parsed.mutations);

        if (!parsed.execute) {
          return {
            output: {
              applied: result.applied,
              mutated: {
                method: result.request.method,
                url: result.request.url,
                header_count: result.request.headers.length,
                body_type: result.request.body?.body_type ?? null,
              },
              request_id: null,
              response_id: null,
              status: null,
              evidence_id: null,
              truncated: false,
              content_kind: null,
              timing_ms: null,
            },
            summary: { mutations: result.applied.length, executed: false },
          };
        }

        const outcome = await executeAndRecord(deps, ctx, {
          engagementId: base.engagement_id as string,
          method: result.request.method,
          url: result.request.url,
          headers: result.request.headers,
          body: result.request.body,
          identityId: parsed.identity_id ?? ctx.identityId ?? null,
          source: 'REPLAY',
          parentRequestId: parsed.base_request_id,
          reason: parsed.reason ?? 'controlled mutation',
        });
        const executed = outcome.output as Record<string, unknown>;
        return {
          output: {
            applied: result.applied,
            mutated: {
              method: result.request.method,
              url: result.request.url,
              header_count: result.request.headers.length,
              body_type: result.request.body?.body_type ?? null,
            },
            request_id: executed.request_id,
            response_id: executed.response_id,
            status: executed.status,
            evidence_id: executed.evidence_id,
            truncated: executed.truncated,
            content_kind: executed.content_kind,
            timing_ms: executed.timing_ms,
          },
          summary: { mutations: result.applied.length, executed: true, status: executed.status },
        };
      }),
  };

  return [httpRequest, httpReplay, httpMutate];
}

// ---------------------------------------------------------------------------
// Browser tools (§7-§9, §60)
// ---------------------------------------------------------------------------

const BrowserToolOutputSchema = z.object({
  action: z.string(),
  ok: z.boolean(),
  page_id: z.string().nullable(),
  url: z.string().nullable(),
  details: z.record(z.unknown()).default({}),
  evidence_ids: z.array(z.string()),
  http_records: z.array(z.string()),
  error: z.object({ code: z.string(), message: z.string() }).nullable(),
});

function browserTool(
  deps: ToolboxDeps,
  action: BrowserActionRequest['action'],
  version: string,
  description: string,
  options: {
    riskLevel: RiskLevel;
    capabilities: ToolCapability[];
    urlField?: 'url';
  },
): ToolDefinition {
  return {
    name: `browser.${action}`,
    version,
    description,
    inputSchema: BrowserActionRequestSchema,
    outputSchema: BrowserToolOutputSchema,
    riskLevel: options.riskLevel,
    capabilities: options.capabilities,
    requiresScope: true,
    ...(options.urlField ? { urlFields: [options.urlField] } : {}),
    implemented: true,
    timeoutMs: 45_000,
    execute: async (input: unknown, ctx: ToolExecutionContext) =>
      withExecutionLog(deps, `browser.${action}`, version, ctx, input, async () => {
        const parsed = input as BrowserActionRequest;
        const request: BrowserActionRequest = { ...parsed, action };
        const result = await deps.browser.performAction(ctx.engagementId!, request, ctx.scope!);
        return {
          output: result,
          summary: { action, ok: result.ok, url: result.url, evidence: result.evidence_ids.length },
        };
      }),
  };
}

export function createBrowserTools(deps: ToolboxDeps): ToolDefinition[] {
  const tools: ToolDefinition[] = [
    browserTool(deps, 'navigate', '1.0.0', 'Navigates the controlled, identity-isolated browser to an in-scope URL. Network activity is captured and promoted to HTTP records.', { riskLevel: 'LOW', capabilities: ['BROWSER', 'NETWORK', 'READ_ONLY'], urlField: 'url' }),
    browserTool(deps, 'go_back', '1.0.0', 'Navigates back in the browser history of the current page.', { riskLevel: 'LOW', capabilities: ['BROWSER', 'READ_ONLY'] }),
    browserTool(deps, 'go_forward', '1.0.0', 'Navigates forward in the browser history of the current page.', { riskLevel: 'LOW', capabilities: ['BROWSER', 'READ_ONLY'] }),
    browserTool(deps, 'reload', '1.0.0', 'Reloads the current page.', { riskLevel: 'LOW', capabilities: ['BROWSER', 'READ_ONLY'] }),
    browserTool(deps, 'click', '1.0.0', 'Clicks an element described by a semantic selector (role/text/label/placeholder/test_id or css/xpath).', { riskLevel: 'MEDIUM', capabilities: ['BROWSER', 'MUTATION'] }),
    browserTool(deps, 'fill', '1.0.0', 'Fills an input element described by a semantic selector with a value.', { riskLevel: 'MEDIUM', capabilities: ['BROWSER', 'MUTATION'] }),
    browserTool(deps, 'select_option', '1.0.0', 'Selects option(s) in a <select> element.', { riskLevel: 'MEDIUM', capabilities: ['BROWSER', 'MUTATION'] }),
    browserTool(deps, 'check', '1.0.0', 'Checks a checkbox or radio element.', { riskLevel: 'MEDIUM', capabilities: ['BROWSER', 'MUTATION'] }),
    browserTool(deps, 'uncheck', '1.0.0', 'Unchecks a checkbox element.', { riskLevel: 'MEDIUM', capabilities: ['BROWSER', 'MUTATION'] }),
    browserTool(deps, 'press', '1.0.0', 'Presses a keyboard key on the focused element (e.g. Enter, Escape).', { riskLevel: 'MEDIUM', capabilities: ['BROWSER', 'MUTATION'] }),
    browserTool(deps, 'hover', '1.0.0', 'Hovers over an element described by a semantic selector.', { riskLevel: 'LOW', capabilities: ['BROWSER', 'READ_ONLY'] }),
    browserTool(deps, 'wait_for_url', '1.0.0', 'Waits until the page URL matches a pattern (glob or regex).', { riskLevel: 'LOW', capabilities: ['BROWSER', 'READ_ONLY'] }),
    browserTool(deps, 'wait_for_selector', '1.0.0', 'Waits until an element matching a semantic selector is visible.', { riskLevel: 'LOW', capabilities: ['BROWSER', 'READ_ONLY'] }),
    browserTool(deps, 'screenshot', '1.0.0', 'Captures a PNG screenshot of the current page and stores it as SCREENSHOT evidence.', { riskLevel: 'LOW', capabilities: ['BROWSER', 'READ_ONLY'] }),
    browserTool(deps, 'snapshot', '1.0.0', 'Captures a normalized DOM snapshot (forms, inputs, links, buttons, ARIA, scripts) and stores it as DERIVED evidence.', { riskLevel: 'LOW', capabilities: ['BROWSER', 'READ_ONLY'] }),
  ];

  // browser.submit — explicit form submission (click on submit control).
  const submit: ToolDefinition = {
    name: 'browser.submit',
    version: '1.0.0',
    description: 'Submits a form by clicking its submit control; the resulting navigation and network exchange are captured.',
    inputSchema: BrowserActionRequestSchema,
    outputSchema: BrowserToolOutputSchema,
    riskLevel: 'HIGH' as RiskLevel,
    capabilities: ['BROWSER', 'MUTATION'] as ToolCapability[],
    requiresScope: true,
    implemented: true,
    timeoutMs: 45_000,
    execute: async (input: unknown, ctx: ToolExecutionContext) =>
      withExecutionLog(deps, 'browser.submit', '1.0.0', ctx, input, async () => {
        const parsed = input as BrowserActionRequest;
        const result = await deps.browser.performAction(ctx.engagementId!, { ...parsed, action: 'click' }, ctx.scope!);
        return {
          output: { ...result, action: 'submit' },
          summary: { action: 'submit', ok: result.ok, url: result.url },
        };
      }),
  };
  tools.push(submit);

  // browser.capture_state — cookies + storage (values never returned).
  const captureState: ToolDefinition = {
    name: 'browser.capture_state',
    version: '1.0.0',
    description: 'Captures cookies and browser storage for the context into the secret store; returns counts and opaque references only.',
    inputSchema: z.object({
      context_id: z.string(),
      reason: z.string().max(2000).optional(),
    }),
    outputSchema: z.object({
      context_id: z.string(),
      cookies: z.object({ count: z.number().int(), sensitive: z.number().int() }),
      storage: z.object({ origins: z.number().int(), entries: z.number().int(), sensitive: z.number().int() }),
    }),
    riskLevel: 'LOW' as RiskLevel,
    capabilities: ['BROWSER', 'READ_ONLY'] as ToolCapability[],
    requiresScope: true,
    implemented: true,
    timeoutMs: 20_000,
    execute: async (input: unknown, ctx: ToolExecutionContext) =>
      withExecutionLog(deps, 'browser.capture_state', '1.0.0', ctx, input, async () => {
        const parsed = input as { context_id: string };
        const state = await deps.browser.captureContextState(ctx.engagementId!, parsed.context_id);
        return {
          output: { context_id: parsed.context_id, cookies: state.cookies, storage: state.storage },
          summary: { cookies: state.cookies.count, storage_entries: state.storage.entries },
        };
      }),
  };
  tools.push(captureState);

  // browser.diff_snapshot — DOM change detection (§33).
  const diffSnapshot: ToolDefinition = {
    name: 'browser.diff_snapshot',
    version: '1.0.0',
    description: 'Diffs the current DOM against a stored snapshot and reports added/removed/changed elements (DOM change detection).',
    inputSchema: z.object({
      context_id: z.string(),
      snapshot_id: z.string(),
      reason: z.string().max(2000).optional(),
    }),
    outputSchema: z.object({
      added: z.array(z.string()),
      removed: z.array(z.string()),
      changed: z.array(z.object({ selector: z.string(), before: z.string().nullable(), after: z.string().nullable() })),
    }),
    riskLevel: 'LOW' as RiskLevel,
    capabilities: ['BROWSER', 'READ_ONLY'] as ToolCapability[],
    requiresScope: true,
    implemented: true,
    timeoutMs: 20_000,
    execute: async (input: unknown, ctx: ToolExecutionContext) =>
      withExecutionLog(deps, 'browser.diff_snapshot', '1.0.0', ctx, input, async () => {
        const parsed = input as { context_id: string; snapshot_id: string };
        const diff = await deps.browser.diffAgainstSnapshot(ctx.engagementId!, parsed.context_id, parsed.snapshot_id);
        return {
          output: diff,
          summary: { added: diff.added.length, removed: diff.removed.length, changed: diff.changed.length },
        };
      }),
  };
  tools.push(diffSnapshot);

  return tools;
}

// ---------------------------------------------------------------------------
// WebSocket observation (§36)
// ---------------------------------------------------------------------------

export function createWebsocketTools(deps: ToolboxDeps): ToolDefinition[] {
  const observe: ToolDefinition = {
    name: 'websocket.observe',
    version: '1.0.0',
    description: 'Returns observed WebSocket connections and message metadata (direction, size, previews) for the engagement.',
    inputSchema: WsObservationInputSchema,
    outputSchema: z.object({
      connections: z.array(
        z.object({
          id: z.string(),
          url: z.string(),
          origin: z.string().nullable(),
          closed: z.boolean(),
          messages: z.array(
            z.object({
              direction: z.string(),
              is_binary: z.boolean(),
              bytes: z.number().int(),
              truncated: z.boolean(),
              preview: z.string().nullable(),
            }),
          ),
        }),
      ),
    }),
    riskLevel: 'LOW' as RiskLevel,
    capabilities: ['BROWSER', 'READ_ONLY'] as ToolCapability[],
    requiresScope: true,
    implemented: true,
    timeoutMs: 15_000,
    execute: async (input: unknown, ctx: ToolExecutionContext) =>
      withExecutionLog(deps, 'websocket.observe', '1.0.0', ctx, input, async () => {
        const parsed = input as WsObservationInput;
        const connections = await deps.repos.websockets.listConnections(ctx.engagementId!);
        const filtered = parsed.connection_id
          ? connections.filter((c) => c.id === parsed.connection_id)
          : connections;
        const out = [];
        for (const connection of filtered.slice(0, 50)) {
          const messages = await deps.repos.websockets.listMessages(connection.id as string, 100);
          out.push({
            id: connection.id,
            url: connection.url,
            origin: connection.origin ?? null,
            closed: connection.closed_at !== null && connection.closed_at !== undefined,
            messages: messages.map((m) => ({
              direction: m.direction,
              is_binary: m.is_binary,
              bytes: m.byte_size,
              truncated: m.truncated,
              preview: m.payload_preview ?? null,
            })),
          });
        }
        return { output: { connections: out }, summary: { connections: out.length } };
      }),
  };
  return [observe];
}

// ---------------------------------------------------------------------------
// Artifact retrieval (§65)
// ---------------------------------------------------------------------------

async function resolveArtifact(
  deps: ToolboxDeps,
  ctx: ToolExecutionContext,
  artifactRef: string,
): Promise<{ bytes: Uint8Array; sha256: string; evidenceId: string | null }> {
  const record = await deps.repos.evidence.findById(artifactRef);
  if (!record) {
    throw new NotFoundError(`Artifact '${artifactRef}'`, 'ARTIFACT_NOT_FOUND');
  }
  if (ctx.engagementId && record.engagement_id !== ctx.engagementId) {
    throw new AuthorizationError('Artifact belongs to a different engagement', 'ARTIFACT_ENGAGEMENT_MISMATCH');
  }
  const bytes = await deps.objectStore.get(record.content_reference);
  return { bytes, sha256: record.sha256, evidenceId: record.id };
}

export function createArtifactTools(deps: ToolboxDeps): ToolDefinition[] {
  const read: ToolDefinition = {
    name: 'artifact.read',
    version: '1.0.0',
    description: 'Reads a bounded byte window of a stored artifact (evidence record) — token-efficient retrieval instead of whole-file dumps.',
    inputSchema: ArtifactReadInputSchema,
    outputSchema: z.object({
      sha256: z.string(),
      byte_length: z.number().int(),
      offset: z.number().int(),
      returned: z.number().int(),
      truncated: z.boolean(),
      data_b64: z.string(),
    }),
    riskLevel: 'LOW' as RiskLevel,
    capabilities: ['READ_ONLY'] as ToolCapability[],
    requiresScope: true,
    implemented: true,
    timeoutMs: 15_000,
    execute: async (input: unknown, ctx: ToolExecutionContext) =>
      withExecutionLog(deps, 'artifact.read', '1.0.0', ctx, input, async () => {
        const parsed = input as ArtifactReadInput;
        const { bytes, sha256 } = await resolveArtifact(deps, ctx, parsed.artifact_ref);
        const slice = bytes.slice(parsed.offset, parsed.offset + parsed.limit_bytes);
        return {
          output: {
            sha256,
            byte_length: bytes.byteLength,
            offset: parsed.offset,
            returned: slice.byteLength,
            truncated: parsed.offset + slice.byteLength < bytes.byteLength,
            data_b64: Buffer.from(slice).toString('base64'),
          },
          summary: { bytes: slice.byteLength, total: bytes.byteLength },
        };
      }),
  };

  const extract: ToolDefinition = {
    name: 'artifact.extract',
    version: '1.0.0',
    description: 'Extracts a structured portion of an artifact: JSON path, regex capture, or line range.',
    inputSchema: ArtifactExtractInputSchema,
    outputSchema: z.object({
      format: z.string(),
      value: z.unknown().nullable(),
      matched: z.boolean(),
    }),
    riskLevel: 'LOW' as RiskLevel,
    capabilities: ['READ_ONLY'] as ToolCapability[],
    requiresScope: true,
    implemented: true,
    timeoutMs: 15_000,
    execute: async (input: unknown, ctx: ToolExecutionContext) =>
      withExecutionLog(deps, 'artifact.extract', '1.0.0', ctx, input, async () => {
        const parsed = input as ArtifactExtractInput;
        const { bytes } = await resolveArtifact(deps, ctx, parsed.artifact_ref);
        const text = Buffer.from(bytes.slice(0, parsed.limit_bytes)).toString('utf8');
        if (parsed.format === 'JSON_PATH') {
          let data: unknown = null;
          try {
            data = JSON.parse(text) as unknown;
          } catch {
            return { output: { format: parsed.format, value: null, matched: false }, summary: { matched: false } };
          }
          let cursor: unknown = data;
          let matched = true;
          for (const segment of parsed.selector.split('.').filter((s) => s !== '')) {
            if (cursor === null || typeof cursor !== 'object') {
              matched = false;
              break;
            }
            cursor = (cursor as Record<string, unknown>)[segment];
          }
          return {
            output: { format: parsed.format, value: matched ? cursor ?? null : null, matched: matched && cursor !== undefined },
            summary: { matched: matched && cursor !== undefined },
          };
        }
        if (parsed.format === 'REGEX') {
          const match = new RegExp(parsed.selector).exec(text);
          return {
            output: { format: parsed.format, value: match ? match.slice(0, 10) : null, matched: match !== null },
            summary: { matched: match !== null },
          };
        }
        // LINE_RANGE
        const [fromRaw, toRaw] = parsed.selector.split('-');
        const from = Number.parseInt(fromRaw ?? '1', 10);
        const to = Number.parseInt(toRaw ?? '', 10);
        const lines = text.split('\n');
        const selected = lines.slice(from - 1, Number.isNaN(to) ? undefined : to);
        return {
          output: { format: parsed.format, value: selected, matched: selected.length > 0 },
          summary: { lines: selected.length },
        };
      }),
  };

  const search: ToolDefinition = {
    name: 'artifact.search',
    version: '1.0.0',
    description: 'Searches artifact content for a literal or regex pattern and returns bounded matches with context.',
    inputSchema: ArtifactSearchInputSchema,
    outputSchema: z.object({
      matches: z.array(z.object({ index: z.number().int(), preview: z.string() })),
      total: z.number().int(),
    }),
    riskLevel: 'LOW' as RiskLevel,
    capabilities: ['READ_ONLY'] as ToolCapability[],
    requiresScope: true,
    implemented: true,
    timeoutMs: 15_000,
    execute: async (input: unknown, ctx: ToolExecutionContext) =>
      withExecutionLog(deps, 'artifact.search', '1.0.0', ctx, input, async () => {
        const parsed = input as ArtifactSearchInput;
        const { bytes } = await resolveArtifact(deps, ctx, parsed.artifact_ref);
        const text = Buffer.from(bytes.slice(0, 262_144)).toString('utf8');
        const pattern = parsed.is_regex ? new RegExp(parsed.pattern, 'g') : new RegExp(escapeRegex(parsed.pattern), 'g');
        const matches: Array<{ index: number; preview: string }> = [];
        let total = 0;
        for (const match of text.matchAll(pattern)) {
          total += 1;
          if (matches.length < parsed.max_matches) {
            const index = match.index ?? 0;
            matches.push({
              index,
              preview: text.slice(Math.max(0, index - 40), Math.min(text.length, index + 80)).replace(/\s+/g, ' ').slice(0, 160),
            });
          }
        }
        return { output: { matches, total }, summary: { total } };
      }),
  };

  return [read, extract, search];
}

function escapeRegex(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

export const TOOLBOX_CONFIGURATION_VERSION = TOOL_CONFIGURATION_VERSION;
