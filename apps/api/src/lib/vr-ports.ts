/**
 * Part 7 port adapters: ControlledHttpPort + ReasoningVerificationPort.
 *
 * The verification-reporting engine executes through the SAME controlled
 * infrastructure worker tools use (§8: "the verifier executes the plan
 * through the same controlled tool infrastructure"): scope-validated
 * HttpEngine sends, traffic recording with provenance, session-manager
 * identity material, and the Part 4 reasoning engine for the skeptical
 * checklist bridge.
 */
import type { ControlledHttpPort, ReasoningVerificationPort } from '@aegis/vr';
import type { HttpBodyInput } from '@aegis/contracts';
import type { PlainHeader, HttpEngine, HttpTrafficRecorder } from '@aegis/target-http';
import type { SessionManager } from '@aegis/session-manager';
import type { ScopeRules } from '@aegis/security';
import type { Repositories, ScopeRecord } from '@aegis/database';
import type { SecurityReasoningEngine } from '@aegis/reasoning';
import { ScopeViolationError } from '@aegis/shared';
import { AgentPolicy } from '@aegis/agent';
import { mkdirSync, readFileSync, writeFileSync, existsSync } from 'node:fs';
import { join, dirname, normalize } from 'node:path';

export interface VrPortDeps {
  httpEngine: HttpEngine;
  trafficRecorder: HttpTrafficRecorder;
  sessionManager: SessionManager;
  repos: Repositories;
}

function scopeRulesFrom(record: ScopeRecord | null): ScopeRules | null {
  return AgentPolicy.scopeRules(record);
}

function toEngineBody(body: string | null): HttpBodyInput | null {
  if (body === null || body === '') return null;
  return { body_type: 'JSON', raw: body } as unknown as HttpBodyInput;
}

/** Controlled execution shared by send + replay (scope ALWAYS enforced). */
async function execute(
  deps: VrPortDeps,
  input: {
    engagementId: string;
    method: string;
    url: string;
    headers: PlainHeader[];
    body: string | null;
    identityId: string | null;
    source: 'HTTP_WORKER' | 'REPLAY';
    parentRequestId: string | null;
    reason: string | null;
  },
): Promise<{ status: number | null; requestId: string | null; responseId: string | null; evidenceId: string | null; error: string | null }> {
  const record = await deps.repos.scope.findByEngagement(input.engagementId).catch(() => null);
  const scope = scopeRulesFrom(record);
  if (!scope) {
    return {
      status: null,
      requestId: null,
      responseId: null,
      evidenceId: null,
      error: new ScopeViolationError(
        'Engagement has no scope configured; verification operations are refused',
        'SCOPE_NOT_CONFIGURED',
      ).message,
    };
  }
  const applyAuth = async (identityId: string, headers: PlainHeader[]): Promise<PlainHeader[]> => {
    const injection = await deps.sessionManager.resolveForHttp(identityId);
    let updated = [...headers, ...injection.headers];
    if (injection.cookieHeader) {
      updated = [
        ...updated.filter((h) => h.name.toLowerCase() !== 'cookie'),
        { name: 'cookie', value: injection.cookieHeader },
      ];
    }
    return updated;
  };

  try {
    const exchange = await deps.httpEngine.send(
      {
        engagementId: input.engagementId,
        method: input.method as Parameters<typeof deps.httpEngine.send>[0]['method'],
        url: input.url,
        headers: input.headers,
        body: toEngineBody(input.body),
        identityId: input.identityId,
        applyAuth,
      },
      scope,
    );
    const recorded = await deps.trafficRecorder.recordExchange({
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
    return {
      status: exchange.response.status,
      requestId: recorded.request.id,
      responseId: recorded.response?.id ?? null,
      evidenceId: recorded.evidenceId,
      error: null,
    };
  } catch (error) {
    return {
      status: null,
      requestId: null,
      responseId: null,
      evidenceId: null,
      error: error instanceof Error ? error.message : String(error),
    };
  }
}

export function createControlledHttpPort(deps: VrPortDeps): ControlledHttpPort {
  return {
    async send(input) {
      return execute(deps, {
        engagementId: input.engagementId,
        method: input.method,
        url: input.url,
        headers: input.headers ?? [],
        body: input.body ?? null,
        identityId: input.identityId,
        source: 'HTTP_WORKER',
        parentRequestId: null,
        reason: input.reason,
      });
    },
    async replay(input) {
      const record = (await deps.repos.httpRequests.findById(input.requestId)) as
        | Record<string, unknown>
        | null;
      if (!record) {
        return {
          status: null,
          responseId: null,
          evidenceId: null,
          bodyPreview: null,
          error: `request record ${input.requestId} not found`,
        };
      }
      const headers = (record.headers as PlainHeader[] | undefined) ?? [];
      const outcome = await execute(deps, {
        engagementId: input.engagementId,
        method: String(record.method),
        url: String(record.url),
        headers,
        body: null,
        identityId: input.identityId,
        source: 'REPLAY',
        parentRequestId: input.requestId,
        reason: input.reason,
      });
      const response =
        outcome.responseId !== null
          ? ((await deps.repos.httpResponses.findByRequestId(outcome.requestId ?? '').catch(() => null)) as
              | Record<string, unknown>
              | null)
          : null;
      return {
        status: outcome.status,
        responseId: outcome.responseId,
        evidenceId: outcome.evidenceId,
        bodyPreview: String(response?.body_preview ?? ''),
        error: outcome.error,
      };
    },
  };
}

export function createReasoningPort(reasoning: SecurityReasoningEngine): ReasoningVerificationPort {
  return {
    async ingest(engagementId, limit = 200) {
      const summary = await reasoning.ingest(engagementId, limit);
      return { ingested: (summary as { ingested?: number }).ingested ?? 0 };
    },
    async verify(input) {
      const { verification, outcome } = await reasoning.verify(input);
      // Structural conversion between the Part 4 outcome records and the
      // Part 7 verification port types (§2 bridge).
      return {
        verificationId: verification.id,
        outcome: {
          kind: outcome.kind,
          status: outcome.status,
          checklist: outcome.checklist.map((check) => ({
            check: check.check,
            status: String(check.status),
            detail: check.detail,
          })),
          alternatives: outcome.alternatives.map((alternative) => ({
            id: `ALT_${alternative.explanation.slice(0, 24).replace(/\W/g, '_').toUpperCase()}`,
            label: alternative.explanation.slice(0, 120),
            description: alternative.detail,
            refuted: alternative.refuted,
            refutation: alternative.refuted ? alternative.detail : null,
            evidence_ids: [],
          })),
          result: outcome.result,
          evidenceIds: outcome.evidenceIds,
        },
      };
    },
  };
}

/**
 * Keyed artifact store for rendered report exports (§63). The evidence
 * object store is strictly content-addressed (sha256 keys only), so report
 * artifacts use a namespaced keyed store under the same storage root.
 */
export function createReportArtifactStore(rootDir: string): {
  put(key: string, content: Buffer | string): Promise<void>;
  get(key: string): Promise<Buffer | null>;
} {
  const safePath = (key: string): string => {
    const normalized = normalize(key).replace(/\\/g, '/');
    if (normalized.startsWith('..') || normalized.includes('../')) {
      throw new ScopeViolationError('Report artifact keys must not traverse directories', 'ARTIFACT_KEY_INVALID');
    }
    return join(rootDir, normalized);
  };
  return {
    async put(key, content) {
      const path = safePath(key);
      mkdirSync(dirname(path), { recursive: true });
      writeFileSync(path, content, { mode: 0o640 });
    },
    async get(key) {
      const path = safePath(key);
      return existsSync(path) ? readFileSync(path) : null;
    },
  };
}
