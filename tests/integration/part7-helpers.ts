/**
 * Part 7 integration helpers: composes the verification-reporting engine over
 * the REAL interaction + reasoning stack (Part 3/4 helpers). The
 * ControlledHttpPort is the same scope-validated engine/recorder path the API
 * wires (apps/api/src/lib/vr-ports.ts); the reasoning port bridges the Part 4
 * skeptical checklist. Reproduction therefore replays REAL requests against
 * the REAL lab fixture.
 */
import type { Pool } from 'pg';
import type { Repositories } from '@aegis/database';
import { VerificationReportingEngine } from '@aegis/vr';import { buildReasoningStack, type ReasoningStack } from './part4-helpers.js';
import { loadConfig } from '@aegis/config';
import type { ScopeRecord } from '@aegis/database';
import { AgentPolicy } from '@aegis/agent';

export interface VrStack {
  reasoning: ReasoningStack;
  repos: Repositories;
  pool: Pool;
  engine: VerificationReportingEngine;
  close(): Promise<void>;
}

export async function buildVrStack(options: { pool: Pool }): Promise<VrStack> {
  const reasoning = await buildReasoningStack({ pool: options.pool });
  const config = loadConfig({
    env: {
      NODE_ENV: 'test',
      REPORTING_CONFIDENCE_HIGH_THRESHOLD: '0.75',
      REPORTING_CONFIDENCE_MEDIUM_THRESHOLD: '0.45',
    },
  });

  const engine = new VerificationReportingEngine({
    repos: reasoning.repos,
    eventBus: reasoning.interaction.eventBus,
    config,
    http: {
      send: (input) =>
        sendThrough(
          reasoning,
          input.engagementId,
          input.method,
          input.url,
          input.headers ?? [],
          input.body ?? null,
          input.identityId,
          input.reason,
        ),
      replay: async (input) => {
        const record = (await reasoning.repos.httpRequests.findById(input.requestId)) as
          | Record<string, unknown>
          | null;
        if (!record) {
          return { status: null, responseId: null, evidenceId: null, bodyPreview: null, error: 'record not found' };
        }
        const result = await sendThrough(
          reasoning,
          input.engagementId,
          String(record.method),
          String(record.url),
          (record.headers as Array<{ name: string; value: string }> | undefined) ?? [],
          null,
          input.identityId,
          input.reason,
        );
        const response = result.requestId
          ? ((await reasoning.repos.httpResponses.findByRequestId(result.requestId).catch(() => null)) as
              | Record<string, unknown>
              | null)
          : null;
        return {
          status: result.status,
          responseId: result.responseId,
          evidenceId: result.evidenceId,
          bodyPreview: String(response?.body_preview ?? ''),
          error: result.error,
        };
      },
    },
    reasoning: {
      ingest: async (engagementId, limit = 200) => {
        const summary = await reasoning.reasoning.ingest(engagementId, limit);
        return { ingested: (summary as { ingested?: number }).ingested ?? 0 };
      },
      verify: async (input) => {
        const { verification, outcome } = await reasoning.reasoning.verify(input);
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
    },
    objectStore: memoryArtifactStore(),
  });

  return {
    reasoning,
    repos: reasoning.repos,
    pool: reasoning.pool,
    engine,
    close: async () => {
      await reasoning.close();
    },
  };
}

async function scopeRulesFor(
  repos: Repositories,
  engagementId: string,
): Promise<ReturnType<typeof AgentPolicy.scopeRules>> {
  const record: ScopeRecord | null = await repos.scope.findByEngagement(engagementId).catch(() => null);
  return AgentPolicy.scopeRules(record);
}

async function sendThrough(
  stack: ReasoningStack,
  engagementId: string,
  method: string,
  url: string,
  headers: Array<{ name: string; value: string }>,
  body: string | null,
  identityId: string | null,
  reason: string | null,
): Promise<{ status: number | null; requestId: string | null; responseId: string | null; evidenceId: string | null; error: string | null }> {
  try {
    const scope = await scopeRulesFor(stack.repos, engagementId);
    if (!scope) {
      return { status: null, requestId: null, responseId: null, evidenceId: null, error: 'scope not configured' };
    }
    const exchange = await stack.interaction.engine.send(
      {
        engagementId,
        method: method as 'GET',
        url,
        headers,
        body: body ? ({ body_type: 'JSON', raw: body } as never) : null,
        identityId,
      },
      scope,
    );
    const recorded = await stack.interaction.recorder.recordExchange({
      engagementId,
      taskId: null,
      identityId,
      exchange,
      source: 'REPLAY',
      provenance: {
        source: 'replay',
        parentTaskId: null,
        hypothesisId: null,
        testId: null,
        reason,
      },
      parentRequestId: null,
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

export function memoryArtifactStore(): {
  put(key: string, content: Buffer | string): Promise<void>;
  get(key: string): Promise<Buffer | null>;
} {
  const store = new Map<string, Buffer>();
  return {
    async put(key, content) {
      store.set(key, typeof content === 'string' ? Buffer.from(content, 'utf8') : content);
    },
    async get(key) {
      return store.get(key) ?? null;
    },
  };
}
