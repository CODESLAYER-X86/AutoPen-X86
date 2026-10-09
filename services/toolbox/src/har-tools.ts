/**
 * HAR import tool (spec Part 3 §41, §80).
 *
 * Imported traffic is UNTRUSTED: entries are scope-validated at import
 * (out-of-scope entries are explicitly skipped and reported) and the
 * records are marked IMPORTED. Replay re-validates scope anyway.
 */
import { z } from 'zod';
import type { RiskLevel, ToolCapability } from '@aegis/shared';
import type { ToolDefinition, ToolExecutionContext } from '@aegis/tools';
import type { ScopeRules } from '@aegis/security';
import { parseHarForScope } from '@aegis/target-http';
import { HarImportInputSchema, type HarImportInput } from '@aegis/contracts';
import type { ToolboxDeps } from './part3-tools.js';

export function createHarTools(deps: ToolboxDeps): ToolDefinition[] {
  const harImport: ToolDefinition = {
    name: 'har.import',
    version: '1.0.0',
    description: 'Imports HTTP Archive (HAR) entries as untrusted request records; out-of-scope entries are skipped and reported. Imported requests pass scope validation again at replay time.',
    inputSchema: HarImportInputSchema,
    outputSchema: z.object({
      total: z.number().int(),
      imported: z.number().int(),
      skipped: z.number().int(),
      skipped_reasons: z.array(z.object({ url: z.string(), reason: z.string() })),
      request_ids: z.array(z.string()),
    }),
    riskLevel: 'LOW' as RiskLevel,
    capabilities: ['READ_ONLY'] as ToolCapability[],
    requiresScope: true,
    implemented: true,
    timeoutMs: 30_000,
    execute: async (input: unknown, ctx: ToolExecutionContext) => {
      const parsed = input as HarImportInput;
      const scope: ScopeRules = ctx.scope!;
      const { summary, entries } = parseHarForScope(parsed, scope);

      const requestIds: string[] = [];
      for (const entry of entries) {
        const recorded = await deps.recorder.recordExchange({
          engagementId: ctx.engagementId!,
          taskId: null,
          identityId: null,
          exchange: {
            request: {
              method: entry.method,
              url: entry.url,
              normalizedUrl: {
                scheme: new URL(entry.url).protocol.replace(':', ''),
                host: new URL(entry.url).hostname,
                port: null,
                path: new URL(entry.url).pathname,
                query: new URL(entry.url).search,
                href: entry.url,
                resolvedIps: [],
              },
              headers: entry.headers,
              body: null,
              sentHeaders: entry.headers,
            },
            response: {
              status: entry.responseStatus ?? 0,
              headers: [],
              contentType: entry.responseContentType,
              contentKind: 'UNKNOWN',
              bodyBytes: new TextEncoder().encode(entry.responseBodyText ?? ''),
              parsed: { kind: 'UNKNOWN', parsed: null, textPreview: (entry.responseBodyText ?? '').slice(0, 2048) || null },
              truncated: false,
              contentLengthHeader: null,
              timingMs: 0,
              redirectTo: null,
              finalUrl: entry.url,
            },
            redirects: [],
            totalDurationMs: 0,
          },
          source: 'IMPORTED',
          provenance: {
            source: 'import',
            parentTaskId: null,
            hypothesisId: null,
            testId: null,
            reason: parsed.reason ?? 'HAR import',
          },
          parentRequestId: null,
          browserContextId: null,
          browserPageId: null,
          correlationId: null,
        });
        requestIds.push(recorded.request.id);
      }

      await deps.eventBus.publish({
        type: 'HAR_IMPORTED',
        engagement_id: ctx.engagementId!,
        task_id: null,
        trace_id: `HAR_${Date.now()}`,
        actor_id: null,
        payload: { total: summary.total, imported: summary.imported, skipped: summary.skipped },
        occurred_at: new Date().toISOString(),
        dedup_key: `har-import:${ctx.engagementId}:${Date.now()}`,
      });

      return {
        total: summary.total,
        imported: summary.imported,
        skipped: summary.skipped,
        skipped_reasons: summary.entries
          .filter((e) => !e.imported)
          .slice(0, 100)
          .map((e) => ({ url: e.url, reason: e.reason ?? 'skipped' })),
        request_ids: requestIds,
      };
    },
  };
  return [harImport];
}
