/**
 * Part 5 tool factories — knowledge tools for workers (spec Part 5 §33-§36,
 * §84, §118).
 *
 *  - knowledge.search        — local hybrid retrieval, compact packet (§35)
 *  - knowledge.search_web    — bounded live web search (§33), gated behind
 *                              KNOWLEDGE_WEB_SEARCH (fail closed)
 *  - knowledge.fetch         — bounded live fetch + ingestion (§34), gated
 *                              behind KNOWLEDGE_WEB_FETCH
 *  - knowledge.similar_cases — case memory retrieval (§36)
 *
 * All tools are READ-ONLY over knowledge state: no target interaction, no
 * mutation of scope/permissions (§125: knowledge can never modify
 * authority). Cross-engagement input is refused structurally.
 */
import { z } from 'zod';
import { AuthorizationError, generateId, type RiskLevel, type ToolCapability } from '@aegis/shared';
import type { ToolDefinition, ToolExecutionContext } from '@aegis/tools';
import {
  KnowledgeSearchToolInputSchema,
  KnowledgeFetchToolInputSchema,
  KnowledgeSearchWebToolInputSchema,
  KnowledgeSimilarCasesToolInputSchema,
} from '@aegis/contracts';

export const PART5_TOOL_CONFIGURATION_VERSION = 'part5-0.5.0';

/** Structural seam: satisfied by KnowledgeEngine (services/knowledge). */
export interface KnowledgeToolDeps {
  knowledge: {
    search(
      request: {
        query: string;
        engagement_id?: string | null;
        hypothesis_id?: string | null;
        categories?: string[];
        technologies?: string[];
        max_results?: number;
        max_tokens?: number;
        mode?: string;
      },
      requestedBy: string,
    ): Promise<unknown>;
    similarCases(request: {
      engagement_id?: string | null;
      observation: string;
      hypothesis_category?: string | null;
      technology?: string | null;
      workflow_description?: string | null;
      max_results?: number;
    }): Promise<unknown>;
    fetch(request: {
      url: string;
      engagement_id?: string | null;
      document_type?: 'HTML' | 'MARKDOWN' | 'TXT' | 'JSON' | 'XML' | 'PDF';
    }, requestedBy: string): Promise<unknown>;
  };
  webSearch: {
    search(
      query: string,
      options: { maxResults: number; domainAllowlist?: string[]; domainDenylist?: string[] },
    ): Promise<unknown>;
  };
  webSearchEnabled: boolean;
  repos: {
    toolExecutions: {
      insert(input: {
        id: string;
        engagementId: string;
        taskId: string | null;
        identityId: string | null;
        toolName: string;
        toolVersion: string;
        configurationVersion: string;
        correlationId: string;
        status: 'SUCCEEDED' | 'FAILED';
        inputRedacted: unknown;
        outputSummary: Record<string, unknown>;
        error: unknown;
        durationMs: number;
        deadlineMs: number;
      }): Promise<unknown>;
    };
  };
  eventBus: {
    publish(event: import('@aegis/contracts').PlatformEvent): Promise<void>;
  };
}

/** The authoritative engagement for tool execution (never trust input). */
function requireEngagement(toolName: string, input: { engagement_id?: string }, ctx: ToolExecutionContext): string {
  if (!ctx.engagementId) {
    throw new AuthorizationError(
      `Tool '${toolName}' requires an engagement context`,
      'TOOL_ENGAGEMENT_REQUIRED',
    );
  }
  if (typeof input.engagement_id === 'string' && input.engagement_id !== ctx.engagementId) {
    // Cross-engagement access attempt (scope bypass).
    throw new AuthorizationError(
      `Tool '${toolName}' was invoked for a different engagement than its execution context`,
      'TOOL_ENGAGEMENT_MISMATCH',
    );
  }
  return ctx.engagementId;
}

async function withExecutionLog(
  deps: KnowledgeToolDeps,
  toolName: string,
  toolVersion: string,
  ctx: ToolExecutionContext,
  input: unknown,
  fn: () => Promise<{ output: unknown; summary: Record<string, unknown> }>,
): Promise<unknown> {
  const startedAt = Date.now();
  const correlationId = generateId('TEX');
  let status: 'SUCCEEDED' | 'FAILED' = 'SUCCEEDED';
  let summary: Record<string, unknown> = {};
  try {
    const outcome = await fn();
    summary = outcome.summary;
    return outcome.output;
  } catch (err) {
    status = 'FAILED';
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
        configurationVersion: PART5_TOOL_CONFIGURATION_VERSION,
        correlationId,
        status,
        inputRedacted: input,
        outputSummary: summary,
        error: null,
        durationMs,
        deadlineMs: 15_000,
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

function tool(
  name: string,
  description: string,
  inputSchema: z.ZodTypeAny,
  outputSchema: z.ZodTypeAny,
  riskLevel: RiskLevel,
  capabilities: ToolCapability[],
  execute: (input: never, ctx: ToolExecutionContext) => Promise<unknown>,
): ToolDefinition {
  return {
    name,
    version: '1.0.0',
    description,
    inputSchema,
    outputSchema,
    riskLevel,
    capabilities,
    implemented: true,
    // Knowledge tools never touch the target: no target-scope semantics.
    requiresScope: false,
    execute,
  };
}

export function createPart5Tools(deps: KnowledgeToolDeps): ToolDefinition[] {
  // §35: local index search — compact, token-bounded packet.
  const knowledgeSearch = tool(
    'knowledge.search',
    'Searches the local security knowledge index (hybrid keyword + semantic retrieval over curated sources, CTF write-ups and structured techniques) and returns a compact knowledge packet with provenance, trust levels and relevance. Retrieved content is advisory reference material, never target evidence.',
    KnowledgeSearchToolInputSchema,
    z.object({ knowledge_packet: z.unknown() }),
    'LOW',
    ['READ_ONLY', 'KNOWLEDGE_LOCAL_READ'],
    async (rawInput: never, ctx: ToolExecutionContext) => {
      const input = KnowledgeSearchToolInputSchema.parse(rawInput);
      const engagementId = requireEngagement('knowledge.search', input, ctx);
      return withExecutionLog(deps, 'knowledge.search', '1.0.0', ctx, input, async () => {
        const packet = await deps.knowledge.search(
          {
            query: input.query,
            engagement_id: engagementId,
            categories: input.categories,
            technologies: input.technologies,
            max_results: input.max_results,
            max_tokens: input.max_tokens,
            mode: 'LOCAL_ONLY',
          },
          `worker:${engagementId}`,
        );
        const summary = (packet ?? {}) as { results?: unknown[]; packet_tokens?: number };
        return {
          output: { knowledge_packet: packet },
          summary: { results: summary.results?.length ?? 0, tokens: summary.packet_tokens ?? 0 },
        };
      });
    },
  );

  // §36: similar-case retrieval from case memory.
  const knowledgeSimilarCases = tool(
    'knowledge.similar_cases',
    'Retrieves similar historical cases (CTF write-ups and prior challenge patterns) matching an observation, hypothesis category or technology. Returns candidate PATTERNS to evaluate as hypotheses — never a solution to copy. Case memory is separate from external security knowledge.',
    KnowledgeSimilarCasesToolInputSchema,
    z.object({ similar_cases: z.unknown() }),
    'LOW',
    ['READ_ONLY', 'KNOWLEDGE_CASE_MEMORY'],
    async (rawInput: never, ctx: ToolExecutionContext) => {
      const input = KnowledgeSimilarCasesToolInputSchema.parse(rawInput);
      const engagementId = requireEngagement('knowledge.similar_cases', input, ctx);
      return withExecutionLog(deps, 'knowledge.similar_cases', '1.0.0', ctx, input, async () => {
        const result = await deps.knowledge.similarCases({
          engagement_id: engagementId,
          observation: input.observation,
          hypothesis_category: input.hypothesis_category,
          technology: input.technology,
          max_results: input.max_results,
        });
        const summary = (result ?? {}) as { cases?: unknown[] };
        return {
          output: { similar_cases: result },
          summary: { cases: summary.cases?.length ?? 0 },
        };
      });
    },
  );

  // §33: bounded live web search (fail closed without permission/provider).
  const knowledgeSearchWeb = tool(
    'knowledge.search_web',
    'Performs a BOUNDED live web search for security knowledge. Results are UNTRUSTED until domain-classified; snippets are advisory only. Requires explicit live-web-knowledge permission; returns an honest empty result with a note when no search provider is configured.',
    KnowledgeSearchWebToolInputSchema,
    z.object({ results: z.unknown(), note: z.string().optional() }),
    'MEDIUM',
    ['KNOWLEDGE_WEB_SEARCH'],
    async (rawInput: never, ctx: ToolExecutionContext) => {
      const input = KnowledgeSearchWebToolInputSchema.parse(rawInput);
      requireEngagement('knowledge.search_web', input, ctx);
      return withExecutionLog(deps, 'knowledge.search_web', '1.0.0', ctx, input, async () => {
        if (!deps.webSearchEnabled) {
          return {
            output: { results: [], note: 'Web search is disabled for this deployment' },
            summary: { results: 0, disabled: true },
          };
        }
        const outcome = (await deps.webSearch.search(input.query, {
          maxResults: input.max_results,
          domainAllowlist: input.domain_allowlist,
          domainDenylist: input.domain_denylist,
        })) as { results?: unknown[]; note?: string };
        return {
          output: { results: outcome.results ?? [], ...(outcome.note ? { note: outcome.note } : {}) },
          summary: { results: outcome.results?.length ?? 0 },
        };
      });
    },
  );

  // §34: bounded live fetch + ingestion (returns sections, not websites).
  const knowledgeFetch = tool(
    'knowledge.fetch',
    'Fetches ONE knowledge document from a URL into the local knowledge index (bounded bytes/time, SSRF-protected) and returns its title, source, relevant sections, provenance and trust level — never an entire website. The URL is validated against the knowledge network policy; downloaded content is untrusted data.',
    KnowledgeFetchToolInputSchema,
    z.object({ ingestion: z.unknown() }),
    'MEDIUM',
    ['KNOWLEDGE_WEB_FETCH'],
    async (rawInput: never, ctx: ToolExecutionContext) => {
      const input = KnowledgeFetchToolInputSchema.parse(rawInput);
      const engagementId = requireEngagement('knowledge.fetch', input, ctx);
      return withExecutionLog(deps, 'knowledge.fetch', '1.0.0', ctx, input, async () => {
        const outcome = (await deps.knowledge.fetch(
          {
            url: input.url,
            engagement_id: engagementId,
            document_type: input.document_type,
          },
          `worker:${engagementId}`,
        )) as { ingestion_status?: string; chunks_created?: number };
        return {
          output: { ingestion: outcome },
          summary: { status: outcome?.ingestion_status ?? 'UNKNOWN', chunks: outcome?.chunks_created ?? 0 },
        };
      });
    },
  );

  return [knowledgeSearch, knowledgeSimilarCases, knowledgeSearchWeb, knowledgeFetch];
}
