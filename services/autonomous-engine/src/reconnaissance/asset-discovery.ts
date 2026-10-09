/**
 * Passive asset discovery (spec Part 6 §10).
 *
 * Deterministic extraction of information already naturally available:
 * links, scripts, forms, API references and WebSocket references from
 * RECORDED responses and DOM snapshots. Every discovery becomes an
 * observation (§10). No model calls — this is engine-side analysis.
 */
import type { Repositories } from '@aegis/database';
import type { PlatformEvent } from '@aegis/contracts';
import type { EventBus } from '@aegis/events';
import { generateId } from '@aegis/shared';

export interface PassiveDiscoveryResult {
  links: string[];
  scripts: string[];
  forms: string[];
  apiReferences: string[];
  websocketReferences: string[];
  observations: number;
}

/** Regexes operate on bounded response previews only (never full bodies). */
const LINK_RE = /href=["']([^"']+)["']/gi;
const SCRIPT_RE = /src=["']([^"']+\.js[^"']*)["']/gi;
const API_REF_RE = /["'](\/(?:api|v\d+|graphql|rest)[^"']*)["']/gi;
const WS_REF_RE = /["'](?:wss?|ws):\/\/[^"']+["']/gi;
const FORM_RE = /<form[^>]*>/gi;

export class AssetDiscovery {
  constructor(
    private readonly deps: { repos: Repositories; eventBus: EventBus },
  ) {}

  /**
   * Extract passive discoveries from recorded responses and DOM snapshots
   * since the last run. Idempotent per engagement via observation dedup
   * (`type::description` normalized by the observations repo contract).
   */
  async discover(engagementId: string, limit = 60): Promise<PassiveDiscoveryResult> {
    const result: PassiveDiscoveryResult = {
      links: [],
      scripts: [],
      forms: [],
      apiReferences: [],
      websocketReferences: [],
      observations: 0,
    };

    const responses = await this.deps.repos.httpResponses.listByEngagement(engagementId, limit);
    for (const response of responses) {
      const preview = typeof response.body_preview === 'string' ? response.body_preview : '';
      if (!preview) continue;
      const contentType = typeof response.content_type === 'string' ? response.content_type : '';
      const requestId = typeof response.request_id === 'string' ? response.request_id : null;
      if (!requestId) continue;
      const request = await this.deps.repos.httpRequests.findById(requestId);
      const url = request ? String(request.url) : '';

      if (contentType.includes('text/html')) {
        collect(preview, LINK_RE, result.links);
        collect(preview, SCRIPT_RE, result.scripts);
        collect(preview, API_REF_RE, result.apiReferences);
        collect(preview, WS_REF_RE, result.websocketReferences);
        result.forms.push(...(preview.match(FORM_RE) ?? []).map((form) => extractFormAction(form)));
      }
      void url;
    }

    // Dedup and bound.
    result.links = [...new Set(result.links)].slice(0, 200);
    result.scripts = [...new Set(result.scripts)].slice(0, 100);
    result.forms = [...new Set(result.forms.filter((f) => f.length > 0))].slice(0, 50);
    result.apiReferences = [...new Set(result.apiReferences)].slice(0, 100);
    result.websocketReferences = [...new Set(result.websocketReferences)].slice(0, 20);

    // Each discovery class becomes ONE bounded observation (§10).
    const discovered: Array<{ type: string; description: string; confidence: number; metadata: Record<string, unknown> }> = [];
    if (result.links.length > 0) {
      discovered.push({
        type: 'ASSET_DISCOVERED',
        description: `Passive discovery: ${result.links.length} unique links observed in recorded HTML`,
        confidence: 0.9,
        metadata: { kind: 'link', refs: result.links.slice(0, 40) },
      });
    }
    if (result.scripts.length > 0) {
      discovered.push({
        type: 'ASSET_DISCOVERED',
        description: `Passive discovery: ${result.scripts.length} JavaScript assets observed`,
        confidence: 0.9,
        metadata: { kind: 'script', refs: result.scripts.slice(0, 40) },
      });
    }
    if (result.forms.length > 0) {
      discovered.push({
        type: 'FORM_DISCOVERED',
        description: `Passive discovery: ${result.forms.length} forms observed in recorded HTML`,
        confidence: 0.85,
        metadata: { kind: 'form', refs: result.forms.slice(0, 25) },
      });
    }
    if (result.apiReferences.length > 0) {
      discovered.push({
        type: 'ENDPOINT_DISCOVERED',
        description: `Passive discovery: ${result.apiReferences.length} API references observed in content`,
        confidence: 0.75,
        metadata: { kind: 'api', refs: result.apiReferences.slice(0, 40), source: 'PASSIVE' },
      });
    }
    if (result.websocketReferences.length > 0) {
      discovered.push({
        type: 'WEBSOCKET_DISCOVERED',
        description: `Passive discovery: ${result.websocketReferences.length} WebSocket references observed`,
        confidence: 0.7,
        metadata: { kind: 'websocket', refs: result.websocketReferences.slice(0, 10) },
      });
    }

    for (const item of discovered) {
      await this.record(engagementId, item);
      result.observations += 1;
    }
    return result;
  }

  private async record(
    engagementId: string,
    item: { type: string; description: string; confidence: number; metadata: Record<string, unknown> },
  ): Promise<void> {
    await this.deps.repos.observations.create({
      engagementId,
      taskId: null,
      hypothesisId: null,
      type: item.type,
      description: item.description,
      confidence: item.confidence,
      evidenceIds: [],
      metadata: item.metadata,
    });
    const event: PlatformEvent = {
      type: 'OBSERVATION_CREATED',
      engagement_id: engagementId,
      trace_id: generateId('TRC'),
      actor_id: null,
      payload: { observation_type: item.type, passive: true, kind: item.metadata.kind ?? null },
      occurred_at: new Date().toISOString(),
      dedup_key: `passive-discovery:${engagementId}:${item.type}:${item.metadata.kind ?? ''}`,
    };
    await this.deps.eventBus.publish(event).catch(() => undefined);
  }
}

function collect(text: string, re: RegExp, out: string[]): void {
  let match: RegExpExecArray | null;
  const regex = new RegExp(re.source, re.flags);
  while ((match = regex.exec(text)) !== null) {
    if (match[1] && match[1].length > 1 && !match[1].startsWith('data:')) {
      out.push(match[1]);
    }
    if (out.length > 2000) break; // hard bound
  }
}

function extractFormAction(formTag: string): string {
  const action = /action=["']([^"']+)["']/i.exec(formTag);
  return action?.[1] ?? '';
}
