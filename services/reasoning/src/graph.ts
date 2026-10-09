/**
 * Attack-surface graph writer (spec §4-§6, §91).
 *
 * Nodes and edges are persisted with fingerprint upserts (§5). The graph
 * mirrors the reasoning registries (ENDPOINT, PARAMETER, IDENTITY, WORKFLOW,
 * STATE, OBJECT, HYPOTHESIS, FINDING nodes) plus navigation-derived nodes
 * (HOST, PAGE, FORM, SCRIPT, WEBSOCKET). Bounded by limits (§113).
 */
import type { AttackEdgeRelation, AttackNodeType } from '@aegis/shared';
import type { AttackEdgeRecord, AttackNodeRecord, EndpointRecord } from '@aegis/database';
import { createHash } from 'node:crypto';

export interface GraphWriterDeps {
  nodes: {
    upsert(input: {
      engagementId: string;
      nodeType: AttackNodeType;
      externalRef: string | null;
      fingerprint: string;
      label: string;
      metadata: Record<string, unknown>;
      confidence: number;
      at: string;
    }): Promise<AttackNodeRecord>;
    findByExternalRef(engagementId: string, nodeType: AttackNodeType, externalRef: string): Promise<AttackNodeRecord | null>;
    countByEngagement(engagementId: string): Promise<number>;
  };
  edges: {
    upsert(input: {
      engagementId: string;
      sourceNodeId: string;
      targetNodeId: string;
      relation: AttackEdgeRelation;
      metadata: Record<string, unknown>;
      confidence: number;
    }): Promise<{ record: AttackEdgeRecord; created: boolean }>;
    countByEngagement(engagementId: string): Promise<number>;
  };
}

export class AttackSurfaceGraph {
  constructor(private readonly deps: GraphWriterDeps) {}

  static nodeFingerprint(nodeType: AttackNodeType, externalRef: string): string {
    return createHash('sha256').update(`${nodeType}|${externalRef}`).digest('hex').slice(0, 40);
  }

  private async upsertNode(
    engagementId: string,
    nodeType: AttackNodeType,
    externalRef: string | null,
    label: string,
    metadata: Record<string, unknown> = {},
    confidence = 0.9,
    at = new Date().toISOString(),
  ): Promise<AttackNodeRecord> {
    const effectiveRef = externalRef ?? label;
    return this.deps.nodes.upsert({
      engagementId,
      nodeType,
      externalRef,
      fingerprint: AttackSurfaceGraph.nodeFingerprint(nodeType, effectiveRef),
      label,
      metadata,
      confidence,
      at,
    });
  }

  async ensureEngagementNode(engagementId: string, name: string): Promise<AttackNodeRecord> {
    return this.upsertNode(engagementId, 'ENGAGEMENT', engagementId, `Engagement ${name}`);
  }

  async ensureHostNode(engagementId: string, host: string): Promise<AttackNodeRecord> {
    return this.upsertNode(engagementId, 'HOST', host, host, { host });
  }

  async ensurePageNode(engagementId: string, pageId: string, url: string): Promise<AttackNodeRecord> {
    return this.upsertNode(engagementId, 'PAGE', pageId, bounded(url, 200), { url: bounded(url, 512) });
  }

  async ensureEndpointNode(engagementId: string, endpoint: EndpointRecord): Promise<AttackNodeRecord> {
    return this.upsertNode(
      engagementId,
      'ENDPOINT',
      endpoint.id,
      `${endpoint.methods.map((method) => method.method).join(',').slice(0, 40)} ${endpoint.canonical_path}`,
      {
        canonical_path: endpoint.canonical_path,
        fingerprint: endpoint.fingerprint,
        discovery_source: endpoint.discovery_source,
        confidence_category: endpoint.confidence_category,
      },
      endpoint.confidence,
    );
  }

  async ensureParameterNode(engagementId: string, parameterId: string, name: string, location: string): Promise<AttackNodeRecord> {
    return this.upsertNode(engagementId, 'PARAMETER', parameterId, `${name} (${location.toLowerCase()})`, {
      name,
      location,
    });
  }

  async ensureIdentityNode(engagementId: string, identityId: string, name: string, role: string): Promise<AttackNodeRecord> {
    return this.upsertNode(engagementId, 'IDENTITY', identityId, `${name}${role ? ` (${role})` : ''}`, { name, role });
  }

  async ensureFormNode(engagementId: string, pageUrl: string, action: string): Promise<AttackNodeRecord> {
    return this.upsertNode(engagementId, 'FORM', `${pageUrl}->${action}`, `Form ${bounded(action, 120)} on ${bounded(pageUrl, 80)}`, {
      action: bounded(action, 512),
      page_url: bounded(pageUrl, 512),
    });
  }

  async ensureScriptNode(engagementId: string, scriptSrc: string): Promise<AttackNodeRecord> {
    return this.upsertNode(engagementId, 'SCRIPT', scriptSrc, bounded(scriptSrc, 200), { src: bounded(scriptSrc, 512) });
  }

  async ensureWebSocketNode(engagementId: string, connectionId: string, url: string): Promise<AttackNodeRecord> {
    return this.upsertNode(engagementId, 'WEBSOCKET', connectionId, bounded(url, 200), { url: bounded(url, 512) });
  }

  async ensureWorkflowNode(engagementId: string, workflowId: string, name: string): Promise<AttackNodeRecord> {
    return this.upsertNode(engagementId, 'WORKFLOW', workflowId, name);
  }

  async ensureStateNode(engagementId: string, stateId: string, name: string): Promise<AttackNodeRecord> {
    return this.upsertNode(engagementId, 'STATE', stateId, name);
  }

  async ensureObjectNode(engagementId: string, objectId: string, name: string, kind: string): Promise<AttackNodeRecord> {
    return this.upsertNode(engagementId, 'OBJECT', objectId, `${name} (${kind.toLowerCase()})`, { name, kind }, 0.6);
  }

  async ensureHypothesisNode(engagementId: string, hypothesisId: string, statement: string): Promise<AttackNodeRecord> {
    return this.upsertNode(engagementId, 'HYPOTHESIS', hypothesisId, bounded(statement, 200), {}, 0.5);
  }

  async ensureFindingNode(engagementId: string, findingId: string, title: string): Promise<AttackNodeRecord> {
    return this.upsertNode(engagementId, 'FINDING', findingId, bounded(title, 200));
  }

  async link(
    engagementId: string,
    source: AttackNodeRecord,
    target: AttackNodeRecord,
    relation: AttackEdgeRelation,
    metadata: Record<string, unknown> = {},
    confidence = 0.9,
  ): Promise<AttackEdgeRecord | null> {
    if (source.id === target.id) return null; // no self-edges (migration constraint)
    const nodeCount = await this.deps.nodes.countByEngagement(engagementId);
    if (nodeCount > 50_000) return null; // hard bound even before configured limits
    const result = await this.deps.edges.upsert({
      engagementId,
      sourceNodeId: source.id,
      targetNodeId: target.id,
      relation,
      metadata,
      confidence,
    });
    return result.record;
  }

  /**
   * Standard relationship wiring for an observed endpoint (§4):
   * HOST contains ENDPOINT; IDENTITY accesses ENDPOINT; PAGE calls ENDPOINT.
   */
  async wireEndpoint(
    engagementId: string,
    endpoint: EndpointRecord,
    context: { hostNode: AttackNodeRecord; identityId: string | null; pageId: string | null },
  ): Promise<void> {
    const endpointNode = await this.ensureEndpointNode(engagementId, endpoint);
    await this.link(engagementId, context.hostNode, endpointNode, 'contains', {
      scheme: endpoint.scheme,
      port: endpoint.port,
    });
    if (context.identityId) {
      // Identity node is ensured by the caller (names come from identities repo).
      const identityNode = await this.deps.nodes.findByExternalRef(engagementId, 'IDENTITY', context.identityId);
      if (identityNode) {
        await this.link(engagementId, identityNode, endpointNode, 'accesses', { methods: endpoint.methods.map((method) => method.method) });
      }
    }
    if (context.pageId) {
      const pageNode = await this.deps.nodes.findByExternalRef(engagementId, 'PAGE', context.pageId);
      if (pageNode) {
        await this.link(engagementId, pageNode, endpointNode, 'calls', { source: 'browser_capture' });
      }
    }
  }
}

function bounded(text: string, max: number): string {
  return text.length > max ? text.slice(0, max) : text;
}
