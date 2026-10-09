/**
 * Attack-surface graph projection (spec Part 6 §12-§13).
 *
 * Unified graph view: reasoning graph nodes (Part 4) + identity/session
 * relationships + workflow transitions + hypothesis/finding links,
 * projected for the API (§72 GET /engagements/:id/graph). Node and edge
 * types follow the §13 vocabulary; unrelated concepts are never overloaded
 * onto one node type.
 */
import type { Repositories } from '@aegis/database';
import type { AttackSurfaceGraph, GraphNode, GraphEdge } from '@aegis/contracts';

const MAX_NODES = 2000;
const MAX_EDGES = 8000;

export class AttackSurfaceGraphProjector {
  constructor(private readonly repos: Repositories) {}

  /** Build the unified graph projection (§12, §13). */
  async project(engagementId: string): Promise<AttackSurfaceGraph> {
    const nodes: GraphNode[] = [];
    const edges: GraphEdge[] = [];
    const counts: Record<string, number> = {};

    const addNode = (node: GraphNode) => {
      if (nodes.length >= MAX_NODES) return;
      nodes.push(node);
      counts[node.type] = (counts[node.type] ?? 0) + 1;
    };
    const addEdge = (edge: GraphEdge) => {
      if (edges.length >= MAX_EDGES) return;
      edges.push(edge);
    };

    // Engagement -> targets (§12 TARGET -> HOST -> APPLICATION).
    const targets = await this.repos.targets.listByEngagement(engagementId);
    for (const target of targets) {
      addNode({ id: target.id, type: 'TARGET', label: target.value, status: null, refs: [] });
      addEdge({ source: engagementId, target: target.id, relation: 'HOSTS' });
      addNode({ id: `${target.id}:app`, type: 'APPLICATION', label: `application @ ${target.value}`, status: null, refs: [target.id] });
      addEdge({ source: target.id, target: `${target.id}:app`, relation: 'CONTAINS' });
    }

    // Part 4 reasoning nodes: endpoints, parameters, objects, workflows.
    const endpoints = await this.repos.endpoints.listByEngagement(engagementId, { limit: 200 });
    const endpointTarget = new Map<string, string>();
    for (const endpoint of endpoints) {
      const parentId = endpoints.length > 0 && targets.length > 0 ? `${targets[0]!.id}:app` : engagementId;
      const methods = endpoint.methods.map((m) => m.method).join('|');
      addNode({
        id: endpoint.id,
        type: 'ENDPOINT',
        label: `${methods || 'GET'} ${endpoint.canonical_path}`,
        status: endpoint.status,
        refs: [endpoint.resource_family ?? ''],
      });
      endpointTarget.set(endpoint.id, parentId);
      addEdge({ source: parentId, target: endpoint.id, relation: 'CONTAINS' });
    }

    const parameters = await this.repos.parameters.listByEngagement(engagementId, 400);
    for (const parameter of parameters) {
      addNode({ id: parameter.id, type: 'PARAMETER', label: `${parameter.location}:${parameter.name}`, status: null, refs: [] });
      if (parameter.endpoint_id) addEdge({ source: parameter.endpoint_id, target: parameter.id, relation: 'ACCEPTS' });
    }

    const objects = await this.repos.objectCandidates.listByEngagement(engagementId, 200);
    for (const object of objects) {
      addNode({ id: object.id, type: 'OBJECT', label: `${object.kind}:${object.name}`, status: null, refs: [object.parameter_id ?? ''] });
      if (object.endpoint_id) addEdge({ source: object.endpoint_id, target: object.id, relation: 'RETURNS' });
    }

    const workflows = await this.repos.workflows.listByEngagement(engagementId);
    for (const workflow of workflows) {
      addNode({ id: workflow.id, type: 'WORKFLOW', label: workflow.name, status: workflow.status, refs: [] });
      addEdge({ source: engagementId, target: workflow.id, relation: 'CONTAINS' });
      const states = await this.repos.workflowStates.listByWorkflow(workflow.id);
      for (const state of states) {
        addNode({ id: state.id, type: 'STATE', label: state.name, status: state.observed ? 'OBSERVED' : 'INFERRED', refs: [workflow.id] });
        addEdge({ source: workflow.id, target: state.id, relation: 'TRANSITIONS_TO' });
      }
    }

    // Identity relationships (§12: USER_A --USES--> SESSION_A).
    const identities = await this.repos.identities.listByEngagement(engagementId);
    for (const identity of identities) {
      addNode({ id: identity.id, type: 'IDENTITY', label: `${identity.name} (${identity.type})`, status: null, refs: [] });
      addEdge({ source: engagementId, target: identity.id, relation: 'CONTAINS' });
    }
    const matrix = await this.repos.authzMatrix.listByEngagement(engagementId, 300);
    for (const cell of matrix) {
      const identityRef = cell.identity_id ?? `${engagementId}:anonymous`;
      if (!nodes.some((n) => n.id === identityRef)) {
        addNode({ id: identityRef, type: 'IDENTITY', label: 'anonymous', status: null, refs: [] });
      }
      if (cell.endpoint_id) {
        addEdge({ source: identityRef, target: cell.endpoint_id, relation: 'CALLS' });
      }
      if (cell.object_ref) {
        addEdge({ source: identityRef, target: cell.object_ref, relation: 'USES' });
      }
    }

    // Hypotheses + findings (§13 OBSERVED_IN / SUPPORTS / CONTRADICTS).
    const hypotheses = await this.repos.hypotheses.listByEngagement(engagementId, { limit: 100 });
    for (const hypothesis of hypotheses) {
      addNode({ id: hypothesis.id, type: 'HYPOTHESIS', label: hypothesis.statement.slice(0, 120), status: hypothesis.status, refs: [] });
      addEdge({ source: engagementId, target: hypothesis.id, relation: 'OBSERVED_IN' });
    }
    const findings = await this.repos.findings.listByEngagement(engagementId, { limit: 50 });
    for (const finding of findings) {
      addNode({ id: finding.id, type: 'FINDING', label: finding.title, status: finding.status, refs: [] });
      if (finding.hypothesis_id) {
        addEdge({ source: finding.hypothesis_id, target: finding.id, relation: 'SUPPORTS' });
      }
    }

    return {
      engagement_id: engagementId,
      nodes,
      edges,
      counts,
      truncated: nodes.length >= MAX_NODES || edges.length >= MAX_EDGES,
    };
  }
}
