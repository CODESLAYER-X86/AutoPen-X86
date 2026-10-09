/**
 * Parameter discovery (spec Part 6 §11, §13).
 *
 * Passive: parameters already observed (Part 4 extracts them from traffic).
 * Active: hidden-parameter probe candidates — a small, conventional set of
 * parameter names NOT yet observed on high-value endpoints. These become
 * mutation-based test candidates, never raw brute force.
 */
import type { Repositories } from '@aegis/database';
import { reconFingerprint } from './recon-planner.js';

export interface ParameterProbeCandidate {
  endpointId: string;
  canonicalPath: string;
  parameter: string;
  location: 'query';
  reason: string;
  expectedInformationGain: number;
  estimatedCost: number;
  fingerprint: string;
}

/** Conventional hidden-parameter candidates (bounded, deterministic). */
const HIDDEN_PARAMETER_CANDIDATES: readonly string[] = [
  'debug',
  'admin',
  'role',
  'user_id',
  'account',
  'internal',
  'test',
  'callback',
  'redirect',
  'next',
];

export class ParameterDiscovery {
  constructor(private readonly repos: Repositories) {}

  /**
   * Hidden-parameter probes for the highest-priority endpoints (§11
   * parameter variation). Only endpoints with observed parameters or object
   * identifiers are probed — parameter presence implies the handler reads
   * them.
   */
  async candidates(engagementId: string, maxCandidates = 12): Promise<ParameterProbeCandidate[]> {
    const endpoints = await this.repos.endpoints.listByEngagement(engagementId, { limit: 40 });
    const out: ParameterProbeCandidate[] = [];

    for (const endpoint of endpoints) {
      if (endpoint.confidence < 0.4 || endpoint.observation_count < 1) continue;
      const parameters = await this.repos.parameters.listByEndpoint(endpoint.id);
      const observed = new Set(parameters.map((p) => p.name.toLowerCase()));
      for (const candidate of HIDDEN_PARAMETER_CANDIDATES) {
        if (observed.has(candidate)) continue;
        out.push({
          endpointId: endpoint.id,
          canonicalPath: endpoint.canonical_path,
          parameter: candidate,
          location: 'query',
          reason: `Hidden-parameter probe: "${candidate}" not yet observed on ${endpoint.canonical_path}; presence would reveal additional server-side handling`,
          expectedInformationGain: 0.3,
          estimatedCost: 0.1,
          fingerprint: reconFingerprint(engagementId, 'param-probe', `${endpoint.id}:${candidate}`),
        });
        if (out.length >= maxCandidates) return out;
      }
    }
    return out;
  }
}
