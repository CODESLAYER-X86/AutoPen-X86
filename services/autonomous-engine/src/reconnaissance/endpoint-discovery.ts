/**
 * Endpoint discovery (spec Part 6 §11).
 *
 * Generates BOUNDED candidate probes for endpoints not yet discovered —
 * known-path validation and API route exploration. This is not a
 * brute-forcer: the candidate set is small, deterministic and deduplicated
 * against the reasoning engine's discovered endpoints.
 */
import type { Repositories } from '@aegis/database';
import { reconFingerprint } from './recon-planner.js';

export interface EndpointProbeCandidate {
  path: string;
  reason: string;
  expectedInformationGain: number;
  estimatedCost: number;
  fingerprint: string;
}

/** Candidate route segments derived from observed resource families (§11). */
const FAMILY_SUFFIXES = ['', '/{id}', '/list', '/all', '/search', '/detail', '/status'];

export class EndpointDiscovery {
  constructor(private readonly repos: Repositories) {}

  /**
   * Candidates = known paths not yet discovered + family expansions of
   * discovered canonical paths. Bounded to `maxCandidates`.
   */
  async candidates(
    engagementId: string,
    knownPaths: readonly string[],
    maxCandidates = 16,
  ): Promise<EndpointProbeCandidate[]> {
    const endpoints = await this.repos.endpoints.listByEngagement(engagementId, { limit: 200 });
    const known = new Set(endpoints.map((endpoint) => endpoint.canonical_path.toLowerCase()));
    const out: EndpointProbeCandidate[] = [];

    for (const path of knownPaths) {
      if (known.has(path.toLowerCase())) continue;
      out.push({
        path,
        reason: 'Known-path validation: path not yet observed in the attack surface',
        expectedInformationGain: 0.5,
        estimatedCost: 0.1,
        fingerprint: reconFingerprint(engagementId, 'endpoint-probe', path),
      });
      if (out.length >= maxCandidates) return out;
    }

    // Family exploration (§11 API route exploration): for each discovered
    // collection path, a bounded set of conventional siblings.
    for (const endpoint of endpoints.slice(0, 12)) {
      const family = endpoint.resource_family;
      if (!family) continue;
      for (const suffix of FAMILY_SUFFIXES) {
        const candidate = suffix === '' ? `/api/${family}` : `/api/${family}${suffix}`;
        if (known.has(candidate.toLowerCase())) continue;
        out.push({
          path: candidate,
          reason: `Resource family expansion: "${family}" observed, conventional sibling path`,
          expectedInformationGain: 0.4,
          estimatedCost: 0.1,
          fingerprint: reconFingerprint(engagementId, 'endpoint-probe', candidate),
        });
        if (out.length >= maxCandidates) return out;
      }
    }
    return out;
  }
}
