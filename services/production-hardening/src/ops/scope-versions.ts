/**
 * Scope versioning (spec Part 8 §91-§92).
 *
 * Scope never mutates in place. A change proposes a new version with a
 * deterministic diff; explicit confirmation activates it; the previous
 * version is superseded. Every audit entry for target-bound actions records
 * the scope version it executed under, so historical behaviour stays
 * attributable (Task T42 ran under Scope v3 even after v4 activates).
 */
import type { ScopeVersionRecord } from '@aegis/database';
import type { EventPort } from '../ops/ports.js';

export interface ScopeRulesShape {
  allowed_hosts: string[];
  allowed_domains: string[];
  allowed_paths?: string[];
  allowed_ports: number[];
  allowed_schemes: string[];
  excluded_hosts: string[];
  excluded_paths?: string[];
  rate_limit?: number | null;
  concurrency_limit?: number | null;
  destructive_actions_allowed?: boolean;
}

export interface ScopeDiff {
  added_hosts: string[];
  removed_hosts: string[];
  added_paths: string[];
  removed_paths: string[];
  destructive_actions_allowed: boolean;
}

export interface ScopeVersionsDeps {
  repos: {
    scopeVersions: {
      propose(input: {
        engagementId: string;
        scope: Record<string, unknown>;
        diff: Record<string, unknown>;
        createdBy: string;
      }): Promise<ScopeVersionRecord>;
      activate(id: string): Promise<ScopeVersionRecord | null>;
      findActive(engagementId: string): Promise<ScopeVersionRecord | null>;
      listByEngagement(engagementId: string): Promise<ScopeVersionRecord[]>;
    };
    audit: {
      create(input: {
        actorUserId: string | null;
        action: string;
        resource: string;
        resourceId?: string | null;
        engagementId?: string | null;
        metadata?: Record<string, unknown>;
      }): Promise<unknown>;
    };
  };
  eventBus?: EventPort;
}

/** Deterministic scope diff — symmetric difference of hosts + paths (§91). */
export function computeScopeDiff(previous: ScopeRulesShape, next: ScopeRulesShape): ScopeDiff {
  const prevHosts = new Set(previous.allowed_hosts.map((h) => h.toLowerCase()));
  const nextHosts = new Set(next.allowed_hosts.map((h) => h.toLowerCase()));
  const prevPaths = new Set((previous.allowed_paths ?? []).map((p) => p.toLowerCase()));
  const nextPaths = new Set((next.allowed_paths ?? []).map((p) => p.toLowerCase()));
  return {
    added_hosts: [...nextHosts].filter((h) => !prevHosts.has(h)).sort(),
    removed_hosts: [...prevHosts].filter((h) => !nextHosts.has(h)).sort(),
    added_paths: [...nextPaths].filter((p) => !prevPaths.has(p)).sort(),
    removed_paths: [...prevPaths].filter((p) => !nextPaths.has(p)).sort(),
    destructive_actions_allowed: (next.destructive_actions_allowed ?? false) && !(previous.destructive_actions_allowed ?? false),
  };
}

export class ScopeVersionsEngine {
  constructor(private readonly deps: ScopeVersionsDeps) {}

  /**
   * Propose a new scope version. Requires explicit user confirmation
   * afterwards (§91: never silently mutate the existing scope).
   */
  async propose(input: {
    engagementId: string;
    scope: ScopeRulesShape;
    createdBy: string;
  }): Promise<ScopeVersionRecord> {
    const active = await this.deps.repos.scopeVersions.findActive(input.engagementId);
    const diff = computeScopeDiff(
      (active?.scope as ScopeRulesShape | undefined) ?? emptyScope(),
      input.scope,
    );
    const record = await this.deps.repos.scopeVersions.propose({
      engagementId: input.engagementId,
      scope: input.scope as unknown as Record<string, unknown>,
      diff: diff as unknown as Record<string, unknown>,
      createdBy: input.createdBy,
    });
    await this.deps.repos.audit.create({
      actorUserId: input.createdBy,
      action: 'scope_version.proposed',
      resource: 'scope_version',
      resourceId: record.id,
      engagementId: input.engagementId,
      metadata: { version: record.version, diff },
    });
    await this.deps.eventBus?.publish({
      type: 'SCOPE_VERSION_PROPOSED',
      engagement_id: input.engagementId,
      trace_id: record.id,
      actor_id: input.createdBy,
      payload: { version: record.version, diff },
      occurred_at: new Date().toISOString(),
    });
    return record;
  }

  /** Explicit confirmation activates the version (§91). */
  async activate(input: { id: string; engagementId: string; actorUserId: string }): Promise<ScopeVersionRecord> {
    const record = await this.deps.repos.scopeVersions.activate(input.id);
    if (!record) {
      throw new Error('Scope version not found or not in PROPOSED state');
    }
    await this.deps.repos.audit.create({
      actorUserId: input.actorUserId,
      action: 'scope_version.activated',
      resource: 'scope_version',
      resourceId: record.id,
      engagementId: record.engagement_id,
      metadata: { version: record.version },
    });
    await this.deps.eventBus?.publish({
      type: 'SCOPE_VERSION_ACTIVATED',
      engagement_id: record.engagement_id,
      trace_id: record.id,
      actor_id: input.actorUserId,
      payload: { version: record.version },
      occurred_at: new Date().toISOString(),
    });
    return record;
  }

  findActive(engagementId: string): Promise<ScopeVersionRecord | null> {
    return this.deps.repos.scopeVersions.findActive(engagementId);
  }

  listByEngagement(engagementId: string): Promise<ScopeVersionRecord[]> {
    return this.deps.repos.scopeVersions.listByEngagement(engagementId);
  }
}

function emptyScope(): ScopeRulesShape {
  return {
    allowed_hosts: [],
    allowed_domains: [],
    allowed_paths: [],
    allowed_ports: [],
    allowed_schemes: [],
    excluded_hosts: [],
    excluded_paths: [],
  };
}
