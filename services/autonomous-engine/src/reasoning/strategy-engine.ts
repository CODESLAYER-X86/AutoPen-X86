/**
 * Pentest strategy engine (spec Part 6 §32-§33, §74-§75, §78).
 *
 * Strategy priorities are DYNAMIC: they follow the observed attack surface
 * (no fixed vulnerability checklist, §33). Example: API + multiple
 * identities + object IDs + JSON -> authorization differential first. The
 * engine computes a deterministic initial strategy and recomputes it on
 * replan triggers (§75); the leader may override priorities but the
 * platform decides what executes (§47).
 */
import type { Repositories } from '@aegis/database';
import type { AttackSurfaceProjection } from './projection-types.js';

export interface StrategyPriorities {
  phase: 'INITIAL_RECON' | 'SURFACE_MODELING' | 'HYPOTHESIS_TESTING' | 'VERIFICATION' | 'DEEP_EXPLORATION';
  priorities: string[];
  rationale: string;
  stopConditions: string[];
  budgetAllocation: { recon: number; testing: number; verification: number };
}

export interface StrategyEngineOptions {
  reconShare: number;
  testingShare: number;
}

export class StrategyEngine {
  constructor(
    private readonly repos: Repositories,
    private readonly opts: StrategyEngineOptions,
  ) {}

  /**
   * Initial strategy (§74): objective, recon priorities, stop conditions and
   * resource allocation — never hundreds of tests up front.
   */
  async generateInitialStrategy(engagementId: string): Promise<StrategyPriorities> {
    const [endpoints, identities, objects, workflows] = await Promise.all([
      this.repos.endpoints.listByEngagement(engagementId, { limit: 200 }),
      this.repos.identities.listByEngagement(engagementId),
      this.repos.objectCandidates.listByEngagement(engagementId, 200),
      this.repos.workflows.listByEngagement(engagementId),
    ]);

    const hasApi = endpoints.some((e) => e.canonical_path.startsWith('/api'));
    const multiIdentity = identities.filter((i) => i.type !== 'ANONYMOUS').length >= 2;
    const hasObjects = objects.length > 0;
    const hasWorkflows = workflows.length > 0;

    const priorities: string[] = [];
    if (hasApi && multiIdentity && hasObjects) {
      priorities.push('authorization_differential', 'object_access_control', 'role_enforcement');
    }
    if (hasWorkflows) priorities.push('workflow_state_issues');
    priorities.push('input_validation', 'session_handling', 'client_side_state', 'configuration');

    return {
      phase: 'INITIAL_RECON',
      priorities,
      rationale: [
        `Observed surface: ${endpoints.length} endpoints, ${identities.length} identities, ${objects.length} object candidates, ${workflows.length} workflows.`,
        hasApi && multiIdentity && hasObjects
          ? 'API + multiple identities + object identifiers: authorization differentials dominate (§32).'
          : 'Surface does not yet support authorization differentials; authorization priority falls until identities/objects exist (§32).',
      ].join(' '),
      stopConditions: ['objective_completed', 'no_useful_hypotheses', 'budget_exhausted', 'diminishing_returns'],
      budgetAllocation: {
        recon: this.opts.reconShare,
        testing: this.opts.testingShare,
        verification: Math.max(0.05, 1 - this.opts.reconShare - this.opts.testingShare),
      },
    };
  }

  /**
   * Replanned strategy (§64): after every meaningful result the priorities
   * are recomputed from the CURRENT surface. Evidence changes -> strategy
   * changes (§32 dynamic selection).
   */
  async replan(engagementId: string, trigger: string): Promise<StrategyPriorities> {
    const [hypotheses, verifiedFindings] = await Promise.all([
      this.repos.hypotheses.listByEngagement(engagementId, {
        statuses: ['PROPOSED', 'ACTIVE', 'TESTING', 'SUPPORTED'],
      }),
      this.repos.findings.listByEngagement(engagementId, { statuses: ['CONFIRMED', 'VERIFIED'], limit: 100 }),
    ]);

    const priorities: string[] = [];
    if (verifiedFindings.length > 0) {
      priorities.push('related_endpoint_expansion');
    }
    if (hypotheses.some((h) => h.status === 'SUPPORTED')) {
      priorities.push('verification');
    }
    const surface = await this.surfaceSnapshot(engagementId);
    if (surface.identityCount >= 2 && surface.objectCount > 0) {
      priorities.push('authorization_differential', 'object_access_control');
    }
    if (surface.workflowCount > 0) priorities.push('workflow_state_issues');
    priorities.push('input_validation', 'session_handling');

    return {
      phase: verifiedFindings.length > 0 ? 'VERIFICATION' : 'HYPOTHESIS_TESTING',
      priorities,
      rationale: `Replan (${trigger}): ${hypotheses.length} actionable hypotheses, ${verifiedFindings.length} verified findings; priorities recomputed from the current surface (§64).`,
      stopConditions: ['objective_completed', 'no_useful_hypotheses', 'budget_exhausted', 'diminishing_returns'],
      budgetAllocation: {
        recon: Math.max(0.1, this.opts.reconShare / 2),
        testing: this.opts.testingShare,
        verification: Math.max(0.05, 1 - this.opts.reconShare / 2 - this.opts.testingShare),
      },
    };
  }

  private async surfaceSnapshot(engagementId: string): Promise<AttackSurfaceProjection> {
    const [endpoints, identities, objects, workflows] = await Promise.all([
      this.repos.endpoints.listByEngagement(engagementId, { limit: 200 }),
      this.repos.identities.listByEngagement(engagementId),
      this.repos.objectCandidates.listByEngagement(engagementId, 200),
      this.repos.workflows.listByEngagement(engagementId),
    ]);
    return {
      endpointCount: endpoints.length,
      identityCount: identities.filter((i) => i.type !== 'ANONYMOUS').length,
      objectCount: objects.length,
      workflowCount: workflows.length,
      parameterCount: 0,
    };
  }
}
