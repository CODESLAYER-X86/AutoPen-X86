/**
 * Reconnaissance planner (spec Part 6 §9-§11, §77).
 *
 * When an engagement starts the engine FIRST establishes a baseline — it does
 * NOT immediately begin vulnerability testing (§9):
 *
 *   Validate Scope -> Load Targets -> Load Identities -> Initialize Sessions
 *   -> Passive Discovery -> Active Discovery -> Application Mapping
 *
 * The plan is deterministic: every task carries reason, scope, expected
 * information gain, estimated cost and risk (§11). Active discovery stays
 * bounded (never uncontrolled brute-force by default): a fixed candidate
 * path set per target, rate-limited by the HTTP engine's limiter and audited
 * by the normal task lifecycle.
 */
import { createHash } from 'node:crypto';
import type { EngagementRecord, TargetRecord, IdentityRecord } from '@aegis/database';
import type { ReconPlan, ReconPlanTask } from '@aegis/contracts';
import type { ReconLevel } from '@aegis/shared';

export interface ReconPlannerOptions {
  maxTasks: number;
  maxPathsPerTarget: number;
  /** Bounded active-discovery candidate paths (§11 — NOT a brute-forcer). */
  knownPaths?: readonly string[];
}

/** Conservative, well-known validation paths (§11 known-path validation). */
export const DEFAULT_KNOWN_PATHS: readonly string[] = [
  '/robots.txt',
  '/sitemap.xml',
  '/login',
  '/api',
  '/api/status',
  '/api/health',
  '/.well-known/security.txt',
  '/docs',
  '/openapi.json',
  '/swagger.json',
];

export interface ReconPlanInput {
  engagement: EngagementRecord;
  targets: TargetRecord[];
  identities: IdentityRecord[];
}

export class ReconPlanner {
  private readonly opts: Required<ReconPlannerOptions>;

  constructor(options: ReconPlannerOptions) {
    this.opts = {
      maxTasks: options.maxTasks,
      maxPathsPerTarget: options.maxPathsPerTarget,
      knownPaths: options.knownPaths ?? DEFAULT_KNOWN_PATHS,
    };
  }

  /**
   * Build the deterministic initial recon plan (§9). Level defaults to 2
   * (normal active discovery, §77); the leader may deepen later.
   */
  async plan(input: ReconPlanInput, level: ReconLevel = 2): Promise<ReconPlan> {
    const tasks: ReconPlanTask[] = [];
    const { engagement, targets, identities } = input;

    // 1. Scope validation (§9 step 1) — a read-only analysis task.
    tasks.push(
      this.task({
        stage: 'SCOPE_VALIDATION',
        objective: `Validate engagement scope against targets and confirm every target is in-scope before any active work: ${targets.map((t) => t.value).join(', ')}`,
        task_type: 'RECON',
        worker_type: 'ANALYSIS_WORKER',
        identity_id: null,
        target_hint: null,
        expected_information_gain: 0.9,
        estimated_cost: 0.05,
        risk: 'LOW',
        reason: 'Scope validation is the mandatory first stage of the recon pipeline (§9).',
        paths: [],
        fingerprint: `recon-scope:${engagement.id}`,
      }),
    );

    for (const target of targets) {
      const base = this.baseUrl(target);

      // 2. Passive discovery per target (§10) — browser mapping captures
      //    links, forms, scripts, network traffic and DOM snapshots.
      tasks.push(
        this.task({
          stage: 'PASSIVE_DISCOVERY',
          objective: `Map the application at ${base} passively: navigate the entry page, capture links, forms, scripts, client-side storage and observed network requests without any mutation.`,
          task_type: 'BROWSER_INVESTIGATION',
          worker_type: 'BROWSER_WORKER',
          identity_id: null,
          target_hint: base,
          expected_information_gain: 0.85,
          estimated_cost: 0.2,
          risk: 'LOW',
          reason: 'Passive discovery first: information already naturally available (§10).',
          paths: [],
          fingerprint: `recon-passive:${engagement.id}:${target.id}`,
        }),
      );

      // 3. Active discovery (§11) — bounded known-path validation.
      if (level >= 2) {
        const paths = this.opts.knownPaths.slice(0, this.opts.maxPathsPerTarget);
        tasks.push(
          this.task({
            stage: 'ACTIVE_DISCOVERY',
            objective: `Validate known application paths on ${base} (${paths.join(', ')}) and record which respond, their status, content type and redirect behavior. Do not attempt vulnerability payloads.`,
            task_type: 'RECON',
            worker_type: 'HTTP_WORKER',
            identity_id: null,
            target_hint: base,
            expected_information_gain: 0.7,
            estimated_cost: 0.35,
            risk: 'LOW',
            reason: 'Bounded known-path validation extends the map with candidate endpoints (§11).',
            paths,
            fingerprint: `recon-active:${engagement.id}:${target.id}`,
          }),
        );
      }
    }

    // 4. Session initialization (§9 step 4) — one login workflow per
    //    identity that has auth material, so later differentials have two
    //    cleanly separated identity sessions (§19).
    for (const identity of identities) {
      if (identity.type === 'ANONYMOUS') continue;
      tasks.push(
        this.task({
          stage: 'SESSION_INIT',
          objective: `Initialize the session for identity ${identity.name} by exercising the recorded login workflow, then capture and verify the resulting session state for later identity-differential tests.`,
          task_type: 'AUTHENTICATION_ANALYSIS',
          worker_type: 'BROWSER_WORKER',
          identity_id: identity.id,
          target_hint: null,
          expected_information_gain: 0.8,
          estimated_cost: 0.25,
          risk: 'LOW',
          reason: 'Identity sessions are prerequisites for differential testing (§9, §19).',
          paths: [],
          fingerprint: `recon-session:${engagement.id}:${identity.id}`,
        }),
      );
    }

    // 5. Application mapping (§9) — correlate the captured surface.
    tasks.push(
      this.task({
        stage: 'APPLICATION_MAPPING',
        objective: 'Correlate all reconnaissance observations into an application model: pages, endpoints, API families, JavaScript assets, forms, parameters, authentication boundaries and workflows. Summarize the attack surface.',
        task_type: 'RECON',
        worker_type: 'ANALYSIS_WORKER',
        identity_id: null,
        target_hint: null,
        expected_information_gain: 0.6,
        estimated_cost: 0.15,
        risk: 'LOW',
        reason: 'Attack-surface graph construction follows discovery (§12).',
        paths: [],
        fingerprint: `recon-mapping:${engagement.id}`,
      }),
    );

    return {
      engagement_id: engagement.id,
      level,
      tasks: tasks.slice(0, this.opts.maxTasks),
      passive_sources: ['HTTP_RESPONSE', 'DOM_SNAPSHOT', 'BROWSER_NETWORK', 'REDIRECT', 'COOKIE'],
      bounded: true,
    };
  }

  private task(input: Omit<ReconPlanTask, 'fingerprint'> & { fingerprint: string }): ReconPlanTask {
    return { ...input };
  }

  private baseUrl(target: TargetRecord): string {
    const value = target.value.trim();
    if (/^https?:\/\//i.test(value)) return value.replace(/\/+$/, '');
    return `http://${value.replace(/\/+$/, '')}`;
  }
}

/** Deterministic recon task fingerprint (used for idempotent compilation). */
export function reconFingerprint(engagementId: string, stage: string, ref: string): string {
  return createHash('sha256').update(`${engagementId}:${stage}:${ref}`).digest('hex').slice(0, 32);
}
