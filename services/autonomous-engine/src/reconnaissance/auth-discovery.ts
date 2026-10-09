/**
 * Authentication-flow discovery (spec Part 6 §9, §10, §19).
 *
 * Detects login flows deterministically: recorded auth workflows, DOM
 * snapshots containing password fields, and login-shaped recorded requests.
 * Produces session-initialization requirements per identity — the
 * prerequisite for identity differential testing (§19).
 */
import type { Repositories } from '@aegis/database';

export interface AuthFlowFinding {
  kind: 'RECORDED_WORKFLOW' | 'LOGIN_FORM' | 'LOGIN_REQUEST';
  reference: string;
  url: string | null;
  identityIds: string[];
  note: string;
}

export interface SessionRequirement {
  identityId: string;
  identityName: string;
  hasAuthMaterial: boolean;
  required: boolean;
  reason: string;
}

export class AuthDiscovery {
  constructor(private readonly repos: Repositories) {}

  /** Detect authentication surfaces from recorded evidence (§10). */
  async detectFlows(engagementId: string): Promise<AuthFlowFinding[]> {
    const findings: AuthFlowFinding[] = [];

    const workflows = await this.repos.authWorkflows.listByEngagement(engagementId);
    for (const workflow of workflows) {
      const steps = Array.isArray(workflow.steps) ? (workflow.steps as Array<Record<string, unknown>>) : [];
      const navigate = steps.find((step) => String(step.action ?? '') === 'navigate');
      findings.push({
        kind: 'RECORDED_WORKFLOW',
        reference: String(workflow.id),
        url: navigate && typeof navigate.detail === 'string' ? navigate.detail : null,
        identityIds: workflow.identity_id ? [String(workflow.identity_id)] : [],
        note: 'Recorded authentication workflow with captured session material',
      });
    }

    const snapshots = await this.repos.domSnapshots.listByEngagement(engagementId, 40);
    for (const snapshot of snapshots) {
      const structured = snapshot.snapshot as Record<string, unknown> | null;
      if (!structured) continue;
      const inputs = Array.isArray(structured.inputs) ? (structured.inputs as Array<Record<string, unknown>>) : [];
      const hasPassword = inputs.some((input) => String(input.type ?? '') === 'password');
      if (hasPassword) {
        findings.push({
          kind: 'LOGIN_FORM',
          reference: String(snapshot.id),
          url: typeof snapshot.url === 'string' ? snapshot.url : null,
          identityIds: [],
          note: 'DOM snapshot contains a password input — login flow candidate',
        });
      }
    }
    return findings.slice(0, 40);
  }

  /**
   * Session requirements per identity (§9 Initialize Sessions): identities
   * WITHOUT an active session need one before identity differentials run.
   */
  async sessionRequirements(engagementId: string): Promise<SessionRequirement[]> {
    const identities = await this.repos.identities.listByEngagement(engagementId);
    const out: SessionRequirement[] = [];
    for (const identity of identities) {
      if (identity.type === 'ANONYMOUS') continue;
      const session = await this.repos.sessions.findActiveByIdentity(identity.id);
      const hasAuthMaterial = session !== null;
      out.push({
        identityId: identity.id,
        identityName: identity.name,
        hasAuthMaterial,
        required: !hasAuthMaterial,
        reason: hasAuthMaterial
          ? 'Active session exists; ready for identity differential tests'
          : 'No active session: initialize via the login workflow before identity differentials (§19)',
      });
    }
    return out;
  }
}
