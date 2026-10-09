/**
 * Workflow discovery (spec Part 6 §9, §21).
 *
 * Plans flow-exercise tasks so observed traffic exercises multi-step
 * workflows (login -> create -> edit -> submit -> confirm). The Part 4
 * reasoning engine then reconstructs the state machine from that traffic;
 * the state analyzer generates workflow-order questions (§21).
 */
import type { Repositories, TargetRecord } from '@aegis/database';
import { reconFingerprint } from './recon-planner.js';

export interface WorkflowExercisePlan {
  target: TargetRecord;
  baseUrl: string;
  objective: string;
  reason: string;
  fingerprint: string;
}

export class WorkflowDiscovery {
  constructor(private readonly repos: Repositories) {}

  /**
   * Plan workflow-exercise recon tasks for forms whose action endpoints look
   * multi-step (workflows already reconstructed take priority — deepen by
   * re-exercising their observed transitions, §21).
   */
  async exercisePlans(engagementId: string, targets: TargetRecord[]): Promise<WorkflowExercisePlan[]> {
    const plans: WorkflowExercisePlan[] = [];
    const workflows = await this.repos.workflows.listByEngagement(engagementId);

    if (workflows.length > 0) {
      // Deepen observed workflows: re-exercise the observed transition order
      // so state transitions are observed with fresh evidence.
      for (const workflow of workflows.slice(0, 4)) {
        const target = this.matchTarget(targets, workflow.required_identity ?? null);
        plans.push({
          target,
          baseUrl: this.baseUrl(target),
          objective: `Exercise the observed workflow "${workflow.name}" end-to-end in its documented order to generate fresh state-transition evidence for every step.`,
          reason: 'Workflow reconstruction exists; exercising it produces verified transition evidence (§21).',
          fingerprint: reconFingerprint(engagementId, 'workflow-exercise', workflow.id),
        });
      }
      return plans.slice(0, 4);
    }

    // No reconstructed workflows yet: exercise discovered forms in sequence.
    for (const target of targets.slice(0, 2)) {
      plans.push({
        target,
        baseUrl: this.baseUrl(target),
        objective: `Exercise the application at ${this.baseUrl(target)} as a normal user would: walk discovered links, fill and submit any forms (including the login form with provided credentials), follow the resulting flows, and record each step so the workflow state machine can be reconstructed.`,
        reason: 'No workflows reconstructed yet; form-driven exercise generates the traffic the reasoning engine needs (§9 workflow discovery).',
        fingerprint: reconFingerprint(engagementId, 'workflow-exercise', target.id),
      });
    }
    return plans;
  }

  private matchTarget(targets: TargetRecord[], _identity: string | null): TargetRecord {
    return targets[0]!;
  }

  private baseUrl(target: TargetRecord): string {
    const value = target.value.trim();
    if (/^https?:\/\//i.test(value)) return value.replace(/\/+$/, '');
    return `http://${value.replace(/\/+$/, '')}`;
  }
}
