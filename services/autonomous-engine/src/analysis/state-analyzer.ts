/**
 * State analyzer (spec Part 6 §21-§22).
 *
 * Generates workflow/state QUESTIONS from reconstructed workflows (§21):
 * can step B happen before A? can C happen twice? can a completed action be
 * repeated? can a cancelled action be resumed? can a state transition be
 * skipped? can two identities continue the same workflow?
 *
 * Questions become bounded test-candidate suggestions the planner may
 * compile — always through the structured mutation path.
 */
import type { Repositories } from '@aegis/database';

export interface WorkflowQuestion {
  workflowId: string;
  workflowName: string;
  question: string;
  kind: 'ORDER_INVERSION' | 'REPEAT' | 'SKIP' | 'RESUME' | 'CROSS_IDENTITY';
  fromState: string | null;
  toState: string | null;
  expectedInformationGain: number;
  rationale: string;
}

export class StateAnalyzer {
  constructor(private readonly repos: Repositories) {}

  /** Generate workflow-order questions from observed state machines (§21). */
  async questions(engagementId: string): Promise<WorkflowQuestion[]> {
    const workflows = await this.repos.workflows.listByEngagement(engagementId);
    const out: WorkflowQuestion[] = [];

    for (const workflow of workflows.slice(0, 6)) {
      const transitions = await this.repos.workflowTransitions.listByEngagement(engagementId, 500);
      const mine = transitions.filter((t) => t.workflow_id === workflow.id);
      const states = await this.repos.workflowStates.listByWorkflow(workflow.id);

      if (states.length < 2) continue;

      // Order inversion: for each non-first state, ask whether it can fire
      // before its predecessor completed (§21 "Can step B happen before A?").
      for (let i = 1; i < Math.min(states.length, 6); i += 1) {
        const previous = states[i - 1]!;
        const current = states[i]!;
        out.push({
          workflowId: workflow.id,
          workflowName: workflow.name,
          question: `Can state "${current.name}" be reached before "${previous.name}" completes (workflow order inversion)?`,
          kind: 'ORDER_INVERSION',
          fromState: previous.name,
          toState: current.name,
          expectedInformationGain: 0.55,
          rationale: 'Workflow order questions expose missing server-side state validation (§21).',
        });
      }

      // Repeat: can the terminal transition happen twice (§21)?
      const terminal = states[states.length - 1]!;
      out.push({
        workflowId: workflow.id,
        workflowName: workflow.name,
        question: `Can the terminal action for state "${terminal.name}" be repeated after completion?`,
        kind: 'REPEAT',
        fromState: terminal.name,
        toState: null,
        expectedInformationGain: 0.5,
        rationale: 'Repeated completed actions expose idempotency/business-logic flaws (§21).',
      });

      // Cross-identity continuation (§21).
      const identityTransitions = mine.filter((t) => t.identity_id !== null);
      const distinct = new Set(identityTransitions.map((t) => t.identity_id));
      if (distinct.size >= 1) {
        out.push({
          workflowId: workflow.id,
          workflowName: workflow.name,
          question: 'Can two identities continue the same workflow instance (cross-identity state continuation)?',
          kind: 'CROSS_IDENTITY',
          fromState: null,
          toState: null,
          expectedInformationGain: 0.6,
          rationale: 'Workflow state must be identity-scoped; cross-identity continuation is an authorization flaw (§21).',
        });
      }
    }
    return out.slice(0, 20);
  }

  /** Record the exact state transition that produced an observation (§21). */
  describeTransition(workflowId: string, fromState: string | null, action: string, toState: string | null): string {
    return `${fromState ?? 'START'} --[${action}]--> ${toState ?? 'END'} (workflow ${workflowId})`;
  }
}
