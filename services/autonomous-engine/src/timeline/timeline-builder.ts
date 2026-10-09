/**
 * Live agent timeline (spec Part 6 §53, §85).
 *
 * Renders the audit chain from persisted events — the same chain that
 * connects decision -> task -> worker -> tool call -> observation ->
 * hypothesis -> evidence -> verification -> finding (§85). The timeline
 * makes the agent's reasoning AUDITABLE (§53 example feed).
 */
import type { Repositories } from '@aegis/database';
import type { Timeline, TimelineEntry } from '@aegis/contracts';

/** Events rendered on the live timeline, with human-readable summaries. */
const TIMELINE_EVENT_SUMMARIES: Record<string, (payload: Record<string, unknown>) => string> = {
  ENGAGEMENT_STARTED: () => 'Engagement started',
  AUTONOMOUS_ENGINE_STARTED: () => 'Autonomous engine started',
  AUTONOMOUS_PHASE_CHANGED: (p) => `Phase: ${String(p.from ?? '?')} -> ${String(p.to ?? '?')}`,
  RECON_PIPELINE_STARTED: () => 'Reconnaissance pipeline started',
  RECON_TASK_PLANNED: (p) => `Recon stage planned: ${String(p.stage ?? '')} (${Number(p.tasks ?? 0)} tasks)`,
  RECON_PIPELINE_COMPLETED: () => 'Reconnaissance baseline established',
  ENDPOINT_DISCOVERED: (p) => `Discovered endpoint ${String(p.canonical_path ?? p.path ?? '')}`,
  PARAMETER_OBSERVED: (p) => `Parameter observed: ${String(p.name ?? '')} (${String(p.location ?? '')})`,
  SECURITY_SIGNAL_GENERATED: (p) => `Security signal: ${String(p.signal_type ?? '')}`,
  HYPOTHESIS_CREATED: (p) => `Hypothesis created: ${String(p.statement ?? p.id ?? '').slice(0, 120)}`,
  HYPOTHESIS_CANDIDATES_CONSUMED: (p) => `Consumed ${Number(p.hypotheses ?? 0)} hypothesis candidates (${Number(p.competitors ?? 0)} competitors preserved)`,
  REASONING_BRANCH_CREATED: (p) => `Branch created: ${String(p.focus ?? '').slice(0, 100)}`,
  REASONING_BRANCH_PRUNED: (p) => `Branch pruned (${String(p.reason ?? '')})`,
  TEST_CANDIDATES_COMPILED: (p) => `Compiled ${Number(p.count ?? 0)} test candidates`,
  TASK_CREATED: (p) => `Task created: ${String(p.type ?? '')}`,
  TASK_DISPATCHED: (p) => `Task dispatched to ${String(p.worker_type ?? 'worker')}`,
  TASK_COMPLETED: (p) => `Task completed (${Number(p.observations ?? 0)} observations)`,
  TASK_FAILED: (p) => `Task failed: ${String(p.code ?? '')}`,
  TASK_LEASE_EXPIRED: (p) => `Task lease expired; recovery policy applied (${Number(p.expired ?? 0)})`,
  AUTONOMOUS_RECOVERY_COMPLETED: (p) => `Crash recovery: ${Number(p.recovered ?? 0)} tasks recovered`,
  DIFFERENTIAL_COMPARISON_RECORDED: (p) => `Differential recorded: ${String(p.verdict ?? '')}`,
  DIFFERENTIAL_AUTO_REQUESTED: (p) => `Auto differential: verdict ${String(p.verdict ?? '')}`,
  VERIFICATION_REQUESTED: (p) => `Verification requested for ${String(p.hypothesis_id ?? '')}`,
  VERIFICATION_COMPLETED: (p) => `Verification completed: ${String(p.status ?? '')}`,
  VERIFICATION_BRIDGE_APPLIED: (p) => `Verdict applied: ${String(p.applied ?? '')} (${String(p.verdict ?? '')})`,
  HYPOTHESIS_CONFIRMED: (p) => `Hypothesis CONFIRMED: ${String(p.hypothesis_id ?? '')}`,
  HYPOTHESIS_DISPROVED: (p) => `Hypothesis disproved: ${String(p.hypothesis_id ?? '')}`,
  FINDING_CREATED: (p) => `Finding created: ${String(p.title ?? '').slice(0, 120)}`,
  FINDING_VERIFIED: (p) => `Finding verified: ${String(p.finding_id ?? p.id ?? '')}`,
  FINDING_CONFIDENCE_COMPUTED: (p) => `Finding confidence ${String(p.level ?? '')} (${Number(p.confidence ?? 0)})`,
  DEAD_END_RECORDED: () => 'Dead end recorded (negative memory, §39)',
  APPROVAL_REQUESTED: (p) => `Approval required (${String(p.risk ?? 'HIGH')} risk): ${String(p.action_summary ?? '').slice(0, 120)}`,
  APPROVAL_DECIDED: (p) => `Approval ${String(p.decision ?? '')}`,
  CTF_CONTEXT_CREATED: (p) => `CTF challenge loaded: ${String(p.title ?? '')}`,
  CTF_CLUE_ANALYZED: (p) => {
    const raw = (p as Record<string, unknown>).interpretations;
    const count = Array.isArray(raw) ? raw.length : 0;
    return `Clue analyzed (${count} interpretations)`;
  },
  FLAG_CONDITION_HYPOTHESIZED: (p) => `Flag condition hypothesized (${String(p.pattern ?? '')})`,
  FLAG_DETECTED: () => 'Flag pattern DETECTED',
  CHALLENGE_SOLVED: () => 'Challenge SOLVED (success condition verified, §31)',
  COVERAGE_UPDATED: (p) => `Coverage: endpoints ${Number(p.endpoint_coverage ?? 0)}, identities ${Number(p.identity_coverage ?? 0)}`,
  BUDGET_THRESHOLD_EXCEEDED: (p) => `Budget near limit: ${String(p.fields ?? '')}`,
  REPLAN_REQUESTED: (p) => `Replan requested (${String(p.trigger ?? '')})`,
  STOP_CONDITION_MET: (p) => `Stop condition: ${String(p.reason ?? '')} — ${String(p.detail ?? '')}`,
  AUTONOMOUS_ENGINE_STOPPED: (p) => `Engine stopped: ${String(p.reason ?? '')}`,
  KNOWLEDGE_QUERY: (p) => `Knowledge query: ${String(p.query ?? '').slice(0, 100)}`,
  OSCILLATION_DETECTED: () => 'Oscillation detected — branch paused (§41)',
  LOOP_PROTECTION_TRIGGERED: () => 'Loop protection triggered (§40)',
};

export class TimelineBuilder {
  constructor(private readonly repos: Repositories) {}

  /** Build the live timeline (§53) from persisted engagement events. */
  async build(engagementId: string, limit = 200): Promise<Timeline> {
    const events = await this.repos.events.listByEngagement(engagementId, Math.min(Math.max(limit, 1), 500));
    const entries: TimelineEntry[] = [];

    for (const event of events) {
      const summarizer = TIMELINE_EVENT_SUMMARIES[event.type];
      if (!summarizer) continue; // only meaningful transitions (§53)
      const payload = (event.payload ?? {}) as Record<string, unknown>;
      entries.push({
        event_id: event.id,
        occurred_at: event.occurred_at,
        type: event.type,
        phase: typeof payload.phase === 'string' ? payload.phase : null,
        summary: summarizer(payload).slice(0, 1000),
        refs: {
          ...(event.task_id ? { task_id: event.task_id } : {}),
          ...(typeof payload.hypothesis_id === 'string' ? { hypothesis_id: payload.hypothesis_id } : {}),
          ...(typeof payload.finding_id === 'string' ? { finding_id: payload.finding_id } : {}),
          ...(typeof payload.verification_id === 'string' ? { verification_id: payload.verification_id } : {}),
          ...(event.trace_id ? { trace_id: event.trace_id } : {}),
        },
      });
    }

    // Events are newest-first from the repo; the timeline renders oldest-first.
    entries.reverse();
    return { engagement_id: engagementId, entries, total: entries.length };
  }
}
