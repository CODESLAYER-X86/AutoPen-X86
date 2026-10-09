/**
 * Retest service (spec Part 7 §37-§38).
 *
 * A retest re-verifies the SECURITY PROPERTY (the same verification plan
 * strategy against the current target state), never a raw request replay.
 * Outcomes: FIXED / PARTIALLY_FIXED / STILL_PRESENT; original finding
 * history is preserved; the finding's retest_state stays in sync (§38).
 */
import type { EventBus } from '@aegis/events';
import type { PlatformEvent } from '@aegis/contracts';
import { generateId, NotFoundError, ValidationError } from '@aegis/shared';
import type { Repositories } from '@aegis/database';
import type { FindingRecord, RetestRecord, VerificationResultRecord } from '@aegis/database';
import { Verifier } from '../verification/verifier.js';

export class RetestService {
  constructor(
    private readonly deps: {
      repos: Repositories;
      eventBus: EventBus;
      verifier: Verifier;
    },
  ) {}

  /** §37: run the retest for the OPEN retest of a finding. */
  async retest(engagementId: string, findingId: string, actor: string): Promise<{
    retest: RetestRecord;
    result: VerificationResultRecord;
    finding: FindingRecord;
  }> {
    const finding = await this.deps.repos.findings.findByIdAndEngagement(findingId, engagementId);
    if (!finding) throw new NotFoundError('Finding not found for this engagement', 'FINDING_NOT_FOUND');

    const open = await this.deps.repos.retests.findOpen(engagementId, findingId);
    if (!open) {
      throw new ValidationError('No OPEN retest for this finding; request one first (§37)', 'RETEST_NOT_OPEN');
    }

    // Same verification, current state: the verifier re-plans and re-executes
    // against the CURRENT matrix/evidence — the security property, not the
    // literal original request (§37).
    const verifyResult = await this.deps.verifier.verifyFinding(engagementId, finding, {});

    // Compare: previous verdict vs the fresh one.
    const previous = await this.deps.repos.verificationResults.listByFinding(engagementId, findingId);
    const priorVerdict = previous.find((r) => r.id !== verifyResult.result.id)?.status ?? finding.status;
    const fresh = verifyResult.result.status;

    // §37 outcome mapping.
    let outcome: 'FIXED' | 'PARTIALLY_FIXED' | 'STILL_PRESENT';
    if (priorVerdict === 'VERIFIED' && fresh === 'REJECTED') {
      outcome = 'FIXED';
    } else if (priorVerdict === 'VERIFIED' && fresh === 'INCONCLUSIVE') {
      outcome = 'PARTIALLY_FIXED';
    } else if (priorVerdict === 'REJECTED' && fresh === 'VERIFIED') {
      outcome = 'STILL_PRESENT';
    } else if (fresh === 'VERIFIED') {
      outcome = 'STILL_PRESENT';
    } else if (fresh === 'INCONCLUSIVE') {
      outcome = 'PARTIALLY_FIXED';
    } else {
      outcome = 'FIXED';
    }

    const retest = await this.deps.repos.retests.complete(
      open.id,
      engagementId,
      outcome,
      verifyResult.result.id,
      `retest executed the same verification strategy (§37): prior=${priorVerdict} fresh=${fresh} -> ${outcome}`,
    );
    if (!retest) {
      throw new ValidationError('Retest was already completed (single completion, §37)', 'RETEST_ALREADY_COMPLETED');
    }
    await this.deps.repos.findings.setRetestState(findingId, outcome);

    const updated = (await this.deps.repos.findings.findByIdAndEngagement(findingId, engagementId)) ?? finding;
    await this.publish(engagementId, 'RETEST_COMPLETED', {
      finding_id: findingId,
      retest_id: retest.id,
      outcome,
      prior_verdict: priorVerdict,
      fresh_verdict: fresh,
      verification_id: verifyResult.result.id,
    });
    void actor;
    return { retest, result: verifyResult.result, finding: updated };
  }

  /** §37: request a retest (opens the workflow). */
  async request(engagementId: string, findingId: string, requestedBy: string, note?: string): Promise<RetestRecord> {
    const finding = await this.deps.repos.findings.findByIdAndEngagement(findingId, engagementId);
    if (!finding) throw new NotFoundError('Finding not found for this engagement', 'FINDING_NOT_FOUND');
    const existing = await this.deps.repos.retests.findOpen(engagementId, findingId);
    if (existing) return existing;
    const retest = await this.deps.repos.retests.open(engagementId, findingId, requestedBy, note ?? null);
    await this.deps.repos.findings.setRetestState(findingId, 'OPEN');
    await this.publish(engagementId, 'RETEST_REQUESTED', {
      finding_id: findingId,
      retest_id: retest.id,
      requested_by: requestedBy,
    });
    return retest;
  }

  async list(engagementId: string): Promise<RetestRecord[]> {
    return this.deps.repos.retests.listByEngagement(engagementId);
  }

  private async publish(engagementId: string, type: string, payload: Record<string, unknown>): Promise<void> {
    const event: PlatformEvent = {
      type: type as PlatformEvent['type'],
      engagement_id: engagementId,
      trace_id: generateId('TRC'),
      actor_id: null,
      payload,
      occurred_at: new Date().toISOString(),
      dedup_key: `vr:${type}:${engagementId}:${payload.finding_id ?? ''}:${Date.now()}`,
    };
    await this.deps.eventBus.publish(event).catch(() => undefined);
  }
}
