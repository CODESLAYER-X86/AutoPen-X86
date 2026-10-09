/**
 * Human review service (spec Part 7 §67-§68).
 *
 * Accept / Reject / Modify / Request retest / Mark duplicate / Change
 * severity / Add remediation. Human changes are AUDITED and never silently
 * overwrite the agent's original conclusion: agent_status + human decision +
 * resulting status are all stored. Disagreements become machine-usable
 * feedback data (§68).
 */
import type { EventBus } from '@aegis/events';
import type { PlatformEvent } from '@aegis/contracts';
import { generateId, NotFoundError, ValidationError } from '@aegis/shared';
import type { Repositories } from '@aegis/database';
import type { FindingRecord, FindingReviewRecord } from '@aegis/database';
import { canTransition } from '../findings/finding-lifecycle.js';

export interface ReviewInput {
  decision:
    | 'ACCEPT'
    | 'REJECT'
    | 'MODIFY'
    | 'REQUEST_RETEST'
    | 'MARK_DUPLICATE'
    | 'CHANGE_SEVERITY'
    | 'ADD_REMEDIATION';
  reviewer: string;
  reason: string;
  severity?: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  remediation?: string;
  duplicateOf?: string;
}

export class ReviewService {
  constructor(
    private readonly deps: { repos: Repositories; eventBus: EventBus },
  ) {}

  /** §67: record a human review; transition the finding accordingly. */
  async review(engagementId: string, findingId: string, input: ReviewInput): Promise<{
    finding: FindingRecord;
    review: FindingReviewRecord;
  }> {
    const finding = await this.deps.repos.findings.findByIdAndEngagement(findingId, engagementId);
    if (!finding) throw new NotFoundError('Finding not found for this engagement', 'FINDING_NOT_FOUND');
    if (!input.reviewer || input.reviewer.trim().length === 0) {
      throw new ValidationError('Reviewer identity is required (§67 auditable review)', 'REVIEWER_REQUIRED');
    }

    const agentStatus = finding.status;
    const agentConfidence = finding.confidence;
    let resultingStatus = finding.status;
    const metadata: Record<string, unknown> = {};

    switch (input.decision) {
      case 'ACCEPT':
        resultingStatus = 'ACCEPTED';
        break;
      case 'REJECT':
        resultingStatus = 'REJECTED';
        break;
      case 'MARK_DUPLICATE': {
        if (!input.duplicateOf) {
          throw new ValidationError('MARK_DUPLICATE requires duplicate_of', 'DUPLICATE_TARGET_REQUIRED');
        }
        const target = await this.deps.repos.findings.findByIdAndEngagement(input.duplicateOf, engagementId);
        if (!target) {
          throw new NotFoundError('Duplicate target finding not found', 'FINDING_NOT_FOUND');
        }
        await this.deps.repos.findings.markDuplicate(finding.id, target.id, finding.affected_endpoints);
        resultingStatus = 'DUPLICATE';
        metadata.duplicate_of = target.id;
        break;
      }
      case 'CHANGE_SEVERITY': {
        if (!input.severity) {
          throw new ValidationError('CHANGE_SEVERITY requires severity', 'SEVERITY_REQUIRED');
        }
        await this.deps.repos.severityAssessments.create(
          engagementId,
          finding.id,
          { human_decision: input.decision, reason: input.reason, previous_severity: finding.severity },
          input.severity,
          {
            version: '3.1',
            vector: finding.cvss?.vector ?? 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N',
            base_score: finding.cvss?.base_score ?? 0,
            temporal_score: null,
            environmental_score: null,
            base_severity: finding.cvss?.base_severity ?? 'NONE',
          },
          'HUMAN_OVERRIDE',
        );
        await this.deps.repos.findings.applyCvss(finding.id, {
          version: '3.1',
          vector: finding.cvss?.vector ?? 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N',
          baseScore: finding.cvss?.base_score ?? 0,
          temporalScore: null,
          environmentalScore: null,
          baseSeverity: finding.cvss?.base_severity ?? 'NONE',
          severity: input.severity,
          source: 'HUMAN_OVERRIDE',
        });
        metadata.severity_changed_to = input.severity;
        resultingStatus = finding.status;
        break;
      }
      case 'ADD_REMEDIATION': {
        if (!input.remediation || input.remediation.length < 8) {
          throw new ValidationError('ADD_REMEDIATION requires a remediation text', 'REMEDIATION_REQUIRED');
        }
        await this.deps.repos.findings.enrich(finding.id, { remediation: input.remediation });
        metadata.remediation_added = true;
        break;
      }
      case 'REQUEST_RETEST': {
        const existing = await this.deps.repos.retests.findOpen(engagementId, finding.id);
        if (!existing) {
          await this.deps.repos.retests.open(engagementId, finding.id, input.reviewer, input.reason);
        }
        await this.deps.repos.findings.setRetestState(finding.id, 'OPEN');
        resultingStatus = finding.status;
        break;
      }
      case 'MODIFY':
        resultingStatus = finding.status;
        break;
    }

    // Guarded lifecycle transition (§5) for status-changing decisions.
    if (resultingStatus !== finding.status) {
      if (!canTransition(finding.status, resultingStatus)) {
        throw new ValidationError(
          `Human decision ${input.decision} would cause an illegal transition ${finding.status} -> ${resultingStatus}`,
          'FINDING_ILLEGAL_TRANSITION',
        );
      }
      await this.deps.repos.findings.updateStatus(finding.id, resultingStatus as FindingRecord['status']);
      await this.deps.repos.findings.recordLifecycleEvent(
        finding.id,
        engagementId,
        finding.status,
        resultingStatus,
        `human review (${input.decision}): ${input.reason.slice(0, 300)}`,
        'HUMAN',
      );
    }

    // §68: machine-usable disagreement signal.
    const disagreement =
      (input.decision === 'REJECT' && (agentStatus === 'VERIFIED' || agentStatus === 'ACCEPTED')) ||
      (input.decision === 'ACCEPT' && agentStatus === 'REJECTED') ||
      (input.decision === 'CHANGE_SEVERITY' && Boolean(input.severity) && input.severity !== finding.severity);

    const review = await this.deps.repos.findingReviews.create({
      engagementId,
      findingId,
      agentStatus,
      agentConfidence,
      decision: input.decision,
      reviewer: input.reviewer,
      reason: input.reason,
      agentHumanDisagreement: disagreement,
      resultingStatus,
      metadata,
    });

    await this.publish(engagementId, 'HUMAN_REVIEW_RECORDED', {
      finding_id: finding.id,
      decision: input.decision,
      agent_status: agentStatus,
      resulting_status: resultingStatus,
      disagreement,
      reviewer: input.reviewer,
    });
    if (input.decision === 'REQUEST_RETEST') {
      await this.publish(engagementId, 'RETEST_REQUESTED', { finding_id: finding.id, reviewer: input.reviewer });
    }

    const updated = (await this.deps.repos.findings.findByIdAndEngagement(finding.id, engagementId)) ?? finding;
    return { finding: updated, review };
  }

  /** §68: disagreement feed for verification-engine improvement. */
  async feedbackLoop(engagementId: string): Promise<Array<{
    finding_id: string;
    agent_conclusion: string;
    human_conclusion: string;
    difference: string;
    reason: string;
  }>> {
    const reviews = await this.deps.repos.findingReviews.listByEngagement(engagementId, 500);
    return reviews
      .filter((r) => r.agent_human_disagreement)
      .map((r) => ({
        finding_id: r.finding_id,
        agent_conclusion: r.agent_status,
        human_conclusion: r.decision,
        difference: `${r.agent_status} -> ${r.resulting_status}`,
        reason: r.reason,
      }));
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
