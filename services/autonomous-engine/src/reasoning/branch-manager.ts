/**
 * Hypothesis branch manager (spec Part 6 §65-§66).
 *
 * Branches group hypotheses that share an interpretation of the evidence.
 * Scoring considers evidence strength, information gain, impact, cost,
 * novelty and remaining uncertainty (§65). Pruning conditions (§66):
 * disproved hypothesis, cost exceeding expected value, contradicting
 * evidence, repeated identical results, duplication, scope. Pruned branches
 * are PRESERVED — never deleted.
 */
import type { Repositories } from '@aegis/database';
import { generateId } from '@aegis/shared';
import type { PlatformEvent } from '@aegis/contracts';
import type { EventBus } from '@aegis/events';

export interface BranchManagerOptions {
  maxActive: number;
}

export interface CreateBranchInput {
  origin: 'SIGNAL' | 'CTF_CLUE' | 'HYPOTHESIS' | 'MANUAL';
  originRef?: string | null;
  focus: string;
  hypothesisIds?: string[];
  metadata?: Record<string, unknown>;
}

export interface BranchScore {
  evidenceStrength: number;
  informationGain: number;
  impact: number;
  cost: number;
  novelty: number;
  remainingUncertainty: number;
}

export class BranchManager {
  constructor(
    private readonly deps: { repos: Repositories; eventBus: EventBus },
    private readonly opts: BranchManagerOptions,
  ) {}

  async createBranch(engagementId: string, input: CreateBranchInput) {
    const active = await this.deps.repos.branches.countByEngagement(engagementId, 'ACTIVE');
    // Limit active branches (§65 anti-explosion). When the budget is hit the
    // LOWEST-scoring active branch is paused (never deleted).
    if (active >= this.opts.maxActive) {
      const actives = await this.deps.repos.branches.listByEngagement(engagementId, ['ACTIVE']);
      const lowest = [...actives].sort((a, b) => a.score - b.score)[0];
      if (lowest) {
        await this.deps.repos.branches.updateStatus(lowest.id, 'PAUSED', 'branch budget: paused lowest-scoring branch');
        await this.publish(engagementId, 'REASONING_BRANCH_PRUNED', { branch_id: lowest.id, reason: 'BRANCH_BUDGET' });
      }
    }
    const branch = await this.deps.repos.branches.create({
      engagementId,
      origin: input.origin,
      originRef: input.originRef ?? null,
      focus: input.focus,
      hypothesisIds: input.hypothesisIds ?? [],
      score: 0.5,
      metadata: input.metadata ?? {},
    });
    await this.publish(engagementId, 'REASONING_BRANCH_CREATED', {
      branch_id: branch.id,
      origin: input.origin,
      focus: input.focus.slice(0, 200),
    });
    return branch;
  }

  async attachHypothesis(branchId: string, hypothesisId: string): Promise<void> {
    await this.deps.repos.branches.attachHypothesis(branchId, hypothesisId);
  }

  /**
   * Rescore a branch from its hypotheses (§65). Evidence strength comes from
   * hypothesis confidence; novelty decays with test count.
   */
  async rescore(engagementId: string, branchId: string): Promise<number> {
    const branch = await this.deps.repos.branches.findById(branchId);
    if (!branch) return 0;
    const hypotheses = await this.deps.repos.hypotheses.listByEngagement(engagementId, { limit: 200 });
    const mine = hypotheses.filter((h) => branch.hypothesis_ids.includes(h.id));
    if (mine.length === 0) {
      await this.deps.repos.branches.updateScore(branchId, branch.score);
      return branch.score;
    }
    const score: BranchScore = {
      evidenceStrength: average(mine.map((h) => h.confidence)),
      informationGain: average(mine.map((h) => h.priority)),
      impact: average(mine.map((h) => (h.status === 'CONFIRMED' || h.status === 'SUPPORTED' ? 0.9 : 0.5))),
      cost: 0.3,
      novelty: mine.some((h) => h.status === 'TESTING') ? 0.7 : 0.5,
      remainingUncertainty: 1 - average(mine.map((h) => h.confidence)),
    };
    const total =
      0.35 * score.evidenceStrength +
      0.2 * score.informationGain +
      0.15 * score.impact +
      0.1 * (1 - score.cost) +
      0.1 * score.novelty +
      0.1 * score.remainingUncertainty;
    const bounded = Math.max(0, Math.min(1, total));
    await this.deps.repos.branches.updateScore(branchId, bounded);
    await this.publish(engagementId, 'REASONING_BRANCH_UPDATED', { branch_id: branchId, score: bounded });
    return bounded;
  }

  /**
   * Prune (§66) — status becomes PRUNED/DISPROVED; history is preserved.
   */
  async prune(
    engagementId: string,
    branchId: string,
    reason: string,
    status: 'PRUNED' | 'DISPROVED' | 'COMPLETED' = 'PRUNED',
  ): Promise<void> {
    await this.deps.repos.branches.updateStatus(branchId, status, reason);
    await this.publish(engagementId, 'REASONING_BRANCH_PRUNED', { branch_id: branchId, reason, status });
  }

  /** Prune branches whose hypotheses are all terminal (§66 evidence contradicts). */
  async pruneDisproved(engagementId: string): Promise<number> {
    const branches = await this.deps.repos.branches.listByEngagement(engagementId, ['ACTIVE', 'PAUSED']);
    const hypotheses = await this.deps.repos.hypotheses.listByEngagement(engagementId, { limit: 300 });
    let pruned = 0;
    for (const branch of branches) {
      const mine = hypotheses.filter((h) => branch.hypothesis_ids.includes(h.id));
      if (mine.length === 0) continue;
      const allDisproved = mine.every((h) => h.status === 'DISPROVED' || h.status === 'ABANDONED');
      const anyConfirmed = mine.some((h) => h.status === 'CONFIRMED');
      if (allDisproved) {
        await this.prune(engagementId, branch.id, 'all hypotheses disproved', 'DISPROVED');
        pruned += 1;
      } else if (anyConfirmed) {
        await this.prune(engagementId, branch.id, 'hypothesis confirmed; branch complete', 'COMPLETED');
        pruned += 1;
      }
    }
    return pruned;
  }

  private async publish(engagementId: string, type: string, payload: Record<string, unknown>): Promise<void> {
    const event: PlatformEvent = {
      type: type as PlatformEvent['type'],
      engagement_id: engagementId,
      trace_id: generateId('TRC'),
      actor_id: null,
      payload,
      occurred_at: new Date().toISOString(),
      dedup_key: `branch:${type}:${engagementId}:${String(payload.branch_id)}:${Date.now()}`,
    };
    await this.deps.eventBus.publish(event).catch(() => undefined);
  }
}

function average(values: number[]): number {
  if (values.length === 0) return 0;
  return values.reduce((sum, value) => sum + value, 0) / values.length;
}
