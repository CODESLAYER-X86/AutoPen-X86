/**
 * Hypothesis bridge (spec Part 6 §14-§16, §38).
 *
 * Converts Part 4 deterministic hypothesis CANDIDATES (from security
 * signals) into real hypotheses through the Part 2 hypothesis engine, and
 * groups them into reasoning branches (§65). Competing hypotheses are
 * preserved (§16: the first plausible hypothesis never dominates
 * automatically — the scheduler prefers tests that DISTINGUISH them).
 *
 * Model-free: candidates are deterministic engine output; the leader
 * prioritizes but cannot silently drop competitors.
 */
import type { Repositories } from '@aegis/database';
import type { PlatformEvent } from '@aegis/contracts';
import type { EventBus } from '@aegis/events';
import type { HypothesisGroup } from '../engine/ports.js';
import { generateId, type HypothesisType } from '@aegis/shared';
import { HypothesisEngine } from '@aegis/agent';
import { BranchManager } from './branch-manager.js';

export interface HypothesisBridgeResult {
  hypothesesCreated: number;
  branchesCreated: number;
  competitorsPreserved: number;
  signalIdsConsumed: string[];
}

/** Map Part 4 candidate types to the Part 2 hypothesis taxonomy. */
const TYPE_MAP: Record<string, HypothesisType> = {
  AUTHORIZATION: 'AUTHORIZATION',
  AUTHENTICATION: 'AUTHENTICATION',
  SESSION: 'SESSION',
  INPUT_VALIDATION: 'INPUT_VALIDATION',
  INJECTION: 'INJECTION',
  CLIENT_SIDE: 'CLIENT_SIDE',
  BUSINESS_LOGIC: 'BUSINESS_LOGIC',
  DATA_EXPOSURE: 'DATA_EXPOSURE',
  CONFIGURATION: 'CONFIGURATION',
  CRYPTOGRAPHIC: 'CRYPTOGRAPHIC',
  RACE_CONDITION: 'RACE_CONDITION',
};

function mapType(candidateType: string): HypothesisType {
  return TYPE_MAP[candidateType] ?? 'UNKNOWN';
}

export interface HypothesisBridgeDeps {
  repos: Repositories;
  eventBus: EventBus;
  hypothesisEngine: HypothesisEngine;
  branchManager: BranchManager;
  /** Cap on hypotheses created per consumption cycle (§65 budgets). */
  maxPerCycle: number;
}

export class HypothesisBridge {
  constructor(private readonly deps: HypothesisBridgeDeps) {}

  /**
   * Consume candidate groups from the reasoning engine (§16). Each group's
   * PRIMARY becomes the branch focus; competitors become SIBLING hypotheses
   * inside the same branch so distinguishing tests score highly (§17).
   */
  async consumeCandidates(
    engagementId: string,
    groups: HypothesisGroup[],
  ): Promise<HypothesisBridgeResult> {
    const result: HypothesisBridgeResult = {
      hypothesesCreated: 0,
      branchesCreated: 0,
      competitorsPreserved: 0,
      signalIdsConsumed: [],
    };
    let budget = this.deps.maxPerCycle;

    for (const group of groups) {
      if (budget <= 0) break;
      const all = [group.primary, ...group.competitors];

      // Branch focus from the primary statement (bounded).
      const branch = await this.deps.branchManager.createBranch(engagementId, {
        origin: 'SIGNAL',
        originRef: group.signalId,
        focus: group.primary.statement.slice(0, 400),
        metadata: {
          signal_type: group.signalType,
          distinguishing_tests: group.distinguishingTests.slice(0, 8),
        },
      });
      result.branchesCreated += 1;

      for (const candidate of all) {
        if (budget <= 0) {
          result.competitorsPreserved += 1;
          continue;
        }
        try {
          const hypothesis = await this.deps.hypothesisEngine.createHypothesis({
            engagementId,
            type: mapType(candidate.type),
            statement: candidate.statement,
            confidence: candidate.initial_confidence,
            priority: candidate.priority,
            source: `reasoning-signal:${group.signalId}`,
          });
          await this.deps.branchManager.attachHypothesis(branch.id, hypothesis.id);
          await this.linkSignalEvidence(engagementId, group.signalId, hypothesis.id);
          budget -= 1;
          if (candidate.competing) result.competitorsPreserved += 1;
        } catch {
          // Branch budget exceeded (Part 2 §22) or contention — the remaining
          // candidates stay available as unconsumed signals.
          break;
        }
      }
      result.signalIdsConsumed.push(group.signalId);
    }

    if (result.hypothesesCreated >= 0 && (result.hypothesesCreated > 0 || result.branchesCreated > 0)) {
      const event: PlatformEvent = {
        type: 'HYPOTHESIS_CANDIDATES_CONSUMED',
        engagement_id: engagementId,
        trace_id: generateId('TRC'),
        actor_id: null,
        payload: {
          hypotheses: result.hypothesesCreated,
          branches: result.branchesCreated,
          competitors: result.competitorsPreserved,
          signals: result.signalIdsConsumed.length,
        },
        occurred_at: new Date().toISOString(),
        dedup_key: `candidates-consumed:${engagementId}:${Date.now()}`,
      };
      await this.deps.eventBus.publish(event).catch(() => undefined);
    }
    return result;
  }

  private async linkSignalEvidence(engagementId: string, signalId: string, hypothesisId: string): Promise<void> {
    const signals = await this.deps.repos.securitySignals
      .listByEngagement(engagementId, { limit: 200 })
      .catch(() => []);
    const signal = signals.find((s) => s.id === signalId);
    if (!signal) return;
    const evidenceIds = (signal.evidence_ids ?? []).slice(0, 8);
    for (const evidenceId of evidenceIds) {
      await this.deps.repos.hypotheses
        .link({ hypothesisId, refType: 'EVIDENCE', refId: evidenceId })
        .catch(() => undefined);
    }
  }
}
