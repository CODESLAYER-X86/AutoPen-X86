/**
 * Cost estimator (spec Part 6 §17, §42-§43).
 *
 * Deterministic cost model for planned tests: base cost per worker type,
 * scaled by tool budget, mutation count and response sizes. Normalized to
 * [0, 1] — cheaper tests rank ahead of expensive ones at equal value.
 */
import type { TestCandidate } from '@aegis/contracts';

const WORKER_BASE_COST: Record<string, number> = {
  ANALYSIS_WORKER: 0.1,
  HTTP_WORKER: 0.15,
  SOURCE_WORKER: 0.15,
  BROWSER_WORKER: 0.45,
};

export interface CostEstimate {
  cost: number;
  components: {
    workerBase: number;
    mutations: number;
    toolBudget: number;
    responseSize: number;
  };
}

export function estimateCandidateCost(candidate: TestCandidate): CostEstimate {
  const workerBase: number = WORKER_BASE_COST.HTTP_WORKER ?? 0.25;
  const mutations = Math.min(0.2, candidate.mutations.length * 0.05);
  const toolBudget = Math.min(0.15, candidate.estimated_cost / 64);
  const responseSize = 0.05;
  const cost = Math.max(0.05, Math.min(1, workerBase + mutations + toolBudget + responseSize));
  return { cost, components: { workerBase, mutations, toolBudget, responseSize } };
}

export function estimateTaskCost(workerType: string, toolCalls: number, hasNetwork: boolean): number {
  const base: number = WORKER_BASE_COST[workerType] ?? 0.3;
  const tools = Math.min(0.3, toolCalls * 0.03);
  const network = hasNetwork ? 0.1 : 0;
  return Math.max(0.05, Math.min(1, base + tools + network));
}

/** Model-efficiency gate (§43): cheap candidate first. */
export function candidateIsCheap(candidate: TestCandidate): boolean {
  return estimateCandidateCost(candidate).cost <= 0.35;
}
