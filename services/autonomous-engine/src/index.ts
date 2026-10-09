/**
 * @aegis/autonomous — the Autonomous Pentest & CTF Engine (Part 6).
 *
 * A persistent, restartable engine that combines the Agent OS (Part 2),
 * browser/HTTP infrastructure (Part 3), the attack-surface graph and
 * hypothesis machinery (Part 4), the security knowledge system (Part 5),
 * the evidence vault, verification, multi-identity sessions, CTF reasoning
 * and resource/quota management into one event-driven loop:
 *
 *   OBSERVE -> MODEL -> HYPOTHESIZE -> PRIORITIZE -> PLAN -> VALIDATE ->
 *   EXECUTE -> OBSERVE -> COMPARE -> VERIFY -> UPDATE -> REPLAN
 *
 * The engine is DOMAIN-AWARE but EXECUTION-AGNOSTIC (§90) and MODEL-FREE
 * in its deterministic layers: candidates, differentials, verification and
 * stop decisions are computed by code; the strategic model decides
 * priorities through the validated Part 2 decision path (§47).
 */
export * from './engine/state-machine.js';
export * from './engine/lifecycle-manager.js';
export * from './engine/loop-controller.js';
export * from './engine/ports.js';
export * from './engine/engagement-engine.js';
export * from './reconnaissance/recon-planner.js';
export * from './reconnaissance/asset-discovery.js';
export * from './reconnaissance/endpoint-discovery.js';
export * from './reconnaissance/parameter-discovery.js';
export * from './reconnaissance/auth-discovery.js';
export * from './reconnaissance/workflow-discovery.js';
export * from './reconnaissance/technology-fingerprint.js';
export * from './reasoning/hypothesis-engine.js';
export * from './reasoning/hypothesis-prioritizer.js';
export * from './reasoning/strategy-engine.js';
export * from './reasoning/branch-manager.js';
export * from './reasoning/anomaly-analyzer.js';
export * from './reasoning/projection-types.js';
export * from './planning/task-planner.js';
export * from './planning/dependency-planner.js';
export * from './planning/cost-estimator.js';
export * from './execution/execution-controller.js';
export * from './execution/worker-dispatcher.js';
export * from './execution/retry-manager.js';
export * from './execution/recovery-manager.js';
export * from './analysis/observation-analyzer.js';
export * from './analysis/differential-engine.js';
export * from './analysis/dataflow-analyzer.js';
export * from './analysis/state-analyzer.js';
export * from './analysis/evidence-correlator.js';
export * from './verification/verifier.js';
export * from './verification/confidence-engine.js';
export * from './verification/false-positive-filter.js';
export * from './verification/reproduction-engine.js';
export * from './ctf/ctf-engine.js';
export * from './ctf/clue-analyzer.js';
export * from './ctf/riddle-engine.js';
export * from './ctf/flag-condition-analyzer.js';
export * from './ctf/challenge-memory.js';
export * from './stopping/stop-evaluator.js';
export * from './stopping/budget-evaluator.js';
export * from './stopping/coverage-evaluator.js';
export * from './graph/attack-surface-graph.js';
export * from './timeline/timeline-builder.js';
export * from './eval/benchmarks.js';
export * from './eval/benchmark-runner.js';
