/**
 * Verification, Reporting & Evaluation engine (spec Part 7) — facade.
 *
 *   OBSERVATION -> HYPOTHESIS -> TEST -> EVIDENCE -> VERIFICATION ->
 *   CONFIDENCE -> FINDING -> REPORT
 *
 * Composes the deterministic verification pipeline (§2-§24), the finding
 * lifecycle (§4-§20), report generation (§25-§66), human review/retest
 * (§67-§38) and the evaluation system (§39-§92). OBSERVED TRUTH, INFERRED
 * TRUTH and REPORTED TRUTH are never conflated (§101).
 */
import type { EngineDeps } from './ports.js';
import { FindingService } from './findings/finding-service.js';
import { Verifier } from './verification/verifier.js';
import { ReportBuilder } from './reporting/report-builder.js';
import { ReviewService } from './human/review-service.js';
import { RetestService } from './human/retest-service.js';
import { BenchmarkEngine } from './evaluation/benchmark-engine.js';
import { RegressionEngine } from './evaluation/regression-engine.js';

export { FindingService } from './findings/finding-service.js';
export { Verifier } from './verification/verifier.js';
export { ReportBuilder } from './reporting/report-builder.js';
export { ReviewService } from './human/review-service.js';
export { RetestService } from './human/retest-service.js';
export { BenchmarkEngine } from './evaluation/benchmark-engine.js';
export { RegressionEngine } from './evaluation/regression-engine.js';
export { FINDING_TRANSITIONS, verdictToStatus, canTransition, isTerminal } from './findings/finding-lifecycle.js';
export { SeverityEngine } from './findings/severity-engine.js';
export { ConfidenceEngine } from './findings/confidence-engine.js';
export { FindingDeduplicator, computeDedupKey, normalizeEndpointShape } from './findings/finding-deduplicator.js';
export { VerificationPlanner } from './verification/verification-planner.js';
export { ReproductionEngine } from './verification/reproduction-engine.js';
export { ControlTestEngine } from './verification/control-test-engine.js';
export { AlternativeExplanationEngine } from './verification/alternative-explanation-engine.js';
export { resolvePolicy, evaluatePolicy, CATEGORY_POLICIES } from './verification/verification-policy.js';
export { redactText, containsUnredactedSecret } from './reporting/redaction.js';
export { renderMarkdown, renderJson, renderHtml, renderPdf } from './reporting/exporters/index.js';
export { SCENARIO_SEEDS } from './evaluation/benchmark-engine.js';
export type { ControlledHttpPort, ReasoningVerificationPort, EngineDeps } from './ports.js';

export class VerificationReportingEngine {
  readonly findings: FindingService;
  readonly verifier: Verifier;
  readonly reports: ReportBuilder;
  readonly reviews: ReviewService;
  readonly retests: RetestService;
  readonly benchmarks: BenchmarkEngine;
  readonly regression: RegressionEngine;

  constructor(deps: EngineDeps) {
    const confidenceThresholds = {
      high: deps.config.reporting.confidenceHighThreshold,
      medium: deps.config.reporting.confidenceMediumThreshold,
    };
    this.findings = new FindingService({
      repos: deps.repos,
      eventBus: deps.eventBus,
      confidenceThresholds,
    });
    this.verifier = new Verifier({
      repos: deps.repos,
      eventBus: deps.eventBus,
      http: deps.http,
      reasoning: deps.reasoning,
      confidenceThresholds,
    });
    this.reports = new ReportBuilder({
      repos: deps.repos,
      eventBus: deps.eventBus,
      config: deps.config,
      objectStore: deps.objectStore,
    });
    this.reviews = new ReviewService({ repos: deps.repos, eventBus: deps.eventBus });
    this.retests = new RetestService({ repos: deps.repos, eventBus: deps.eventBus, verifier: this.verifier });
    this.benchmarks = new BenchmarkEngine({
      repos: deps.repos,
      eventBus: deps.eventBus,
      config: deps.config,
      http: deps.http,
      reasoning: deps.reasoning,
      logger: deps.logger,
    });
    this.regression = new RegressionEngine({ repos: deps.repos, config: deps.config });
  }
}
