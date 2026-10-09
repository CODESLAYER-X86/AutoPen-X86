/**
 * Verification policy (spec Part 7 §71-§72).
 *
 * Deterministic rules — never model output. Policies differ by finding class:
 * authorization findings require an identity differential; high-severity
 * findings require reproduction AND a control comparison AND a higher
 * confidence threshold before they may be called VERIFIED.
 */

/** Reusable verification strategies (§9), shared across the module. */
export type VerificationStrategy =
  | 'REPRODUCTION'
  | 'CONTROL_COMPARISON'
  | 'IDENTITY_DIFFERENTIAL'
  | 'AUTHENTICATION_DIFFERENTIAL'
  | 'STATE_DIFFERENTIAL'
  | 'SOURCE_CONFIRMATION'
  | 'EVIDENCE_REVIEW'
  | 'ALTERNATIVE_EXPLANATIONS';

export interface VerificationPolicyRule {
  /** Finding categories the rule applies to (empty = default rule). */
  categories: string[];
  minimumEvidence: number;
  requireReproduction: boolean;
  requireControlComparison: boolean;
  requireIdentityDifferential: boolean;
  requireAlternativeElimination: boolean;
  /** §72: high-risk confidence gate before VERIFIED. */
  confidenceThreshold: number;
  strategies: VerificationStrategy[];
  controls: string[];
}

export const DEFAULT_VERIFICATION_POLICY: VerificationPolicyRule = {
  categories: [],
  minimumEvidence: 2,
  requireReproduction: false,
  requireControlComparison: true,
  requireIdentityDifferential: false,
  requireAlternativeElimination: true,
  confidenceThreshold: 0.6,
  strategies: ['REPRODUCTION', 'CONTROL_COMPARISON', 'ALTERNATIVE_EXPLANATIONS'] as VerificationStrategy[],
  controls: ['BASELINE'],
};

/** Class-specific policies (§71: "policies may differ by finding class"). */
export const CATEGORY_POLICIES: VerificationPolicyRule[] = [
  {
    categories: ['AUTHORIZATION', 'AUTHZ', 'BOLA', 'IDOR'],
    minimumEvidence: 3,
    requireReproduction: true,
    requireControlComparison: true,
    requireIdentityDifferential: true,
    requireAlternativeElimination: true,
    confidenceThreshold: 0.7,
    strategies: ['IDENTITY_DIFFERENTIAL', 'REPRODUCTION', 'CONTROL_COMPARISON', 'SOURCE_CONFIRMATION'],
    controls: ['OWNER_OWN_OBJECT', 'OWNER_FOREIGN_OBJECT', 'ANONYMOUS_FOREIGN_OBJECT'],
  },
  {
    categories: ['AUTHENTICATION', 'SESSION'],
    minimumEvidence: 2,
    requireReproduction: true,
    requireControlComparison: true,
    requireIdentityDifferential: false,
    requireAlternativeElimination: true,
    confidenceThreshold: 0.65,
    strategies: ['AUTHENTICATION_DIFFERENTIAL', 'REPRODUCTION', 'CONTROL_COMPARISON'],
    controls: ['ANONYMOUS_BASELINE', 'AUTHENTICATED_BASELINE'],
  },
  {
    categories: ['BUSINESS_LOGIC', 'WORKFLOW_STATE', 'RACE_CONDITION'],
    minimumEvidence: 2,
    requireReproduction: true,
    requireControlComparison: true,
    requireIdentityDifferential: false,
    requireAlternativeElimination: true,
    confidenceThreshold: 0.7,
    strategies: ['STATE_DIFFERENTIAL', 'REPRODUCTION', 'CONTROL_COMPARISON'],
    controls: ['VALID_STATE', 'INVALID_STATE'],
  },
  {
    categories: ['INJECTION', 'XSS', 'INPUT_VALIDATION', 'SSRF'],
    minimumEvidence: 2,
    requireReproduction: true,
    requireControlComparison: true,
    requireIdentityDifferential: false,
    requireAlternativeElimination: true,
    confidenceThreshold: 0.65,
    strategies: ['REPRODUCTION', 'CONTROL_COMPARISON'],
    controls: ['BENIGN_INPUT_CONTROL'],
  },
];

export function resolvePolicy(category: string | null, severity: string): VerificationPolicyRule {
  const normalized = (category ?? '').toUpperCase();
  const match = CATEGORY_POLICIES.find((rule) =>
    rule.categories.some((c) => normalized === c || normalized.includes(c)),
  );
  const base = match ?? DEFAULT_VERIFICATION_POLICY;
  // §72: high-impact findings get the stricter gate (never looser).
  if (severity === 'CRITICAL' || severity === 'HIGH') {
    return {
      ...base,
      requireReproduction: true,
      requireControlComparison: true,
      minimumEvidence: Math.max(base.minimumEvidence, 3),
      confidenceThreshold: Math.max(base.confidenceThreshold, 0.75),
    };
  }
  return base;
}

/** Policy evaluation against an executed verification outcome. */
export interface PolicyEvaluationInput {
  policy: VerificationPolicyRule;
  evidenceCount: number;
  reproduced: boolean;
  controlComparison: boolean;
  identityDifferential: boolean;
  alternativesEliminated: boolean;
  confidence: number;
}

export interface PolicyViolation {
  requirement: string;
  detail: string;
}

export function evaluatePolicy(input: PolicyEvaluationInput): PolicyViolation[] {
  const violations: PolicyViolation[] = [];
  if (input.evidenceCount < input.policy.minimumEvidence) {
    violations.push({
      requirement: 'minimum_evidence',
      detail: `${input.evidenceCount} evidence records present, policy requires ${input.policy.minimumEvidence}`,
    });
  }
  if (input.policy.requireReproduction && !input.reproduced) {
    violations.push({ requirement: 'reproduction', detail: 'policy requires independent reproduction' });
  }
  if (input.policy.requireControlComparison && !input.controlComparison) {
    violations.push({ requirement: 'control_comparison', detail: 'policy requires a control comparison' });
  }
  if (input.policy.requireIdentityDifferential && !input.identityDifferential) {
    violations.push({ requirement: 'identity_differential', detail: 'policy requires an identity differential' });
  }
  if (input.policy.requireAlternativeElimination && !input.alternativesEliminated) {
    violations.push({
      requirement: 'alternative_explanations',
      detail: 'policy requires all alternative explanations to be eliminated',
    });
  }
  if (input.confidence < input.policy.confidenceThreshold) {
    violations.push({
      requirement: 'confidence_threshold',
      detail: `confidence ${input.confidence.toFixed(3)} below policy threshold ${input.policy.confidenceThreshold}`,
    });
  }
  return violations;
}
