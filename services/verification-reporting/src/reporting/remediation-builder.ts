/**
 * Remediation builder (spec Part 7 §35-§36).
 *
 * Root-cause-driven remediation: "perform server-side authorization checks
 * against the authenticated principal and the object's ownership policy
 * before returning object data" — NOT "validate input" (§35). Remediation
 * never assumes a specific framework unless evidence supports it. Priority
 * bands (§36) come from severity + confidence + scope, deterministic.
 */
import type { FindingRecord } from '@aegis/database';

interface RemediationTemplate {
  categories: string[];
  rootCause: string;
  remediation: string;
  fixComplexity: 'LOW' | 'MEDIUM' | 'HIGH';
}

const TEMPLATES: RemediationTemplate[] = [
  {
    categories: ['AUTHORIZATION', 'AUTHZ', 'BOLA', 'IDOR'],
    rootCause: 'object-level authorization is not enforced against the authenticated principal',
    remediation:
      'Perform server-side authorization checks against the authenticated principal and the requested object\u2019s ownership/access-control policy before returning or modifying object data. Deny by default, and log denials. Apply the check in a single enforced layer (not per-route), and add regression tests covering cross-identity access for every object endpoint.',
    fixComplexity: 'LOW',
  },
  {
    categories: ['AUTHENTICATION', 'SESSION'],
    rootCause: 'authentication or session boundary is incorrectly enforced',
    remediation:
      'Enforce authentication at a single trusted boundary; reject unauthenticated access with the same generic error for every protected resource. Regenerate session identifiers after privilege changes, set secure cookie attributes, and invalidate sessions server-side on logout/expiration.',
    fixComplexity: 'MEDIUM',
  },
  {
    categories: ['INJECTION', 'XSS', 'INPUT_VALIDATION'],
    rootCause: 'untrusted input reaches a sensitive interpreter without contextual validation or encoding',
    remediation:
      'Validate untrusted input against a strict allow-list at the trust boundary, and apply context-aware output encoding for the exact interpreter consumed (HTML body vs attribute vs script vs SQL). Prefer parameterized APIs so data and code stay structurally separated.',
    fixComplexity: 'MEDIUM',
  },
  {
    categories: ['BUSINESS_LOGIC', 'WORKFLOW_STATE', 'RACE_CONDITION'],
    rootCause: 'state transitions are accepted without validating the full precondition chain',
    remediation:
      'Encode the workflow state machine server-side; validate every transition\u2019s preconditions atomically (compare-and-set or transactional guard) before applying effects. Reject out-of-order or repeated transitions explicitly and audit rejections.',
    fixComplexity: 'HIGH',
  },
  {
    categories: ['INFORMATION_DISCLOSURE', 'CONFIGURATION', 'CLIENT_SIDE'],
    rootCause: 'sensitive data is exposed to an audience that should not receive it',
    remediation:
      'Classify the data, then remove it from the exposed channel: strip sensitive fields from responses rendered to the wider audience, remove client-side storage of secrets, and disable verbose modes/headers in production. Verify with a differential test after the change.',
    fixComplexity: 'LOW',
  },
  {
    categories: ['SSRF', 'FILE_HANDLING'],
    rootCause: 'untrusted references are resolved against internal resources without an allow-list',
    remediation:
      'Resolve untrusted references only against an explicit allow-list of destinations; reject private/link-local/loopback addresses after DNS resolution (re-check per redirect), limit response sizes, and never return raw internal error output to the caller.',
    fixComplexity: 'MEDIUM',
  },
];

const DEFAULT_TEMPLATE: RemediationTemplate = {
  categories: [],
  rootCause: 'the expected security control is missing or not enforced on the affected path',
  remediation:
    'Define the expected security property for the affected path, enforce it server-side at a single trust boundary, deny by default, and add a regression test that fails when the control is absent.',
  fixComplexity: 'MEDIUM',
};

export interface RemediationGuidance {
  rootCause: string;
  remediation: string;
  priority: 'IMMEDIATE' | 'SHORT_TERM' | 'LONG_TERM';
  fixComplexity: 'LOW' | 'MEDIUM' | 'HIGH';
  note: string;
}

export class RemediationBuilder {
  /** §35: root-cause remediation for a finding (deterministic template). */
  build(finding: FindingRecord): RemediationGuidance {
    const category = (finding.category ?? '').toUpperCase();
    const template =
      TEMPLATES.find((t) => t.categories.some((c) => category === c || category.includes(c))) ?? DEFAULT_TEMPLATE;

    const custom = finding.remediation?.trim();
    const remediation = custom && custom.length >= 40 ? custom : template.remediation;

    // §36: priority from severity + confidence + scope, deterministic.
    const severity = finding.severity;
    const confidence = finding.confidence ?? 0;
    const scope = finding.affected_endpoints.length;
    const priority: RemediationGuidance['priority'] =
      severity === 'CRITICAL' || (severity === 'HIGH' && confidence >= 0.6) || scope >= 3
        ? 'IMMEDIATE'
        : severity === 'HIGH' || (severity === 'MEDIUM' && confidence >= 0.6)
          ? 'SHORT_TERM'
          : 'LONG_TERM';

    return {
      rootCause: template.rootCause,
      remediation,
      priority,
      fixComplexity: template.fixComplexity,
      note:
        'Remediation is derived from the root cause category; it does not assume a specific framework unless evidence supports it (§35).',
    };
  }
}
