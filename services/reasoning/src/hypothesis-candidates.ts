/**
 * Deterministic hypothesis candidates (spec §44-§46, §104, §121).
 *
 * Signals feed competing interpretations (§45): the primary hypothesis is
 * created alongside its alternatives — H1 is never immediately promoted
 * (§45). Application to the real hypothesis engine happens through the
 * composition layer (apps/api), keeping Part 4 free of Part 2 ownership
 * (§119).
 */
import type { HypothesisType } from '@aegis/shared';
import type { HypothesisCandidate } from '@aegis/contracts';
import type { SecuritySignalRecord } from '@aegis/database';

export interface HypothesisGroup {
  /** Signal that generated this group. */
  signalId: string;
  signalType: string;
  /** Primary hypothesis (highest initial confidence). */
  primary: HypothesisCandidate;
  /** Competing alternatives (§45) — siblings, never suppressed. */
  competitors: HypothesisCandidate[];
  /** What evidence would distinguish the competitors (§46, §47). */
  distinguishingTests: string[];
}

const AUTHZ_REQUIRED_EVIDENCE = [
  'same object identifier under test',
  'at least two authenticated identities with different ownership context',
  'a baseline request from the object owner',
  'a reproduced (non-cached) response containing the protected data',
];

/**
 * Generate deterministic competing hypothesis groups from NEW signals
 * (§44-§45). Bounded: at most one group per signal.
 */
export function hypothesisGroupsFromSignals(signals: SecuritySignalRecord[]): HypothesisGroup[] {
  const groups: HypothesisGroup[] = [];
  for (const signal of signals.slice(0, 100)) {
    const group = groupForSignal(signal);
    if (group) groups.push(group);
  }
  return groups;
}

function groupForSignal(signal: SecuritySignalRecord): HypothesisGroup | null {
  switch (signal.signal_type) {
    case 'CROSS_IDENTITY_OBJECT_REFERENCE':
    case 'CROSS_IDENTITY_DIFFERENCE': {
      const path = extractPath(signal);
      const objectRef = signal.object_ref ?? 'the referenced object';
      return {
        signalId: signal.id,
        signalType: signal.signal_type,
        primary: candidate(
          `Endpoint ${path} may not enforce object-level authorization: ${objectRef} was accessible to a non-owner identity`,
          'AUTHORIZATION',
          0.55,
          0.8,
          AUTHZ_REQUIRED_EVIDENCE,
          signal.id,
          `Signal ${signal.id}: ${bounded(signal.summary, 300)}`,
        ),
        competitors: [
          candidate(
            `Object ${objectRef} on ${path} may be intentionally public or shared by design`,
            'AUTHORIZATION',
            0.4,
            0.6,
            ['an anonymous access result', 'documentation or workflow evidence of intentional sharing'],
            signal.id,
            'Competing interpretation: intentional public/shared access (spec §45 H2/H3)',
          ),
          candidate(
            `Access to ${objectRef} on ${path} may be role-based shared access rather than an ownership failure`,
            'AUTHORIZATION',
            0.35,
            0.55,
            ['role claims of the accessing identity', 'comparison against an admin identity'],
            signal.id,
            'Competing interpretation: role-based access (spec §45 H3)',
          ),
          candidate(
            `The permissive response for ${objectRef} on ${path} may be a cached response rather than an authorization decision`,
            'CONFIGURATION',
            0.3,
            0.5,
            ['cache headers on the response', 'a repeated request producing different content'],
            signal.id,
            'Competing interpretation: cache behavior (spec §45 H4)',
          ),
        ],
        distinguishingTests: [
          'Anonymous replay: distinguishes public-object from authorization-failure',
          'Owner baseline replay: confirms the baseline actually differs',
          'Cache-header inspection: distinguishes cached from computed responses',
        ],
      };
    }
    case 'REFLECTED_INPUT': {
      const path = extractPath(signal);
      return {
        signalId: signal.id,
        signalType: signal.signal_type,
        primary: candidate(
          `Reflected input on ${path} may reach a browser-executable context (encoding may be insufficient)`,
          'CLIENT_SIDE',
          0.45,
          0.7,
          ['reflection location (DOM vs server response)', 'encoding observed around the reflected value', 'a browser-context reproduction'],
          signal.id,
          `Signal ${signal.id}: ${bounded(signal.summary, 300)}`,
        ),
        competitors: [
          candidate(
            `Reflection on ${path} may be properly encoded and harmless`,
            'INPUT_VALIDATION',
            0.45,
            0.5,
            ['encoding evidence around the value', 'content-type of the response'],
            signal.id,
            'Competing interpretation: proper output encoding (spec §65)',
          ),
        ],
        distinguishingTests: [
          'Browser-context reproduction: distinguishes DOM-only reflection from server response reflection (§66-§67)',
          'Encoding probe with a canonical marker value',
        ],
      };
    }
    case 'CLIENT_CONTROLLED_VALUE': {
      const path = extractPath(signal);
      const parameter = typeof signal.metadata?.parameter === 'string' ? signal.metadata.parameter : 'a client-controlled parameter';
      return {
        signalId: signal.id,
        signalType: signal.signal_type,
        primary: candidate(
          `Server-side logic on ${path} may trust the client-controlled value "${parameter}" without revalidation`,
          'BUSINESS_LOGIC',
          0.45,
          0.75,
          ['a mutated value accepted by the server', 'observable state change tied to the mutation', 'a baseline with the original value'],
          signal.id,
          `Signal ${signal.id}: ${bounded(signal.summary, 300)}`,
        ),
        competitors: [
          candidate(
            `The value "${parameter}" may be validated server-side and ignored when inconsistent`,
            'INPUT_VALIDATION',
            0.4,
            0.5,
            ['a mutation rejected or ignored by the server'],
            signal.id,
            'Competing interpretation: server-side validation present',
          ),
        ],
        distinguishingTests: [
          'Boundary/type mutation of the value compared against the baseline (§100)',
        ],
      };
    }
    case 'STATE_TRANSITION_ANOMALY': {
      const trigger = bounded(typeof signal.metadata?.trigger === 'string' ? signal.metadata.trigger : 'a workflow transition', 200);
      return {
        signalId: signal.id,
        signalType: signal.signal_type,
        primary: candidate(
          `Workflow state enforcement may be missing: ${trigger} behaved inconsistently with the reconstructed workflow`,
          'BUSINESS_LOGIC',
          0.5,
          0.75,
          ['a reproduced out-of-order transition', 'the prerequisite transition evidence', 'identity attribution'],
          signal.id,
          `Signal ${signal.id}: ${bounded(signal.summary, 300)}`,
        ),
        competitors: [
          candidate(
            `The workflow reconstruction may be wrong: ${trigger} may follow an unobserved legitimate path`,
            'UNKNOWN',
            0.35,
            0.45,
            ['additional observations of the full workflow', 'browser reproduction of the flow'],
            signal.id,
            'Competing interpretation: incomplete workflow reconstruction (spec §35)',
          ),
        ],
        distinguishingTests: [
          'Replay the transition in the reconstructed-valid order and in the skipped order',
        ],
      };
    }
    case 'ERROR_DISCLOSURE':
    case 'SENSITIVE_DATA_EXPOSURE': {
      const path = extractPath(signal);
      return {
        signalId: signal.id,
        signalType: signal.signal_type,
        primary: candidate(
          `Endpoint ${path} may disclose sensitive information beyond its intended response`,
          'DATA_EXPOSURE',
          0.4,
          0.6,
          ['a reproduced response containing the disclosure', 'confirmation the data is actually sensitive', 'an identity comparison showing exposure is not universal'],
          signal.id,
          `Signal ${signal.id}: ${bounded(signal.summary, 300)}`,
        ),
        competitors: [
          candidate(
            `The indicator on ${path} may be a false positive (framework marker, benign path, test fixture)`,
            'UNKNOWN',
            0.45,
            0.4,
            ['manual or LLM interpretation of the excerpt'],
            signal.id,
            'Competing interpretation: false positive expected (spec §64)',
          ),
        ],
        distinguishingTests: [
          'Repeat the request and confirm the disclosure is stable',
          'Compare the response across identities',
        ],
      };
    }
    case 'TOKEN_PATTERN': {
      const path = extractPath(signal);
      return {
        signalId: signal.id,
        signalType: signal.signal_type,
        primary: candidate(
          `Token claims on ${path} may not be validated server-side (role/identity claims attacker-relevant)`,
          'AUTHENTICATION',
          0.4,
          0.6,
          ['a modified-claim token accepted by the server', 'a baseline with the original token'],
          signal.id,
          `Signal ${signal.id}: ${bounded(signal.summary, 300)}`,
        ),
        competitors: [
          candidate(
            `The token on ${path} may be decorative (client-side use only) or fully validated`,
            'AUTHENTICATION',
            0.45,
            0.5,
            ['a request with the token removed', 'a request with a tampered signature'],
            signal.id,
            'Competing interpretation: token is validated or decorative',
          ),
        ],
        distinguishingTests: [
          'Token-removal replay and tampered-claim replay (never credential cracking, §58)',
        ],
      };
    }
    case 'UNEXPECTED_METHOD_BEHAVIOR': {
      const path = extractPath(signal);
      return {
        signalId: signal.id,
        signalType: signal.signal_type,
        primary: candidate(
          `Endpoint ${path} may authorize state-changing methods inconsistently with its intended usage`,
          'AUTHORIZATION',
          0.4,
          0.6,
          ['the method result reproduced', 'authorization outcomes for the method across identities'],
          signal.id,
          `Signal ${signal.id}: ${bounded(signal.summary, 300)}`,
        ),
        competitors: [
          candidate(
            `The method on ${path} is intentionally supported (documented or UI-invoked)`,
            'UNKNOWN',
            0.4,
            0.4,
            ['UI or script evidence invoking the method'],
            signal.id,
            'Competing interpretation: intentional method surface',
          ),
        ],
        distinguishingTests: ['Cross-identity replay of the method'],
      };
    }
    case 'UNEXPECTED_REDIRECT':
      return {
        signalId: signal.id,
        signalType: signal.signal_type,
        primary: candidate(
          `Session handling on the engagement target may expire sessions mid-flow or redirect authenticated users unexpectedly`,
          'SESSION',
          0.45,
          0.5,
          ['reproduction of the redirect with a fresh session', 'session expiration evidence'],
          signal.id,
          `Signal ${signal.id}: ${bounded(signal.summary, 300)}`,
        ),
        competitors: [
          candidate(
            'The redirect may reflect per-route authentication requirements rather than session loss',
            'AUTHENTICATION',
            0.4,
            0.5,
            ['other endpoints accessible with the same session'],
            signal.id,
            'Competing interpretation: route-level auth requirement',
          ),
        ],
        distinguishingTests: ['Replay with a known-active session and inspect which routes redirect'],
      };
    default:
      // AUTH_STATE_CHANGE, OBJECT_IDENTIFIER, UNUSUAL_RESPONSE_DIFFERENCE
      // are context signals: they strengthen/weaken existing hypotheses
      // rather than generating new ones (§44 example uses them as inputs).
      return null;
  }
}

function candidate(
  statement: string,
  type: HypothesisType,
  initialConfidence: number,
  priority: number,
  requiredEvidence: string[],
  signalId: string,
  rationale: string,
): HypothesisCandidate {
  return {
    statement,
    type,
    initial_confidence: initialConfidence,
    priority,
    required_evidence: requiredEvidence,
    signal_id: signalId,
    competing: false,
    rationale,
  };
}

function extractPath(signal: SecuritySignalRecord): string {
  const path = signal.metadata?.['canonical_path'];
  return typeof path === 'string' ? bounded(path, 300) : 'the affected endpoint';
}

function bounded(text: string, max: number): string {
  return text.length > max ? `${text.slice(0, max)}…` : text;
}
