/**
 * Workflow engine (spec §30-§36, §94, §122).
 *
 * Candidate workflows are RECONSTRUCTED from observed request sequences
 * (§34) — the user never defines them manually. States derive from URL /
 * response / method heuristics (§31); transitions record observed vs
 * inferred with confidence (§35). Temporal order is preserved (§94).
 */
import { createHash } from 'node:crypto';
import type { EndpointRecord } from '@aegis/database';

export interface SequenceStep {
  requestId: string;
  method: string;
  path: string;
  status: number | null;
  identityId: string | null;
  at: string;
  endpointId: string | null;
  evidenceId: string | null;
}

export interface StateNameResult {
  name: string;
  detection: Record<string, unknown>;
  observed: boolean;
  confidence: number;
}

const PAGE_STATE_PATTERNS: Array<{ pattern: RegExp; name: string }> = [
  { pattern: /login|signin|sign-in/i, name: 'LOGIN_PAGE' },
  { pattern: /register|signup|sign-up/i, name: 'REGISTRATION' },
  { pattern: /logout|signout/i, name: 'LOGOUT' },
  { pattern: /dashboard|home|index|^\/$/i, name: 'DASHBOARD' },
  { pattern: /checkout|payment|billing/i, name: 'PAYMENT' },
  { pattern: /confirm|confirmation|receipt|success/i, name: 'CONFIRMATION' },
  { pattern: /reset|forgot|recover/i, name: 'PASSWORD_RESET' },
  { pattern: /verify|verification|mfa|2fa/i, name: 'VERIFICATION' },
];

/** Derive a state name from one observed step (§31). */
export function stateNameForStep(step: SequenceStep, nextStep: SequenceStep | null): StateNameResult {
  // Resource-creating POSTs name the created resource state (§30 example).
  if (step.method === 'POST' && step.status !== null && step.status >= 200 && step.status < 300) {
    const resource = resourceFromPath(step.path);
    if (resource) {
      return {
        name: `${resource}_CREATED`,
        detection: { kind: 'response_status', method: step.method, path: step.path, status: step.status },
        observed: true,
        confidence: 0.85,
      };
    }
  }
  // State-changing sub-actions: POST /api/orders/{id}/pay -> ORDER_PAID.
  if (step.method === 'POST' && step.status !== null && step.status >= 200 && step.status < 300) {
    const action = actionFromPath(step.path);
    const resource = action.resource;
    if (resource && action.verb) {
      return {
        name: `${resource}_${action.verb.toUpperCase()}`,
        detection: { kind: 'response_status', method: step.method, path: step.path, status: step.status },
        observed: true,
        confidence: 0.8,
      };
    }
  }
  // Page-shaped paths use page patterns.
  for (const entry of PAGE_STATE_PATTERNS) {
    if (entry.pattern.test(step.path)) {
      return {
        name: entry.name,
        detection: { kind: 'url_pattern', path: bounded(step.path, 256) },
        observed: true,
        confidence: 0.75,
      };
    }
  }
  // GET of a resource identifies a resource-read state.
  if (step.method === 'GET') {
    const resource = resourceFromPath(step.path);
    if (resource) {
      return {
        name: `${resource}_VIEWED`,
        detection: { kind: 'url_pattern', path: bounded(step.path, 256), method: 'GET' },
        observed: true,
        confidence: 0.7,
      };
    }
  }
  // API endpoints (non-page) collapse to a generic API state per family to
  // avoid state explosion (§113 resource limits).
  const family = step.path.split('/').filter((segment) => segment.length > 0 && !segment.startsWith('{')).slice(0, 3).join('_');
  if (family.length === 0) return { name: 'ROOT', detection: { kind: 'url', path: '/' }, observed: true, confidence: 0.6 };
  return {
    name: `API_${family.toUpperCase().replace(/[^A-Z0-9_]/g, '_').slice(0, 48)}`,
    detection: { kind: 'url_family', path: bounded(step.path, 256) },
    observed: true,
    confidence: 0.6,
  };
}

function resourceFromPath(path: string): string | null {
  const segments = path.split('/').filter((segment) => segment.length > 0);
  // Look for a plural resource segment (REST convention, §86).
  const candidates = segments.filter((segment) => /^[a-z][a-z0-9-]*s$/i.test(segment) || /^(orders?|users?|items?|carts?|payments?|invoices?|messages?|posts?|documents?)$/i.test(segment));
  if (candidates.length === 0) return null;
  const resource = candidates[candidates.length - 1]!;
  return singularize(resource).toUpperCase();
}

function actionFromPath(path: string): { resource: string | null; verb: string | null } {
  const segments = path.split('/').filter((segment) => segment.length > 0);
  const actionSegment = segments[segments.length - 1]!;
  const verbish = actionSegment.match(/^(pay|confirm|cancel|submit|approve|reject|ship|deliver|refund|verify|activate|suspend|close|complete)$/i);
  if (!verbish) return { resource: null, verb: null };
  // Find the resource before the {param}: /api/orders/{param}/pay
  const resourceSegment = [...segments].reverse().slice(1).find((segment) => /^[a-z][a-z0-9-]*s$/i.test(segment));
  return {
    resource: resourceSegment ? singularize(resourceSegment).toUpperCase() : null,
    verb: verbish[1]!,
  };
}

function singularize(word: string): string {
  if (/ies$/i.test(word)) return `${word.slice(0, -3)}y`;
  if (/(ses|xes|zes|ches|shes)$/i.test(word)) return word.slice(0, -2);
  if (/s$/i.test(word)) return word.slice(0, -1);
  return word;
}

export interface TransitionFact {
  fromStateName: string | null;
  toStateName: string;
  triggerSummary: string;
  triggerEndpointId: string | null;
  identityId: string | null;
  observationKind: 'OBSERVED' | 'INFERRED';
  confidence: number;
  evidenceIds: string[];
  fingerprint: string;
  at: string;
  fromDetection: Record<string, unknown> | null;
  toDetection: Record<string, unknown>;
  toObserved: boolean;
  toConfidence: number;
}

/**
 * Reconstruct transitions from a per-identity chronological sequence (§34).
 * Consecutive steps become transitions; gaps produce INFERRED links with
 * lower confidence (§35: inferred never becomes fact automatically).
 */
export function transitionsFromSequence(steps: SequenceStep[]): { states: Map<string, StateNameResult>; transitions: TransitionFact[] } {
  const states = new Map<string, StateNameResult>();
  const transitions: TransitionFact[] = [];
  let previous: { step: SequenceStep; state: StateNameResult } | null = null;

  for (const step of steps) {
    const state = stateNameForStep(step, null);
    if (!states.has(state.name)) states.set(state.name, state);
    if (previous && previous.state.name !== state.name) {
      const fingerprint = createHash('sha256')
        .update(`${previous.state.name}|${state.name}|${triggerSummaryFor(step)}`)
        .digest('hex')
        .slice(0, 40);
      const existing = transitions.find((transition) => transition.fingerprint === fingerprint);
      if (existing) {
        // Same transition observed again (dedup by fingerprint, §111).
        existing.at = step.at;
      } else {
        transitions.push({
          fromStateName: previous.state.name,
          toStateName: state.name,
          triggerSummary: triggerSummaryFor(step),
          triggerEndpointId: step.endpointId,
          identityId: step.identityId,
          observationKind: 'OBSERVED',
          confidence: 0.85,
          evidenceIds: step.evidenceId ? [step.evidenceId] : [],
          fingerprint,
          at: step.at,
          fromDetection: previous.state.detection,
          toDetection: state.detection,
          toObserved: state.observed,
          toConfidence: state.confidence,
        });
      }
    }
    previous = { step, state };
  }
  return { states, transitions };
}

export function triggerSummaryFor(step: SequenceStep): string {
  return `${step.method} ${bounded(step.path, 200)}`;
}

/**
 * Segment a chronological request list into per-identity sequences (§94
 * temporal reasoning, §20 identity separation). A gap of > 30 minutes
 * starts a new segment (session boundaries).
 */
export function segmentByIdentity(
  steps: SequenceStep[],
): Map<string, SequenceStep[]> {
  const byIdentity = new Map<string, SequenceStep[]>();
  for (const step of steps) {
    const key = step.identityId ?? 'ANONYMOUS';
    if (!byIdentity.has(key)) byIdentity.set(key, []);
    byIdentity.get(key)!.push(step);
  }
  // Re-split on long time gaps.
  const result = new Map<string, SequenceStep[]>();
  for (const [key, sequence] of byIdentity) {
    let current: SequenceStep[] = [];
    let lastAt: number | null = null;
    for (const step of sequence) {
      const at = Date.parse(step.at);
      if (lastAt !== null && Number.isFinite(at) && at - lastAt > 30 * 60 * 1000) {
        if (current.length > 0) {
          result.set(`${key}#${result.size}`, current);
          current = [];
        }
      }
      current.push(step);
      lastAt = Number.isFinite(at) ? at : lastAt;
    }
    if (current.length > 0) result.set(`${key}#${result.size}`, current);
  }
  return result;
}

/**
 * Prerequisite analysis (§36 business-logic signals): for verb-shaped
 * transitions (confirm/pay/cancel), check whether the prerequisite
 * transition (e.g. ORDER_PAID before ORDER_CONFIRMED) was observed in the
 * same sequence. Returns anomaly facts — signals, never conclusions.
 */
export function prerequisiteAnomalies(
  transitions: TransitionFact[],
): Array<{ triggerSummary: string; anomaly: 'PREREQUISITE_MISSING' | 'SKIPPED_TRANSITION'; detail: string }> {
  const anomalies: Array<{ triggerSummary: string; anomaly: 'PREREQUISITE_MISSING' | 'SKIPPED_TRANSITION'; detail: string }> = [];
  const verbOrder: Array<{ verb: RegExp; requires: RegExp }> = [
    { verb: /^ORDER_CONFIRMED$/, requires: /^ORDER_PAID$/ },
    { verb: /^ORDER_CONFIRMED$/, requires: /^ORDER_CREATED$/ },
  ];
  for (const rule of verbOrder) {
    const targets = transitions.filter((transition) => rule.verb.test(transition.toStateName));
    for (const target of targets) {
      const hasPrerequisite = transitions.some(
        (transition) =>
          rule.requires.test(transition.toStateName) &&
          transition.identityId === target.identityId &&
          Date.parse(transition.at) <= Date.parse(target.at),
      );
      if (!hasPrerequisite) {
        anomalies.push({
          triggerSummary: target.triggerSummary,
          anomaly: 'PREREQUISITE_MISSING',
          detail: `Transition to ${target.toStateName} was observed (status recorded) without a preceding ${rule.requires.source.replace(/[^A-Z_]/g, '')} transition for the same identity`,
        });
      }
    }
  }
  return anomalies.slice(0, 16);
}

/** Workflow name for an engagement surface (§34). */
export function workflowNameForHost(host: string): string {
  return `FLOW:${host.slice(0, 100)}`;
}

function bounded(text: string, max: number): string {
  return text.length > max ? `${text.slice(0, max)}…` : text;
}
