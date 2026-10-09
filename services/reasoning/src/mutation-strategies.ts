/**
 * Mutation strategy engine (spec §51-§57).
 *
 * The LLM chooses a CATEGORY (§51); this module generates the actual
 * structured mutations deterministically. Identifier swaps use ONLY
 * controlled, observed values (§52) — the LLM never constructs uncontrolled
 * target values. Authentication mutations use identity/session references,
 * never raw credentials (§57).
 */
import type { HttpMutation } from '@aegis/contracts';
import type { MutationCategory } from '@aegis/shared';
import type { ParameterRecord } from '@aegis/database';

export interface MutationStrategyContext {
  /** Target endpoint canonical path (for path mutations). */
  canonicalPath: string;
  /** Concrete observed URL to mutate (base request replay target). */
  observedUrl: string;
  parameters: ParameterRecord[];
  /** Controlled identifier values observed on the engagement (§52). */
  objectValues: Array<{ name: string; value: string }>;
  /** Identity references available (§57 — references only). */
  identityOptions: Array<{ identityId: string; label: string }>;
  /** Sensitive/monetary parameters must not be mutated blindly. */
  allowDestructive: boolean;
}

export interface MutationPlan {
  category: MutationCategory;
  description: string;
  mutations: HttpMutation[];
  /** Identity reference to execute the mutated request as (§57). */
  identityId: string | null;
}

const BOUNDARY_VALUES = ['', '0', '-1', '2147483647', '99999999999999999999'];
// HttpMutation values are scalars (contract http.ts): structural type
// mutations (array/object) are intentionally NOT representable here.
const TYPE_VALUES: Array<{ label: string; value: string | number | boolean | null }> = [
  { label: 'string_for_number', value: '1' },
  { label: 'number_for_string', value: 42 },
  { label: 'boolean_true', value: true },
  { label: 'null', value: null },
];

export const MUTATION_CATEGORY_MAX_PER_REQUEST = 4;

/**
 * Generate deterministic mutations for a category (§51-§57). Bounded by
 * MUTATION_CATEGORY_MAX_PER_REQUEST per call; the planner chooses which
 * categories to actually execute (§54: do not execute every value).
 */
export function generateMutations(category: MutationCategory, context: MutationStrategyContext): MutationPlan[] {
  switch (category) {
    case 'AUTHORIZATION':
      return authorizationPlans(context);
    case 'AUTHENTICATION':
      return authenticationPlans(context);
    case 'IDENTIFIER':
      return identifierPlans(context);
    case 'BOUNDARY':
      return boundaryPlans(context);
    case 'TYPE':
      return typePlans(context);
    case 'STRUCTURE':
      return structurePlans(context);
    case 'METHOD':
      return methodPlans(context);
    case 'STATE':
      return statePlans(context);
    case 'QUERY':
      return queryPlans(context);
    case 'JSON':
      return jsonPlans(context);
    case 'FORM':
      return formPlans(context);
    case 'PATH':
      return pathPlans(context);
    case 'HEADER':
      return headerPlans(context);
    case 'COOKIE':
      return cookiePlans(context);
    default:
      return [];
  }
}

function authorizationPlans(context: MutationStrategyContext): MutationPlan[] {
  // Identity swap on the same request (§61): baseline identity A, candidate
  // identity B. Mutations stay empty — the identity reference changes.
  return context.identityOptions.slice(0, 3).map((option) => ({
    category: 'AUTHORIZATION' as MutationCategory,
    description: `Execute the same request as identity ${option.label} (identity reference swap)`,
    mutations: [],
    identityId: option.identityId,
  }));
}

function authenticationPlans(_context: MutationStrategyContext): MutationPlan[] {
  // Anonymous comparison (§57): no identity, and (optionally) no auth headers.
  const plans: MutationPlan[] = [
    {
      category: 'AUTHENTICATION',
      description: 'Execute the request anonymously (no identity/session)',
      mutations: [],
      identityId: null,
    },
    {
      category: 'AUTHENTICATION',
      description: 'Remove authorization-bearing headers and cookies while authenticated',
      mutations: [
        { location: 'header', name: 'authorization', operation: 'remove' },
        { location: 'cookie', name: 'session', operation: 'remove' },
      ],
      identityId: null,
    },
  ];
  return plans;
}

function identifierPlans(context: MutationStrategyContext): MutationPlan[] {
  // Controlled identifier swap A -> B (§52): only values observed during the
  // engagement are used. Swaps pair the first value with each other value.
  const plans: MutationPlan[] = [];
  const byName = new Map<string, string[]>();
  for (const entry of context.objectValues) {
    if (!byName.has(entry.name)) byName.set(entry.name, []);
    if (!byName.get(entry.name)!.includes(entry.value)) byName.get(entry.name)!.push(entry.value);
  }
  for (const [name, values] of byName) {
    if (values.length < 2) continue;
    const baseline = values[0]!;
    for (const other of values.slice(1, 3)) {
      plans.push({
        category: 'IDENTIFIER',
        description: `Swap controlled identifier "${name}": ${bounded(baseline)} -> ${bounded(other)}`,
        mutations: [{ location: 'path', operation: 'replace', value: other, name }],
        identityId: null,
      });
    }
  }
  return plans.slice(0, MUTATION_CATEGORY_MAX_PER_REQUEST);
}

function boundaryPlans(context: MutationStrategyContext): MutationPlan[] {
  // Boundary values on non-sensitive scalar parameters (§54).
  const target = context.parameters.find(
    (parameter) =>
      !parameter.is_sensitive &&
      parameter.location !== 'HEADER' &&
      (parameter.value_characteristics.includes('NUMERIC') || parameter.example_values.length > 0),
  );
  if (!target) return [];
  return BOUNDARY_VALUES.slice(0, 4).map((value) => ({
    category: 'BOUNDARY' as MutationCategory,
    description: `Boundary value for "${target.name}" (${target.location}): ${value === '' ? 'empty' : value}`,
    mutations: [mutationForLocation(target.location, target.name, value, 'replace')],
    identityId: null,
  }));
}

function typePlans(context: MutationStrategyContext): MutationPlan[] {
  const target = context.parameters.find(
    (parameter) => !parameter.is_sensitive && parameter.location === 'JSON',
  );
  if (!target) return [];
  return TYPE_VALUES.slice(0, 4).map((entry) => ({
    category: 'TYPE' as MutationCategory,
    description: `Type mutation for JSON field "${target.name}": ${entry.label}`,
    mutations: [
      {
        location: 'body_json',
        path: target.name,
        operation: 'replace',
        value: entry.value,
      },
    ],
    identityId: null,
  }));
}

function structurePlans(context: MutationStrategyContext): MutationPlan[] {
  const target = context.parameters.find((parameter) => parameter.location === 'JSON' && !parameter.is_sensitive);
  if (!target) return [];
  return [
    {
      category: 'STRUCTURE',
      description: `Remove JSON field "${target.name}"`,
      mutations: [{ location: 'body_json', path: target.name, operation: 'remove' }],
      identityId: null,
    },
    {
      category: 'STRUCTURE',
      description: `Add unexpected JSON field "extra_field"`,
      mutations: [{ location: 'body_json', path: 'extra_field', operation: 'add', value: 'x' }],
      identityId: null,
    },
  ];
}

function methodPlans(_context: MutationStrategyContext): MutationPlan[] {
  return ['PUT', 'PATCH', 'DELETE', 'OPTIONS'].map((method) => ({
    category: 'METHOD' as MutationCategory,
    description: `Send ${method} instead of the observed method`,
    mutations: [{ location: 'method', operation: 'replace', value: method }],
    identityId: null,
  }));
}

function statePlans(_context: MutationStrategyContext): MutationPlan[] {
  // Workflow mutations (§56) are request-SEQUENCE operations — represented as
  // plans the scheduler expands. No direct HTTP mutation is generated here.
  return [
    {
      category: 'STATE',
      description: 'Replay the transition skipping its observed prerequisite (sequence-level mutation, requires workflow context)',
      mutations: [],
      identityId: null,
    },
  ];
}

function queryPlans(context: MutationStrategyContext): MutationPlan[] {
  const target = context.parameters.find((parameter) => parameter.location === 'QUERY' && !parameter.is_sensitive);
  if (!target) return [];
  return [
    {
      category: 'QUERY',
      description: `Remove query parameter "${target.name}"`,
      mutations: [{ location: 'query', name: target.name, operation: 'remove' }],
      identityId: null,
    },
    {
      category: 'QUERY',
      description: `Duplicate query parameter "${target.name}"`,
      mutations: [{ location: 'query', name: target.name, operation: 'duplicate' }],
      identityId: null,
    },
  ];
}

function jsonPlans(context: MutationStrategyContext): MutationPlan[] {
  return structurePlans(context).map((plan) => ({ ...plan, category: 'JSON' as MutationCategory }));
}

function formPlans(context: MutationStrategyContext): MutationPlan[] {
  const target = context.parameters.find((parameter) => parameter.location === 'FORM' && !parameter.is_sensitive);
  if (!target) return [];
  return [
    {
      category: 'FORM',
      description: `Remove form field "${target.name}"`,
      mutations: [{ location: 'body_form', name: target.name, operation: 'remove' }],
      identityId: null,
    },
    {
      category: 'FORM',
      description: `Empty form field "${target.name}"`,
      mutations: [{ location: 'body_form', name: target.name, operation: 'replace', value: '' }],
      identityId: null,
    },
  ];
}

function pathPlans(context: MutationStrategyContext): MutationPlan[] {
  const segments = context.canonicalPath.split('/').filter((segment) => segment.length > 0);
  const paramIndex = segments.indexOf('{param}');
  if (paramIndex < 0) return [];
  const current = context.observedUrl.split('/').filter((segment) => segment.length > 0);
  if (current.length !== segments.length) return [];
  const other = context.objectValues[0]?.value;
  if (!other) return [];
  return [
    {
      category: 'PATH',
      description: `Replace path identifier segment ${paramIndex} with observed value "${bounded(other)}"`,
      mutations: [
        {
          location: 'path',
          operation: 'replace',
          value: other,
        },
      ],
      identityId: null,
    },
  ];
}

function headerPlans(_context: MutationStrategyContext): MutationPlan[] {
  return [
    {
      category: 'HEADER',
      description: 'Add an unexpected custom header (probe reflection/processing)',
      mutations: [{ location: 'header', name: 'x-aegis-probe', operation: 'add', value: 'probe' }],
      identityId: null,
    },
  ];
}

function cookiePlans(_context: MutationStrategyContext): MutationPlan[] {
  return [
    {
      category: 'COOKIE',
      description: 'Remove the session cookie (probe cookie-based auth dependence) — identity reference preserved',
      mutations: [{ location: 'cookie', name: 'session', operation: 'remove' }],
      identityId: null,
    },
  ];
}

function mutationForLocation(
  location: ParameterRecord['location'],
  name: string,
  value: string | number | boolean | null,
  operation: 'replace',
): HttpMutation {
  switch (location) {
    case 'QUERY':
      return { location: 'query', name, operation, value: String(value) };
    case 'JSON':
      return { location: 'body_json', path: name, operation, value };
    case 'FORM':
    case 'MULTIPART':
      return { location: 'body_form', name, operation, value: String(value) };
    case 'PATH':
      return { location: 'path', operation, value: String(value) };
    default:
      return { location: 'query', name, operation, value: String(value) };
  }
}

function bounded(text: string, max = 40): string {
  return text.length > max ? `${text.slice(0, max)}…` : text;
}
