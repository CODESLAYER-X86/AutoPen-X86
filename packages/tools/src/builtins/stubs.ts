/**
 * Registered-but-not-implemented tool interfaces (spec §37: "expose a
 * clear interface and an explicit 'not implemented' state").
 *
 * These definitions exist so the registry, the UI and the API can honestly
 * advertise the planned tool surface. Executing one returns a structured
 * failure (TOOL_NOT_IMPLEMENTED) instead of pretending to work.
 *
 * Part 3 note: the http.* / browser.* / artifact.* / har.import /
 * websocket.observe tools are implemented by @aegis/toolbox and registered
 * by the application composition root — they are no longer stubs.
 */
import { NotImplementedError } from '@aegis/shared';
import { z } from 'zod';
import type { RiskLevel, ToolCapability } from '@aegis/shared';
import type { ToolDefinition } from '../types.js';

interface StubSpec {
  name: string;
  description: string;
  riskLevel: RiskLevel;
  capabilities: ToolCapability[];
  requiresScope: boolean;
  requiresIdentity?: boolean;
  urlFields?: string[];
  plannedPart: string;
}

const STUB_SPECS: StubSpec[] = [
  {
    name: 'parser.html',
    description: 'Parses HTML into a structured tree with form/anchor/script extraction.',
    riskLevel: 'LOW',
    capabilities: ['READ_ONLY'],
    requiresScope: false,
    plannedPart: 'Part 3 (Parsers)',
  },
  {
    name: 'parser.json',
    description: 'Parses and structurally analyses a JSON document.',
    riskLevel: 'LOW',
    capabilities: ['READ_ONLY'],
    requiresScope: false,
    plannedPart: 'Part 3 (Parsers)',
  },
  {
    name: 'diff.response',
    description: 'Deterministically diffs two recorded HTTP responses (status, headers, body).',
    riskLevel: 'LOW',
    capabilities: ['READ_ONLY'],
    requiresScope: false,
    plannedPart: 'Part 3 (Diff engine)',
  },
  {
    name: 'diff.request',
    description: 'Deterministically diffs two recorded HTTP requests.',
    riskLevel: 'LOW',
    capabilities: ['READ_ONLY'],
    requiresScope: false,
    plannedPart: 'Part 3 (Diff engine)',
  },
  {
    name: 'evidence.store',
    description: 'Stores arbitrary bytes as immutable, hash-addressed evidence for an engagement.',
    riskLevel: 'LOW',
    capabilities: ['MUTATION'],
    requiresScope: false,
    plannedPart: 'Part 2 (Agent OS)',
  },
  // knowledge.search / knowledge.fetch were Part 1 stubs; the real Part 5
  // implementations in @aegis/toolbox replaced them (registered by the API
  // context when FEATURE_KNOWLEDGE_SEARCH is enabled).
];

export function createStubTools(): ToolDefinition[] {
  return STUB_SPECS.map((spec) => ({
    name: spec.name,
    version: '0.0.0',
    description: spec.description,
    riskLevel: spec.riskLevel,
    capabilities: spec.capabilities,
    requiresScope: spec.requiresScope,
    requiresIdentity: spec.requiresIdentity,
    implemented: false,
    plannedPart: spec.plannedPart,
    urlFields: spec.urlFields,
    inputSchema: z.object({}).passthrough(),
    outputSchema: z.object({}).passthrough(),
    async execute(): Promise<never> {
      throw new NotImplementedError(
        `Tool '${spec.name}' is not implemented yet — planned for ${spec.plannedPart}`,
        'TOOL_NOT_IMPLEMENTED',
        { tool: spec.name, planned_part: spec.plannedPart },
      );
    },
  }));
}
