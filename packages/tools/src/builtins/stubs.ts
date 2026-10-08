/**
 * Registered-but-not-implemented tool interfaces (spec §37: "expose a
 * clear interface and an explicit 'not implemented' state").
 *
 * These definitions exist so the registry, the UI and the API can honestly
 * advertise the planned tool surface. Executing one returns a structured
 * failure (TOOL_NOT_IMPLEMENTED) instead of pretending to work.
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
    name: 'http.request',
    description: 'Sends a single HTTP request to an in-scope URL and records request/response as evidence.',
    riskLevel: 'MEDIUM',
    capabilities: ['NETWORK', 'READ_ONLY'],
    requiresScope: true,
    urlFields: ['url'],
    plannedPart: 'Part 3 (HTTP worker)',
  },
  {
    name: 'http.replay',
    description: 'Replays a previously recorded HTTP request, optionally with modifications.',
    riskLevel: 'MEDIUM',
    capabilities: ['NETWORK', 'READ_ONLY'],
    requiresScope: true,
    urlFields: ['url'],
    plannedPart: 'Part 3 (HTTP worker)',
  },
  {
    name: 'browser.navigate',
    description: 'Navigates the controlled browser to an in-scope URL.',
    riskLevel: 'MEDIUM',
    capabilities: ['BROWSER', 'NETWORK', 'READ_ONLY'],
    requiresScope: true,
    urlFields: ['url'],
    plannedPart: 'Part 4 (Browser worker)',
  },
  {
    name: 'browser.click',
    description: 'Clicks an element in the controlled browser session.',
    riskLevel: 'MEDIUM',
    capabilities: ['BROWSER', 'MUTATION'],
    requiresScope: true,
    plannedPart: 'Part 4 (Browser worker)',
  },
  {
    name: 'browser.fill',
    description: 'Fills a form field in the controlled browser session.',
    riskLevel: 'MEDIUM',
    capabilities: ['BROWSER', 'MUTATION'],
    requiresScope: true,
    plannedPart: 'Part 4 (Browser worker)',
  },
  {
    name: 'browser.submit',
    description: 'Submits a form in the controlled browser session.',
    riskLevel: 'HIGH',
    capabilities: ['BROWSER', 'MUTATION'],
    requiresScope: true,
    plannedPart: 'Part 4 (Browser worker)',
  },
  {
    name: 'browser.snapshot',
    description: 'Captures DOM snapshot + screenshot of the current browser page.',
    riskLevel: 'LOW',
    capabilities: ['BROWSER', 'READ_ONLY'],
    requiresScope: true,
    plannedPart: 'Part 4 (Browser worker)',
  },
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
  {
    name: 'knowledge.search',
    description: 'Searches the security knowledge base (write-ups, vulnerability references).',
    riskLevel: 'LOW',
    capabilities: ['READ_ONLY'],
    requiresScope: false,
    plannedPart: 'Part 5 (Knowledge)',
  },
  {
    name: 'knowledge.fetch',
    description: 'Fetches a knowledge base reference and returns its content.',
    riskLevel: 'LOW',
    capabilities: ['READ_ONLY'],
    requiresScope: false,
    plannedPart: 'Part 5 (Knowledge)',
  },
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
