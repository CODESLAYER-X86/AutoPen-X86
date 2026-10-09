/**
 * Tool registry with metadata validation (spec §33: "tool metadata
 * validation"). A definition that fails validation is rejected at
 * registration time, not at invocation time.
 */
import { ValidationError, type ToolCapability } from '@aegis/shared';
import type { ToolDescriptor } from '@aegis/contracts';
import type { ToolDefinition } from './types.js';

const NAME_PATTERN = /^[a-z][a-z0-9]*(\.[a-z0-9_-]+)+$/;
const VERSION_PATTERN = /^\d+\.\d+\.\d+$/;
const VALID_CAPABILITIES: ToolCapability[] = [
  'READ_ONLY',
  'NETWORK',
  'BROWSER',
  'MUTATION',
  'AUTHENTICATED',
  'DESTRUCTIVE',
  // Part 5 §84: knowledge capability family.
  'KNOWLEDGE_LOCAL_READ',
  'KNOWLEDGE_WEB_SEARCH',
  'KNOWLEDGE_WEB_FETCH',
  'KNOWLEDGE_CASE_MEMORY',
];

export function validateToolDefinition(tool: ToolDefinition): void {
  const fail = (message: string): never => {
    throw new ValidationError(`Invalid tool definition for '${tool?.name ?? '(unknown)'}': ${message}`, 'TOOL_METADATA_INVALID');
  };

  if (!tool || typeof tool !== 'object') fail('definition must be an object');
  if (typeof tool.name !== 'string' || !NAME_PATTERN.test(tool.name)) {
    fail('name must be dotted lowercase (e.g. parser.jwt)');
  }
  if (typeof tool.version !== 'string' || !VERSION_PATTERN.test(tool.version)) {
    fail('version must be semver (e.g. 1.0.0)');
  }
  if (typeof tool.description !== 'string' || tool.description.length < 5 || tool.description.length > 2000) {
    fail('description must be 5..2000 characters');
  }
  if (!tool.inputSchema || typeof tool.inputSchema.safeParse !== 'function') {
    fail('inputSchema must be a zod schema');
  }
  if (!tool.outputSchema || typeof tool.outputSchema.safeParse !== 'function') {
    fail('outputSchema must be a zod schema');
  }
  if (!Array.isArray(tool.capabilities) || tool.capabilities.length === 0) {
    fail('capabilities must be a non-empty array');
  }
  const seen = new Set<string>();
  for (const capability of tool.capabilities) {
    if (!VALID_CAPABILITIES.includes(capability)) fail(`unknown capability '${String(capability)}'`);
    if (seen.has(capability)) fail(`duplicate capability '${capability}'`);
    seen.add(capability);
  }
  if (typeof tool.requiresScope !== 'boolean') fail('requiresScope must be boolean');
  if (typeof tool.implemented !== 'boolean') fail('implemented must be boolean');
  if (typeof tool.execute !== 'function' && tool.implemented) {
    fail('implemented tools must provide an execute function');
  }
}

export class ToolRegistry {
  private readonly tools = new Map<string, ToolDefinition>();

  register(tool: ToolDefinition): this {
    validateToolDefinition(tool);
    if (this.tools.has(tool.name)) {
      throw new ValidationError(`Tool '${tool.name}' is already registered`, 'TOOL_ALREADY_REGISTERED');
    }
    this.tools.set(tool.name, tool);
    return this;
  }

  registerAll(tools: ToolDefinition[]): this {
    for (const tool of tools) this.register(tool);
    return this;
  }

  get(name: string): ToolDefinition | undefined {
    return this.tools.get(name);
  }

  require(name: string): ToolDefinition {
    const tool = this.tools.get(name);
    if (!tool) {
      throw new ValidationError(
        `Unknown tool '${name}'`,
        'TOOL_NOT_FOUND',
        { hint: 'Tool names come from the registry; model-provided names are never trusted' },
      );
    }
    return tool;
  }

  has(name: string): boolean {
    return this.tools.has(name);
  }

  list(): ToolDescriptor[] {
    return [...this.tools.values()].map((tool) => ({
      name: tool.name,
      version: tool.version,
      description: tool.description,
      risk_level: tool.riskLevel,
      capabilities: tool.capabilities,
      requires_scope: tool.requiresScope,
      requires_identity: tool.requiresIdentity ?? false,
      implemented: tool.implemented,
      ...(tool.plannedPart ? { planned_part: tool.plannedPart } : {}),
    }));
  }

  get size(): number {
    return this.tools.size;
  }
}
