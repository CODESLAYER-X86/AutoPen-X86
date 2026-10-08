import { ToolRegistry } from './registry.js';
import { jwtDecodeTool } from './builtins/jwt.js';
import { createStubTools } from './builtins/stubs.js';

/** Registry with the Part 1 tool surface: 1 real deterministic tool + planned interfaces. */
export function createDefaultToolRegistry(): ToolRegistry {
  const registry = new ToolRegistry();
  registry.register(jwtDecodeTool);
  registry.registerAll(createStubTools());
  return registry;
}

export * from './registry.js';
export * from './gateway.js';
export * from './types.js';
export * from './builtins/jwt.js';
export * from './builtins/stubs.js';
