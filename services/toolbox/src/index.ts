export * from './part3-tools.js';
export * from './har-tools.js';

import type { ToolDefinition } from '@aegis/tools';
import { createHttpTools, createBrowserTools, createWebsocketTools, createArtifactTools, type ToolboxDeps } from './part3-tools.js';
import { createHarTools } from './har-tools.js';

/** All Part 3 interaction-layer tools, ready for registry registration. */
export function createPart3Tools(deps: ToolboxDeps): ToolDefinition[] {
  return [
    ...createHttpTools(deps),
    ...createBrowserTools(deps),
    ...createWebsocketTools(deps),
    ...createArtifactTools(deps),
    ...createHarTools(deps),
  ];
}
