import { defineConfig } from 'vitest/config';
import { workspaceAliases } from './vitest.shared.js';

export default defineConfig({
  resolve: { alias: workspaceAliases() },
  test: {
    include: ['tests/security/**/*.test.ts'],
    environment: 'node',
    globalSetup: ['tests/integration/global-setup.ts'],
    hookTimeout: 30_000,
    testTimeout: 30_000,
    fileParallelism: false,
  },
});
