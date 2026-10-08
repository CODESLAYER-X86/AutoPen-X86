import { defineConfig } from 'vitest/config';
import { workspaceAliases } from './vitest.shared.js';

export default defineConfig({
  resolve: { alias: workspaceAliases() },
  test: {
    include: ['tests/unit/**/*.test.ts'],
    environment: 'node',
  },
});
