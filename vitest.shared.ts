/** Shared vitest setup: workspace aliases point at package sources. */
import { resolve } from 'node:path';

export const REPO_ROOT = resolve(__dirname);

export function workspaceAliases(): Record<string, string> {
  const packages = [
    'shared',
    'contracts',
    'logging',
    'config',
    'security',
    'database',
    'events',
    'queue',
    'model-runtime',
    'tools',
  ];
  const services = [
    'orchestrator',
    'evidence',
    'target-http',
    'browser',
    'worker-runtime',
    'agent',
    'knowledge',
    'session-manager',
    'toolbox',
    'reasoning',
    'autonomous-engine',
    'verification-reporting',
    'production-hardening',
  ];
  const aliases: Record<string, string> = {};
  for (const name of packages) {
    aliases[`@aegis/${name}`] = resolve(REPO_ROOT, `packages/${name}/src/index.ts`);
  }
  for (const name of services) {
    aliases[`@aegis/${name}`] = resolve(REPO_ROOT, `services/${name}/src/index.ts`);
  }
  return aliases;
}

export const TEST_DATABASE_URL =
  process.env.TEST_DATABASE_URL ?? 'postgres://postgres:postgres@127.0.0.1:5433/aegis_test';
