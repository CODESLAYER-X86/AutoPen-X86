/** Shared helpers for the scripts/db/* lifecycle scripts. */
import { execFileSync } from 'node:child_process';
import { existsSync, mkdirSync, symlinkSync } from 'node:fs';
import { createRequire } from 'node:module';
import { dirname, join, resolve } from 'node:path';
import { Client } from 'pg';

const require = createRequire(import.meta.url);

export const REPO_ROOT = resolve(import.meta.dirname, '..', '..');
export const PG_DATA_DIR = join(REPO_ROOT, 'data', 'pg');
export const PG_LOG_FILE = join(REPO_ROOT, 'data', 'pg.log');
export const PG_HOST = '127.0.0.1';
export const PG_PORT = 5433;
export const DATABASES = ['aegis', 'aegis_test'];

function packageNativeRoot(): string {
  // Resolve the package root without relying on the "./package.json" subpath:
  // @embedded-postgres/linux-x64 exposes only "." (dist/index.js) in its exports
  // map, so require.resolve('<pkg>/package.json') throws ERR_PACKAGE_PATH_NOT_EXPORTED.
  // Strategy: resolve the exposed entry, walk up to the package root, then verify
  // the native binaries exist; fall back to the plain node_modules path.
  const rootByExport = (() => {
    try {
      const entry = require.resolve('@embedded-postgres/linux-x64');
      // entry = <pkgroot>/dist/index.js -> package root is one level above dist/
      return join(dirname(entry), '..');
    } catch {
      return undefined;
    }
  })();
  const candidates = [
    ...(rootByExport ? [rootByExport] : []),
    join(REPO_ROOT, 'node_modules', '@embedded-postgres', 'linux-x64'),
  ];
  const root = candidates.find((candidate) => existsSync(join(candidate, 'native', 'bin', 'postgres')));
  if (!root) {
    throw new Error(`[db] @embedded-postgres/linux-x64 native root not found; tried: ${candidates.join(', ')}`);
  }
  return root;
}

export function pgBin(name: 'initdb' | 'pg_ctl' | 'postgres'): string {
  return join(packageNativeRoot(), 'native', 'bin', name);
}

/**
 * Environment for the native PostgreSQL binaries. The package vendors its own
 * ICU 60 / OpenSSL 1.1 shared libraries under native/lib, which newer host
 * systems no longer ship; expose them through LD_LIBRARY_PATH so initdb,
 * pg_ctl and postgres resolve their load-time dependencies regardless of the
 * host's library versions.
 */
function pgProcessEnv(): NodeJS.ProcessEnv {
  const vendoredLib = join(packageNativeRoot(), 'native', 'lib');
  ensureVendoredSonameSymlinks(vendoredLib);
  const existing = process.env.LD_LIBRARY_PATH ?? '';
  const ldPath = existing ? `${vendoredLib}:${existing}` : vendoredLib;
  return { ...process.env, LD_LIBRARY_PATH: ldPath };
}

/**
 * The vendored ICU 60 libraries ship as libicuuc.so.60.2 etc. without the
 * SONAME symlinks the dynamic linker needs (libicuuc.so.60). Create the
 * missing links once so the binaries resolve their load-time dependencies
 * on hosts that no longer provide ICU 60 system-wide. Idempotent.
 */
function ensureVendoredSonameSymlinks(vendoredLib: string): void {
  const links: Array<[target: string, link: string]> = [
    ['libicudata.so.60.2', 'libicudata.so.60'],
    ['libicui18n.so.60.2', 'libicui18n.so.60'],
    ['libicuuc.so.60.2', 'libicuuc.so.60'],
  ];
  for (const [target, link] of links) {
    const linkPath = join(vendoredLib, link);
    if (existsSync(linkPath)) continue;
    if (existsSync(join(vendoredLib, target))) {
      symlinkSync(target, linkPath);
    }
  }
}

export function adminConnectionString(): string {
  return `postgres://postgres@${PG_HOST}:${PG_PORT}/postgres`;
}

export async function isPostgresRunning(): Promise<boolean> {
  const client = new Client({ connectionString: adminConnectionString(), connectionTimeoutMillis: 1500 });
  try {
    await client.connect();
    await client.query('SELECT 1');
    await client.end();
    return true;
  } catch {
    try {
      await client.end();
    } catch {
      /* ignore */
    }
    return false;
  }
}

export function initCluster(): void {
  if (existsSync(join(PG_DATA_DIR, 'PG_VERSION'))) return;
  mkdirSync(join(REPO_ROOT, 'data'), { recursive: true });
  // Trust auth on localhost only: acceptable for a local development cluster
  // that listens on 127.0.0.1 (documented in docs/operations/development.md).
  execFileSync(pgBin('initdb'), ['-D', PG_DATA_DIR, '-U', 'postgres', '-A', 'trust', '-E', 'UTF8'], {
    stdio: 'inherit',
    env: pgProcessEnv(),
  });
}

export function startCluster(): void {
  execFileSync(
    pgBin('pg_ctl'),
    ['-D', PG_DATA_DIR, '-l', PG_LOG_FILE, '-o', `-p ${PG_PORT} -h ${PG_HOST}`, '-w', 'start'],
    { stdio: 'inherit', env: pgProcessEnv() },
  );
}

export function stopCluster(): void {
  execFileSync(pgBin('pg_ctl'), ['-D', PG_DATA_DIR, '-m', 'fast', 'stop'], {
    stdio: 'inherit',
    env: pgProcessEnv(),
  });
}

export async function ensureDatabases(): Promise<void> {
  const client = new Client({ connectionString: adminConnectionString() });
  await client.connect();
  try {
    for (const db of DATABASES) {
      const result = await client.query('SELECT 1 FROM pg_database WHERE datname = $1', [db]);
      if (result.rowCount === 0) {
        await client.query(`CREATE DATABASE "${db}"`);
        console.log(`[db] created database ${db}`);
      }
    }
  } finally {
    await client.end();
  }
}

/** Start the cluster if it is not already running and ensure databases. */
export async function ensureRunning(): Promise<void> {
  if (!(await isPostgresRunning())) {
    initCluster();
    startCluster();
  }
  await ensureDatabases();
}
