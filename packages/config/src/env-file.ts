/**
 * Minimal .env file parser (KEY=VALUE lines, comments with #).
 * Kept dependency-free so configuration can load before anything else.
 */
import { readFileSync } from 'node:fs';

export function parseEnvFile(contents: string): Record<string, string> {
  const out: Record<string, string> = {};
  for (const rawLine of contents.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (line === '' || line.startsWith('#')) continue;
    const eq = line.indexOf('=');
    if (eq <= 0) continue;
    const key = line.slice(0, eq).trim();
    let value = line.slice(eq + 1).trim();
    // Strip matched surrounding quotes.
    if (
      (value.startsWith('"') && value.endsWith('"') && value.length >= 2) ||
      (value.startsWith("'") && value.endsWith("'") && value.length >= 2)
    ) {
      value = value.slice(1, -1);
    }
    out[key] = value;
  }
  return out;
}

export function readEnvFile(path: string): Record<string, string> {
  try {
    return parseEnvFile(readFileSync(path, 'utf8'));
  } catch {
    return {}; // Missing .env is not an error; real env still applies.
  }
}
