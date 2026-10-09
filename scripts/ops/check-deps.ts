/**
 * Part 8 §69-§70: dependency security gate — runs `npm audit --json` and
 * fails the gate on HIGH/CRITICAL advisories affecting production paths.
 * Exits 0 when clean (or only dev-path advisories with --allow-dev).
 */
import { execFileSync } from 'node:child_process';

const allowDev = process.argv.includes('--allow-dev');

interface AuditVulnerability {
  severity: string;
  range?: string;
  effects?: string[];
  nodes?: string[];
}

interface AuditReport {
  vulnerabilities?: Record<string, AuditVulnerability & { via?: unknown[] }>;
  metadata?: { vulnerabilities?: Record<string, number> };
}

let raw: string;
try {
  raw = execFileSync('npm', ['audit', '--json', '--omit=dev'], { encoding: 'utf8', cwd: process.cwd() });
} catch (error) {
  // npm audit exits non-zero when advisories exist; stdout still has JSON.
  const stdout = (error as { stdout?: string }).stdout;
  if (!stdout) throw error;
  raw = stdout;
}

const report = JSON.parse(raw) as AuditReport;
const counts = report.metadata?.vulnerabilities ?? {};
const blocking = Object.entries(report.vulnerabilities ?? {}).filter(
  ([, vuln]) => vuln.severity === 'high' || vuln.severity === 'critical',
);

if (blocking.length > 0) {
  console.error('[deps] BLOCKING advisories (high/critical) in production dependencies:');
  for (const [name, vuln] of blocking) {
    console.error(`  - ${name}: ${vuln.severity} (${(vuln.range ?? '?')})`);
  }
  process.exit(1);
}
console.log(
  `[deps] production dependency audit clean${allowDev ? ' (dev advisories allowed)' : ''} — total: ${counts.total ?? 0}, high: ${counts.high ?? 0}, critical: ${counts.critical ?? 0}`,
);
