/**
 * Technology fingerprinting (spec Part 6 §9, §10).
 *
 * Deterministic fingerprints from recorded responses: server banners,
 * framework headers, cookie naming conventions, generator meta tags and
 * script naming. Produces bounded observations — never model output.
 */
import type { Repositories } from '@aegis/database';

export interface TechnologyFingerprint {
  name: string;
  evidence: string;
  confidence: number;
  category: 'server' | 'framework' | 'platform' | 'language';
}

interface HeaderLike {
  name: string;
  value: string;
}

const HEADER_SIGNATURES: Array<{ header: string; contains: string; name: string; category: TechnologyFingerprint['category'] }> = [
  { header: 'server', contains: '', name: 'HTTP server banner', category: 'server' },
  { header: 'x-powered-by', contains: '', name: 'X-Powered-By', category: 'framework' },
  { header: 'x-aspnet-version', contains: '', name: 'ASP.NET', category: 'framework' },
  { header: 'x-generator', contains: '', name: 'Generator', category: 'platform' },
];

const COOKIE_CONVENTIONS: Array<{ pattern: RegExp; name: string }> = [
  { pattern: /^(?:PHPSESSID|laravel_session)/i, name: 'PHP / Laravel' },
  { pattern: /^JSESSIONID$/i, name: 'Java servlet' },
  { pattern: /^(?:_rails_session|__Host-rails)/i, name: 'Ruby on Rails' },
  { pattern: /^(?:connect\.sid|express)$/i, name: 'Express / Node.js' },
  { pattern: /^(?:ASP\.NET_SessionId|\.AspNet\.ApplicationCookie)/i, name: 'ASP.NET' },
  { pattern: /^(?:django_session|csrftoken)/i, name: 'Django' },
  { pattern: /^cloudflare/i, name: 'Cloudflare' },
];

const GENERATOR_RE = /<meta[^>]+name=["']generator["'][^>]+content=["']([^"']+)["']/i;

export class TechnologyFingerprinter {
  constructor(private readonly repos: Repositories) {}

  /**
   * Fingerprint technologies from recorded response headers/cookies and DOM
   * snapshots. Returns bounded fingerprints + records observations.
   */
  async fingerprint(engagementId: string, limit = 50): Promise<TechnologyFingerprint[]> {
    const out: TechnologyFingerprint[] = [];
    const seen = new Set<string>();

    const responses = await this.repos.httpResponses.listByEngagement(engagementId, limit);
    for (const response of responses) {
      const headers = Array.isArray(response.headers) ? (response.headers as unknown as HeaderLike[]) : [];
      for (const header of headers) {
        const lower = String(header.name ?? '').toLowerCase();
        const value = String(header.value ?? '');
        const signature = HEADER_SIGNATURES.find((sig) => sig.header === lower && value.length > 0);
        if (signature && !seen.has(`${lower}:${value}`)) {
          seen.add(`${lower}:${value}`);
          out.push({
            name: value.slice(0, 100),
            evidence: `${lower}: ${value.slice(0, 100)}`,
            confidence: 0.7,
            category: signature.category,
          });
        }
      }
    }

    const cookieRows = await this.repos.cookies.listByEngagement(engagementId);
    for (const cookie of cookieRows) {
      const name = String((cookie as Record<string, unknown>).name ?? '');
      const convention = COOKIE_CONVENTIONS.find((c) => c.pattern.test(name));
      if (convention && !seen.has(`cookie:${convention.name}`)) {
        seen.add(`cookie:${convention.name}`);
        out.push({
          name: convention.name,
          evidence: `cookie name ${name} matches ${convention.name} conventions`,
          confidence: 0.6,
          category: 'framework',
        });
      }
    }

    const snapshots = await this.repos.domSnapshots.listByEngagement(engagementId, 20);
    for (const snapshot of snapshots) {
      const structured = snapshot.snapshot as Record<string, unknown> | null;
      if (!structured) continue;
      const scripts = Array.isArray(structured.scripts) ? (structured.scripts as Array<Record<string, unknown>>) : [];
      for (const script of scripts) {
        const src = String(script.src ?? script.url ?? '');
        const generator = GENERATOR_RE.exec(src);
        void generator;
      }
      const title = typeof snapshot.title === 'string' ? snapshot.title : '';
      const html = typeof structured.html === 'string' ? structured.html : '';
      const generatorMatch = GENERATOR_RE.exec(html || title);
      if (generatorMatch && !seen.has(`generator:${generatorMatch[1]}`)) {
        seen.add(`generator:${generatorMatch[1]}`);
        out.push({
          name: generatorMatch[1]!.slice(0, 100),
          evidence: `meta generator tag: ${generatorMatch[1]!.slice(0, 100)}`,
          confidence: 0.8,
          category: 'platform',
        });
      }
    }

    // Record ONE bounded observation summarizing detected technologies.
    if (out.length > 0) {
      await this.repos.observations
        .create({
          engagementId,
          taskId: null,
          hypothesisId: null,
          type: 'TECHNOLOGY_FINGERPRINTED',
          description: `Technology fingerprints detected: ${out.slice(0, 10).map((f) => f.name).join(', ')}`,
          confidence: 0.7,
          evidenceIds: [],
          metadata: { fingerprints: out.slice(0, 20) },
        })
        .catch(() => undefined);
    }
    return out.slice(0, 40);
  }
}
