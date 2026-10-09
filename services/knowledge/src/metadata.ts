/**
 * Deterministic metadata extraction (spec Part 5 §57, §74-§76).
 *
 * Extracts titles, authors, dates, CVE/CWE/OWASP/RFC references,
 * technologies, HTTP methods and protocols with REGULAR EXPRESSIONS — no
 * model involvement (§106: the tactical model never spends tokens
 * discovering basic source metadata).
 *
 * A CVE reference is knowledge, NOT evidence of target vulnerability (§76).
 */
import type { SecurityTaxonomyCategory } from '@aegis/shared';
import { detectCategories } from './taxonomy.js';
import type { ParsedDocument } from './parsers.js';

export interface ExtractedReference {
  kind: 'CVE' | 'CWE' | 'OWASP' | 'RFC' | 'OTHER';
  value: string;
  context: string | null;
}

export interface ExtractedMetadata {
  author: string | null;
  language: string | null;
  publishedAt: string | null;
  technologies: string[];
  cveRefs: string[];
  cweRefs: string[];
  owaspRefs: string[];
  httpMethods: string[];
  protocols: string[];
  securityCategories: SecurityTaxonomyCategory[];
  references: ExtractedReference[];
}

const CVE_RE = /\bCVE-(\d{4})-(\d{4,7})\b/gi;
const CWE_RE = /\bCWE-(\d{1,4})\b/gi;
const OWASP_RE = /\bOWASP\s+(?:Top\s*Ten|WSTG|ASVS|API\s*Security\s*Top\s*10|(?:A\d{1,2}(?::[\w\d-]+)?))\b/gi;
const RFC_RE = /\bRFC\s?(\d{3,5})\b/gi;
const DATE_RE =
  /\b(\d{4})-(\d{2})-(\d{2})(?:[T ](\d{2}):(\d{2})(?::(\d{2}))?Z?)?\b|\b(January|February|March|April|May|June|July|August|September|October|November|December)\s+(\d{1,2}),?\s+(\d{4})\b/i;
const METHOD_RE = /\b(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\b\s+(?:\/|https?:)/g;

/** Framework/technology fingerprints (§74) — deterministic, bounded. */
const TECHNOLOGY_FINGERPRINTS: Array<{ name: string; patterns: RegExp[] }> = [
  { name: 'Express', patterns: [/express(?:\.js)?/i, /x-powered-by:\s*express/i] },
  { name: 'Next.js', patterns: [/next\.?js/i, /__NEXT_DATA__/] },
  { name: 'React', patterns: [/react/i] },
  { name: 'Django', patterns: [/django/i] },
  { name: 'Flask', patterns: [/flask/i] },
  { name: 'Laravel', patterns: [/laravel/i] },
  { name: 'Spring', patterns: [/spring(?:\s?(?:boot|framework|security))?/i] },
  { name: 'GraphQL', patterns: [/graphql/i] },
  { name: 'WebSocket', patterns: [/websocket|\bws:\/\//i] },
  { name: 'JWT', patterns: [/\bjwt\b|json web token/i] },
  { name: 'OAuth', patterns: [/\boauth(?:\s?[12]\.?\d?)?\b/i] },
  { name: 'SAML', patterns: [/\bsaml\b/i] },
  { name: 'Redis', patterns: [/\bredis\b/i] },
  { name: 'Node.js', patterns: [/node(?:\.js)?\b/i] },
  { name: 'Apache', patterns: [/apache(?:\shttpd)?/i] },
  { name: 'Nginx', patterns: [/\bnginx\b/i] },
];

const MONTHS: Record<string, string> = {
  january: '01',
  february: '02',
  march: '03',
  april: '04',
  may: '05',
  june: '06',
  july: '07',
  august: '08',
  september: '09',
  october: '10',
  november: '11',
  december: '12',
};

function collect(text: string, re: RegExp, transform: (m: RegExpExecArray) => string, max: number): string[] {
  const out = new Set<string>();
  re.lastIndex = 0;
  let match: RegExpExecArray | null;
  while ((match = re.exec(text)) !== null) {
    out.add(transform(match));
    if (out.size >= max) break;
  }
  return [...out];
}

/** Context window (±60 chars) around a reference for provenance. */
function contextAround(text: string, index: number): string | null {
  const start = Math.max(0, index - 60);
  const end = Math.min(text.length, index + 60);
  return text.slice(start, end).replace(/\s+/g, ' ').trim() || null;
}

function extractReferences(text: string): ExtractedReference[] {
  const references: ExtractedReference[] = [];
  const seen = new Set<string>();
  const push = (kind: ExtractedReference['kind'], value: string, index: number) => {
    const key = `${kind}:${value}`;
    if (seen.has(key) || references.length >= 64) return;
    seen.add(key);
    references.push({ kind, value, context: contextAround(text, index) });
  };
  CVE_RE.lastIndex = 0;
  let match: RegExpExecArray | null;
  while ((match = CVE_RE.exec(text)) !== null) {
    push('CVE', `CVE-${match[1]}-${match[2]}`, match.index);
  }
  while ((match = CWE_RE.exec(text)) !== null) {
    push('CWE', `CWE-${match[1]}`, match.index);
  }
  while ((match = OWASP_RE.exec(text)) !== null) {
    push('OWASP', match[0].replace(/\s+/g, ' ').trim().toUpperCase(), match.index);
  }
  while ((match = RFC_RE.exec(text)) !== null) {
    push('RFC', `RFC ${match[1]}`, match.index);
  }
  return references;
}

function extractPublishedAt(text: string, parserMeta: Record<string, string>): string | null {
  const fromMeta = parserMeta['date'];
  if (fromMeta && /^\d{4}-\d{2}-\d{2}/.test(fromMeta)) {
    return fromMeta.length > 10 ? `${fromMeta.slice(0, 10)}T00:00:00Z` : `${fromMeta}T00:00:00Z`;
  }
  const match = DATE_RE.exec(text);
  if (!match) return null;
  if (match[1]) {
    const iso = `${match[1]}-${match[2]}-${match[3]}`;
    if (match[4] && match[5]) {
      return `${iso}T${match[4]}:${match[5]}:${match[6] ?? '00'}Z`;
    }
    return `${iso}T00:00:00Z`;
  }
  if (match[7] && match[8] && match[9]) {
    const month = MONTHS[match[7].toLowerCase()];
    if (!month) return null;
    const day = match[8].padStart(2, '0');
    return `${match[9]}-${month}-${day}T00:00:00Z`;
  }
  return null;
}

/** Deterministic metadata extraction over parsed text (§57). */
export function extractMetadata(text: string, parsed: ParsedDocument): ExtractedMetadata {
  const cveRefs = collect(text, CVE_RE, (m) => `CVE-${m[1]}-${m[2]}`, 64);
  const cweRefs = collect(text, CWE_RE, (m) => `CWE-${m[1]}`, 64);
  const owaspRefs = collect(text, OWASP_RE, (m) => m[0].replace(/\s+/g, ' ').trim().toUpperCase(), 64);
  const httpMethods = collect(text, METHOD_RE, (m) => m[1]!.toUpperCase(), 16);
  const protocols = [...new Set([
    ...collect(text, /\bhttps?:\/\/|https?/gi, () => 'HTTP', 1),
    ...collect(text, /\bws[s]?:\/\/|websocket/i, () => 'WebSocket', 1),
    ...collect(text, /\bgraphql\b/i, () => 'GraphQL', 1),
    ...collect(text, /\bsaml\b/i, () => 'SAML', 1),
    ...collect(text, /\boauth\b/i, () => 'OAuth', 1),
    ...collect(text, /\bxmlrpc\b/i, () => 'XML-RPC', 1),
  ])].slice(0, 8);

  const technologies: string[] = [];
  for (const tech of TECHNOLOGY_FINGERPRINTS) {
    if (technologies.length >= 16) break;
    if (tech.patterns.some((pattern) => pattern.test(text))) technologies.push(tech.name);
  }

  const securityCategories = detectCategories(text, 8);
  const references = extractReferences(text);

  return {
    author: parsed.meta['author']?.slice(0, 256) ?? null,
    language: parsed.meta['lang']?.slice(0, 16) ?? null,
    publishedAt: extractPublishedAt(text, parsed.meta),
    technologies,
    cveRefs,
    cweRefs,
    owaspRefs,
    httpMethods,
    protocols,
    securityCategories,
    references,
  };
}
