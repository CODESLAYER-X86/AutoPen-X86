/**
 * Security taxonomy mappings and deterministic query expansion (spec Part 5
 * §21, §58, §100-§101).
 *
 * Everything in this module is DETERMINISTIC: no model call decides how a
 * query is expanded or which CTF clue concept is retrieved. Bounded
 * expansion (§21) keeps queries focused instead of exploding the search.
 */
import type { SecurityTaxonomyCategory } from '@aegis/shared';

/** Bounded synonym/expansion map (§21). Values are used for keyword AND
 *  embedding query text — never as separate network calls. */
const QUERY_EXPANSIONS: Record<string, string[]> = {
  idor: ['object-level authorization', 'insecure direct object reference', 'horizontal authorization'],
  'object authorization': ['object-level authorization', 'resource ownership', 'horizontal authorization'],
  authorization: ['access control', 'authorization matrix', 'object-level authorization'],
  authentication: ['login', 'credential validation', 'identity verification'],
  session: ['session management', 'cookie security', 'session fixation'],
  jwt: ['json web token', 'token validation', 'audience validation'],
  xss: ['cross-site scripting', 'script injection', 'html injection'],
  csrf: ['cross-site request forgery', 'anti-csrf token', 'same-site cookie'],
  ssrf: ['server-side request forgery', 'internal url fetch'],
  graphql: ['graphql introspection', 'graphql authorization', 'query depth'],
  websocket: ['websocket authentication', 'websocket origin validation'],
  'business logic': ['workflow logic flaw', 'state transition abuse'],
  'race condition': ['time-of-check time-of-use', 'concurrent modification'],
  'legacy api': ['deprecated endpoint', 'old api version', 'stale endpoint'],
  'api security': ['api authorization', 'broken object level authorization', 'excessive data exposure'],
};

/** Taxonomy keyword hints — deterministic category detection (§58). */
const CATEGORY_KEYWORDS: Record<SecurityTaxonomyCategory, string[]> = {
  AUTHENTICATION: ['login', 'logout', 'password', 'credential', 'mfa', '2fa', 'jwt', 'token issuance'],
  AUTHORIZATION: ['authorization', 'access control', 'permission', 'rbac', 'idor', 'ownership', 'role'],
  SESSION: ['session', 'cookie', 'same-site', 'samesite', 'session id', 'session fixation', 'csrf'],
  INPUT_VALIDATION: ['input validation', 'sanitization', 'schema validation', 'type checking'],
  INJECTION: ['injection', 'sql injection', 'sqli', 'command injection', 'nosql', 'template injection'],
  XSS: ['xss', 'cross-site scripting', 'script injection', 'csp', 'content security policy'],
  CSRF: ['csrf', 'cross-site request forgery', 'anti-csrf', 'origin validation'],
  SSRF: ['ssrf', 'server-side request forgery', 'url fetch', 'internal network access'],
  FILE_HANDLING: ['file upload', 'path traversal', 'directory listing', 'file inclusion', 'mime check'],
  API: ['api', 'rest', 'endpoint', 'versioning', 'rate limit', 'excessive data'],
  GRAPHQL: ['graphql', 'introspection', 'query depth', 'batch query', 'graphql directive'],
  WEBSOCKET: ['websocket', 'ws protocol', 'origin header', 'subprotocol'],
  BUSINESS_LOGIC: ['business logic', 'workflow', 'state machine', 'order of operations', 'price manipulation'],
  RACE_CONDITION: ['race condition', 'concurrency', 'toctou', 'parallel request'],
  CRYPTO: ['cryptography', 'weak hash', 'random', 'padding oracle', 'ecb', 'key management'],
  CONFIGURATION: ['misconfiguration', 'debug mode', 'default credential', 'cors', 'verbose error'],
  INFORMATION_DISCLOSURE: ['information disclosure', 'verbose error', 'stack trace', 'sensitive data exposure', 'backup file'],
  CLIENT_SIDE: ['javascript', 'client-side', 'dom', 'source map', 'local storage'],
};

/**
 * CTF riddle concept map (§100-§101): clue vocabulary maps to BOUNDED sets
 * of technical concepts. The knowledge system never decides the answer —
 * it expands the search space; the leader chooses from target evidence.
 */
const CTF_CONCEPT_MAP: Record<string, string[]> = {
  old: ['legacy api', 'deprecated endpoint', 'old authentication', 'archived route'],
  forgotten: ['legacy api', 'deprecated endpoint', 'backup file', 'archived route', 'stale session'],
  door: ['authentication', 'login bypass', 'access control', 'session management'],
  remembers: ['stale session', 'session persistence', 'cookie lifetime', 'cached credential'],
  version: ['api versioning', 'deprecated endpoint', 'version difference', 'old api version'],
  answers: ['deprecated endpoint', 'legacy api', 'zombie endpoint', 'hidden route'],
  key: ['hardcoded key', 'weak cryptography', 'api key leakage', 'jwt secret'],
  secret: ['hardcoded secret', 'sensitive data exposure', 'configuration disclosure'],
  admin: ['privilege escalation', 'role manipulation', 'authorization bypass'],
  hidden: ['hidden parameter', 'undocumented endpoint', 'comment disclosure', 'source map'],
  backup: ['backup file', 'old source', 'git directory exposure', 'archive file'],
  cache: ['cached response', 'cache poisoning', 'stale content', 'cdn behavior'],
  ghost: ['zombie endpoint', 'stale session', 'deprecated route', 'orphaned token'],
  watch: ['websocket', 'event stream', 'long polling', 'server-sent events'],
  tower: ['port scan', 'service discovery', 'uncommon port', 'banner grab'],
  past: ['old api version', 'deprecated endpoint', 'archive', 'git history'],
};

/** Deterministic bounded query expansion (§21). */
export function expandQuery(query: string, maxExpansions = 5): string[] {
  const lowered = ` ${query.toLowerCase()} `;
  const found = new Set<string>();
  for (const [term, expansions] of Object.entries(QUERY_EXPANSIONS)) {
    if (lowered.includes(` ${term} `) || lowered.includes(`${term} `) || lowered.includes(` ${term}`) || lowered.includes(term)) {
      for (const expansion of expansions) found.add(expansion);
    }
  }
  return [...found].slice(0, maxExpansions);
}

/** Deterministic category detection from text (taxonomy alignment §58). */
export function detectCategories(text: string, maxCategories = 4): SecurityTaxonomyCategory[] {
  const lowered = text.toLowerCase();
  const scored: Array<{ category: SecurityTaxonomyCategory; score: number }> = [];
  for (const [category, keywords] of Object.entries(CATEGORY_KEYWORDS) as Array<
    [SecurityTaxonomyCategory, string[]]
  >) {
    let score = 0;
    for (const keyword of keywords) {
      if (lowered.includes(keyword)) score += keyword.split(' ').length;
    }
    if (score > 0) scored.push({ category, score });
  }
  scored.sort((a, b) => b.score - a.score);
  return scored.slice(0, maxCategories).map((s) => s.category);
}

/**
 * CTF clue interpretation (§100-§101): clue words map to bounded technical
 * concept candidates. The system returns CANDIDATE PATTERNS — never a
 * decision; the leader evaluates them against target evidence (§124).
 */
export function ctfClueConcepts(clue: string, maxConcepts = 8): Array<{ word: string; concepts: string[] }> {
  const lowered = clue.toLowerCase();
  const matches: Array<{ word: string; concepts: string[] }> = [];
  for (const [word, concepts] of Object.entries(CTF_CONCEPT_MAP)) {
    if (lowered.includes(word)) {
      matches.push({ word, concepts: concepts.slice(0, 4) });
    }
  }
  return matches.slice(0, maxConcepts);
}

/** Flatten clue concept candidates into a deduplicated concept list. */
export function ctfConceptList(clue: string): string[] {
  const concepts = new Set<string>();
  for (const { concepts: list } of ctfClueConcepts(clue)) {
    for (const concept of list) concepts.add(concept);
  }
  return [...concepts];
}
