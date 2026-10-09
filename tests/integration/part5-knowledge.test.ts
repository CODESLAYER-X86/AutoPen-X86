/**
 * Part 5 integration tests (spec §127-§132) — the knowledge subsystem over
 * the REAL database + migrations:
 *
 *   source seeding        -> curated catalog upsert (§4-§5)
 *   ingestion             -> HTML/MD/PDF/JSON documents -> chunks (§115)
 *   keyword search        -> PostgreSQL FTS (§13)
 *   semantic search       -> hashed embeddings stored + cosine (§14)
 *   hybrid retrieval      -> §127 query set ranks relevant docs first
 *   trust/freshness       -> §129/§130 ordering behaviour
 *   duplicates            -> §67 cross-URL linking
 *   versioning            -> §25 changed content supersedes
 *   CTF case memory       -> §39/§42/§102 write-ups + similar cases
 *   research              -> §72 bounded loop with a fake search provider
 *   query cache           -> §65 cache hit path
 *   agent context seam    -> §87/§120 trust-separated packet
 *   retrieval evaluation  -> §96-§97 metrics over the fixture corpus
 */
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { generateId } from '@aegis/shared';
import { createPool, createRepositories, runMigrations, UsersRepository, EngagementsRepository, ProjectsRepository, type Repositories } from '@aegis/database';
import { InMemoryEventBus } from '@aegis/events';
import { LocalFileSystemObjectStore } from '@aegis/evidence';
import { loadConfig, type AppConfig } from '@aegis/config';
import { KnowledgeEngine, extractPdf, type WebSearchProvider } from '@aegis/knowledge';
import { ResearchEngine, planQueries, classifyDomain, extractRelevantSection } from '@aegis/knowledge';
import { KnowledgeFetcher } from '@aegis/knowledge';
import { computeMetrics } from '@aegis/knowledge';
import { resolve } from 'node:path';

const TEST_DATABASE_URL =
  process.env.TEST_DATABASE_URL ?? 'postgres://postgres:postgres@127.0.0.1:5433/aegis_test';

/** Deterministic fake web search provider (§127 research testing). */
class FakeSearchProvider implements WebSearchProvider {
  readonly id = 'fake';
  readonly model = 'fake-search';
  calls = 0;
  constructor(private readonly results: Array<{ title: string; url: string; snippet: string }>) {}

  async search(
    query: string,
    options: { maxResults: number; domainAllowlist?: string[]; domainDenylist?: string[] },
  ): Promise<{ results: Array<{ title: string; url: string; snippet: string; domain: string }>; note?: string }> {
    this.calls += 1;
    void query;
    void options;
    return {
      results: this.results.slice(0, options.maxResults).map((result) => ({
        ...result,
        domain: new URL(result.url).hostname.toLowerCase(),
      })),
    };
  }
}

let pool: ReturnType<typeof createPool>;
let repos: Repositories;
let config: AppConfig;
let engine: KnowledgeEngine;
let fakeSearch: FakeSearchProvider;
let owaspSourceId: string;
let mirrorSourceId: string;
let ctfSourceId: string;
let engagementId: string;
let eventBus: InMemoryEventBus;

const CORPUS: Array<{ url: string; title: string; source: 'owasp' | 'mirror' | 'ctf'; body: string; published?: string }> = [
  {
    url: 'https://owasp.test/wstg/object-authorization',
    title: 'Testing for Object Level Authorization',
    source: 'owasp',
    published: '2024-06-01',
    body: `# Object Level Authorization

## Description
Object level authorization checks whether a user is permitted to access the specific object they requested. REST APIs frequently use numeric identifiers such as /api/orders/{id}. When the server checks only that the request is authenticated but not that the requester owns the object, any user can access other users' data.

## How to Test
1. Authenticate as user A and request object 7.
2. Authenticate as user B and request the same object 7.
3. Compare the responses for status code and content.
4. Repeat to rule out caching or transient effects.

## Verification
The same object requested under two distinct identities returning identical protected content indicates missing object-level authorization. Consider shared object visibility, public objects and response caching as alternative explanations before reporting.

References: CWE-639, OWASP API Security Top 10 API1:2023.`,
  },
  {
    url: 'https://owasp.test/wstg/jwt-validation',
    title: 'JWT Audience and Algorithm Validation',
    source: 'owasp',
    published: '2023-02-15',
    body: `# JWT Validation

## Audience Validation
JSON Web Tokens carry an aud claim. A token issued for audience A must not grant access to audience B. Missing audience validation allows cross-service token reuse.

## Algorithm Confusion
Never trust the alg header from the token: an attacker can switch RS256 to HS256 and sign with the public key. Pin the allowed algorithms server-side.

\`\`\`javascript
const decoded = jwt.verify(token, key, { algorithms: ['RS256'], audience: 'service-a' });
\`\`\`
`,
  },
  {
    url: 'https://owasp.test/wstg/websocket-auth',
    title: 'WebSocket Authentication and Origin Validation',
    source: 'owasp',
    body: `# WebSocket Authentication

WebSocket connections upgrade from HTTP and inherit none of its authentication unless implemented. The Origin header must be validated against an allowlist to stop cross-site WebSocket hijacking. Authentication tokens must be re-validated on the upgraded connection.

## How to Test
1. Attempt a WebSocket handshake without authentication.
2. Send a handshake with a foreign Origin header.
3. Check whether server-to-client frames continue after the browser leaves the page.`,
  },
  {
    url: 'https://owasp.test/wstg/graphql-authorization',
    title: 'GraphQL Authorization and Depth Attacks',
    source: 'owasp',
    body: `# GraphQL Authorization

GraphQL resolvers each need their own authorization decision. Introspection in production reveals the full schema. Query depth and cost limits prevent resource exhaustion through nested queries.

## How to Test
Query the same object through different resolvers as two identities and compare data exposure; request deeply nested queries to observe depth limiting.`,
  },
  {
    url: 'https://owasp.test/wstg/business-logic',
    title: 'Business Logic Workflow Testing',
    source: 'owasp',
    body: `# Business Logic Testing

Business logic workflow abuse targets multi-step workflows (register, verify, pay, confirm) that must validate state transitions server-side. Skipping steps, repeating steps or completing them out of order reveals missing state validation. Race conditions in concurrent balance updates double-spend resources.

## How to Test
1. Complete steps out of order.
2. Repeat a completed step.
3. Execute two payment confirmations concurrently.`,
  },
  {
    url: 'https://owasp.test/wstg/legacy-api',
    title: 'Legacy and Deprecated API Versions',
    source: 'owasp',
    published: '2021-08-10',
    body: `# Legacy API Discovery

Deprecated API versions frequently remain deployed without security fixes. When v2 of an API exists, v1 may still answer with weaker authorization, missing rate limits or verbose errors. Old authentication mechanisms and archived routes are common CTF patterns.

## How to Test
Request the same resource through each observed API version and compare authorization behavior and error verbosity.`,
  },
  {
    url: 'https://mirror.example/wstg/object-authorization-copy',
    title: 'Object Level Authorization (mirror)',
    source: 'mirror',
    body: `# Object Level Authorization

## Description
Object level authorization checks whether a user is permitted to access the specific object they requested. REST APIs frequently use numeric identifiers such as /api/orders/{id}. When the server checks only that the request is authenticated but not that the requester owns the object, any user can access other users' data.

## How to Test
1. Authenticate as user A and request object 7.
2. Authenticate as user B and request the same object 7.
3. Compare the responses for status code and content.
4. Repeat to rule out caching or transient effects.

## Verification
The same object requested under two distinct identities returning identical protected content indicates missing object-level authorization. Consider shared object visibility, public objects and response caching as alternative explanations before reporting.

References: CWE-639, OWASP API Security Top 10 API1:2023.`,
  },
];

const CTF_CASES = [
  {
    url: 'https://ctf.test/writeups/forgotten-door',
    challenge_name: 'The Forgotten Door',
    event: 'ExampleCTF 2024',
    year: 2024,
    category: 'web',
    difficulty: 'medium',
    description: 'The old door still remembers. An aging login portal hides a legacy endpoint that answers where the new one refuses.',
    technique: 'legacy API discovery',
    body: `The old door still remembers.
Technique: legacy API discovery
Precondition: multiple API versions observed
Signal: new API behavior differs from old API
Verification: compare authorization behavior
False positive: documented backward compatibility`,
  },
  {
    url: 'https://ctf.test/writeups/ghost-session',
    challenge_name: 'Ghost Session',
    event: 'OtherCTF 2023',
    year: 2023,
    category: 'web/auth',
    difficulty: 'easy',
    description: 'A stale session token from a previous deployment still authenticates to the admin area.',
    technique: 'stale session reuse',
    body: `Ghost in the session store.
Technique: stale session reuse
Precondition: old session token captured
Signal: expired token still accepted
Verification: replay after re-login`,
  },
];

beforeAll(async () => {
  pool = createPool(TEST_DATABASE_URL, { max: 4 });
  await runMigrations(pool, resolve(process.cwd(), 'packages', 'database', 'migrations'));
  repos = createRepositories(pool);

  // Knowledge corpus is fixture data: start from a clean knowledge state so
  // ingestion outcomes are deterministic across repeated runs.
  await pool.query(`TRUNCATE TABLE knowledge_cache, knowledge_results, knowledge_queries,
    research_sources, research_tasks, knowledge_references, security_techniques,
    knowledge_chunk_embeddings, knowledge_chunks, knowledge_documents, knowledge_sources,
    knowledge_versions RESTART IDENTITY CASCADE`);

  const temp = mkdtempSync(join(tmpdir(), 'aegis-p5-'));
  config = loadConfig({
    env: {
      NODE_ENV: 'test',
      DATABASE_URL: TEST_DATABASE_URL,
      KNOWLEDGE_EMBEDDING_PROVIDER: 'hash',
      KNOWLEDGE_EMBEDDING_DIMENSION: '256',
      KNOWLEDGE_CACHE_TTL_MS: '600000',
      STORAGE_LOCAL_PATH: join(temp, 'artifacts'),
      SECRET_STORE_PATH: join(temp, 'secrets.json'),
    },
  });

  eventBus = new InMemoryEventBus();
  fakeSearch = new FakeSearchProvider([
    { title: 'SameSite cookies explained', url: 'https://portswigger.net/web-security/csrf/samesite', snippet: 'SameSite Lax cookies are sent on top-level GET navigations only; cross-site POST requests are blocked by the browser.' },
    { title: 'RFC 6265bis cookie rules', url: 'https://rfc-editor.org/rfc6265bis', snippet: 'Under SameSite Lax, cookies accompany top-level GET navigations; cross-site POST requests do not send the cookie.' },
  ]);
  engine = new KnowledgeEngine({
    pool,
    repos,
    config,
    objectStore: new LocalFileSystemObjectStore(config.storage.localPath),
    eventBus,
    webSearchProvider: fakeSearch,
  });

  // A real user + engagement + hypothesis for the agent-context seam (§120).
  const users = new UsersRepository(pool);
  const user = await users.create({
    email: `p5-knowledge-${Date.now()}-${generateId('USR').slice(4).toLowerCase()}@test.local`,
    name: 'Part5 Knowledge Test',
    passwordHash: 'not-a-real-hash',
  });
  const projects = new ProjectsRepository(pool);
  const project = await projects.create({ ownerId: user.id, name: 'Part5 Knowledge Test Project', description: 'knowledge integration corpus' });
  const engagements = new EngagementsRepository(pool);
  const engagement = await engagements.create({
    projectId: project.id,
    name: 'Part5 Knowledge Engagement',
    mode: 'PENTEST',
    description: 'Authorization testing',
  });
  engagementId = engagement.id;
  await repos.hypotheses.create({
    engagementId,
    type: 'AUTHORIZATION',
    statement: 'object-level authorization missing for /api/notes/{id} numeric identifiers',
    status: 'ACTIVE',
    confidence: 0.6,
    priority: 0.8,
    source: 'system',
  });

  // Seed the curated catalog + index version marker (§4, §95).
  const sync = await engine.sync({ seed: true });
  expect(sync.seeded).toBeGreaterThan(0);

  const sources = await repos.knowledgeSources.list({ limit: 500 });
  owaspSourceId = sources.find((s) => s.name.includes('Web Security Testing Guide'))!.id;
  const liveWeb = await repos.knowledgeSources.upsert({
    name: 'Mirror Site (community)',
    type: 'TECHNICAL_DOCUMENTATION',
    baseUrl: 'https://mirror.example',
    trustLevel: 'COMMUNITY',
    enabled: true,
    updateStrategy: 'MANUAL',
    crawlPolicy: { allowed_domains: ['mirror.example'], blocked_domains: [], entry_paths: [], respect_robots: true },
    licenseNotes: null,
  });
  mirrorSourceId = liveWeb.id;
  const ctfSource = await repos.knowledgeSources.upsert({
    name: 'CTF write-ups (test feed)',
    type: 'CTF_WRITEUPS',
    baseUrl: 'https://ctf.test',
    trustLevel: 'CTF',
    enabled: true,
    updateStrategy: 'INCREMENTAL',
    crawlPolicy: { allowed_domains: ['ctf.test'], blocked_domains: [], entry_paths: [], respect_robots: true },
    licenseNotes: null,
  });
  ctfSourceId = ctfSource.id;

  // Ingest the fixture corpus (§115 pipeline end to end). The mirror copy
  // is ingested separately: identical content takes the §67 duplicate path.
  for (const doc of CORPUS.filter((d) => d.source !== 'mirror')) {
    const sourceId = owaspSourceId;
    const outcome = await engine.ingestRaw({
      sourceId,
      url: doc.url,
      bytes: new Uint8Array(Buffer.from(doc.body, 'utf8')),
      contentType: 'text/markdown',
      titleOverride: doc.title,
    });
    expect(outcome.ingestion_status).toBe('INDEXED');
    expect(outcome.chunks_created).toBeGreaterThan(0);
    expect(outcome.embeddings_created).toBeGreaterThan(0);
    // Reference extraction is deterministic (§57): CWE/OWASP-bearing docs
    // produce reference rows; docs without identifiers produce none.
    if (/CWE-|CVE-|OWASP\s/.test(doc.body)) {
      expect(outcome.references_extracted).toBeGreaterThan(0);
    } else {
      expect(outcome.references_extracted).toBe(0);
    }
  }
  // §67: identical content under a different URL links to the canonical
  // document instead of re-indexing.
  const mirror = CORPUS.find((d) => d.source === 'mirror')!;
  const mirrorOutcome = await engine.ingestRaw({
    sourceId: mirrorSourceId,
    url: mirror.url,
    bytes: new Uint8Array(Buffer.from(mirror.body, 'utf8')),
    contentType: 'text/markdown',
    titleOverride: mirror.title,
  });
  expect(mirrorOutcome.duplicate_of).not.toBeNull();
  expect(mirrorOutcome.chunks_created).toBe(0);
  for (const ctf of CTF_CASES) {
    const result = await engine.ingestCtfWriteup({
      sourceId: ctfSourceId,
      url: ctf.url,
      challenge_name: ctf.challenge_name,
      event: ctf.event,
      year: ctf.year,
      category: ctf.category,
      difficulty: ctf.difficulty,
      description: ctf.description,
      technique: ctf.technique,
      body: ctf.body,
    });
    expect(result.patternsStored).toBeGreaterThan(0);
  }
});

afterAll(async () => {
  await pool.end();
});

// ---------------------------------------------------------------------------
// Ingestion, keyword + semantic retrieval (§127).
// ---------------------------------------------------------------------------

describe('part5 ingestion and hybrid retrieval', () => {
  it('ingested documents produce chunks, embeddings and references', async () => {
    const status = await engine.status();
    expect(status.documents).toBeGreaterThanOrEqual(CORPUS.length);
    expect(status.chunks).toBeGreaterThan(10);
    expect(status.embeddings).toBeGreaterThan(10);
    expect(status.techniques).toBeGreaterThanOrEqual(2);
    expect(status.references).toBeGreaterThanOrEqual(2);
    expect(status.embeddingModel).toContain('aegis-hash');
  });

  const QUERY_SET: Array<{ query: string; expectedInTop: string[] }> = [
    { query: 'object level authorization', expectedInTop: ['Object Level Authorization'] },
    { query: 'JWT audience validation', expectedInTop: ['JWT Audience and Algorithm Validation'] },
    { query: 'WebSocket authentication', expectedInTop: ['WebSocket Authentication and Origin Validation'] },
    { query: 'GraphQL authorization', expectedInTop: ['GraphQL Authorization and Depth Attacks'] },
    { query: 'business logic workflow', expectedInTop: ['Business Logic Workflow Testing'] },
    { query: 'legacy API', expectedInTop: ['Legacy and Deprecated API Versions'] },
  ];

  for (const { query, expectedInTop } of QUERY_SET) {
    it(`ranks relevant documents highly for "${query}" (§127)`, async () => {
      const packet = await engine.search(
        { query, engagement_id: null, hypothesis_id: null, categories: [], technologies: [], mode: 'LOCAL_ONLY', max_results: 6, max_tokens: 4000 },
        'integration-test',
      );
      expect(packet.results.length).toBeGreaterThan(0);
      const titles = packet.results.map((r) => r.title);
      for (const expected of expectedInTop) {
        expect(titles.some((title) => title.includes(expected))).toBe(true);
      }
      // Every result carries provenance (§60: no fabricated citations).
      for (const result of packet.results) {
        expect(result.source_name).toBeTruthy();
        expect(result.url).toMatch(/^https:\/\//);
        expect(result.trust_level).toBeTruthy();
      }
      // Retrieval results are persisted for evaluation (§85, §97).
      const rows = await repos.knowledgeResults.findByQuery(packet.query_id);
      expect(rows.length).toBeGreaterThan(0);
      expect(rows.every((row) => row.relevance >= 0 && row.relevance <= 1)).toBe(true);
    });
  }

  it('semantic path contributes: embeddings stored and cosine-ranked (§14)', async () => {
    const vectors = await repos.knowledgeEmbeddings.listVectors('aegis-hash-256-v1', 1000);
    expect(vectors.length).toBeGreaterThan(10);
    // Engine search with a conceptually-phrased query finds the doc without exact terms.
    const packet = await engine.search(
      { query: 'checking whether a requester may access a specific resource they asked for in a REST API', engagement_id: null, hypothesis_id: null, categories: [], technologies: [], mode: 'LOCAL_ONLY', max_results: 5, max_tokens: 3000 },
      'integration-test',
    );
    expect(packet.results.length).toBeGreaterThan(0);
    expect(packet.results.some((r) => r.title.includes('Object Level Authorization'))).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// Trust, freshness, duplicates, versioning (§129, §130, §67, §25).
// ---------------------------------------------------------------------------

describe('part5 trust, freshness, duplicates, versioning', () => {
  it('official source outranks the community mirror for identical content (§67, §129)', async () => {
    const packet = await engine.search(
      { query: 'object level authorization comparison identities', engagement_id: null, hypothesis_id: null, categories: ['AUTHORIZATION'], technologies: [], mode: 'LOCAL_ONLY', max_results: 10, max_tokens: 6000 },
      'integration-test',
    );
    const owaspHits = packet.results.filter((r) => r.source_name.includes('Testing Guide'));
    const mirrorHits = packet.results.filter((r) => r.source_name.includes('Mirror'));
    // The primary (official) content must appear; the duplicate is penalized
    // but provenance is retained (§67).
    expect(owaspHits.length).toBeGreaterThan(0);
    if (mirrorHits.length > 0) {
      expect(owaspHits[0]!.relevance).toBeGreaterThanOrEqual(mirrorHits[0]!.relevance);
    }
  });

  it('freshness is tracked but relevance dominates (§130)', async () => {
    // legacy-api (2021) vs newer docs: the legacy doc still ranks for its topic.
    const packet = await engine.search(
      { query: 'deprecated endpoints and old api versions', engagement_id: null, hypothesis_id: null, categories: [], technologies: [], mode: 'LOCAL_ONLY', max_results: 5, max_tokens: 3000 },
      'integration-test',
    );
    expect(packet.results.some((r) => r.title.includes('Legacy'))).toBe(true);
  });

  it('ingesting the same content at a new URL links to the canonical document (§67)', async () => {
    const canonical = CORPUS[0]!;
    const outcome = await engine.ingestRaw({
      sourceId: mirrorSourceId,
      url: 'https://mirror.example/another-copy-of-object-authorization',
      bytes: new Uint8Array(Buffer.from(canonical.body, 'utf8')),
      contentType: 'text/markdown',
      titleOverride: 'Another copy',
    });
    expect(outcome.duplicate_of).not.toBeNull();
    expect(outcome.chunks_created).toBe(0);
  });

  it('changed content at the same URL creates a new version and supersedes (§25)', async () => {
    const original = await engine.ingestRaw({
      sourceId: owaspSourceId,
      url: 'https://owasp.test/wstg/versioned-doc',
      bytes: new Uint8Array(Buffer.from('# Original\n\nFirst version content about session fixation.', 'utf8')),
      contentType: 'text/markdown',
    });
    expect(original.version).toBe(1);
    const changed = await engine.ingestRaw({
      sourceId: owaspSourceId,
      url: 'https://owasp.test/wstg/versioned-doc',
      bytes: new Uint8Array(Buffer.from('# Updated\n\nSecond version content about session rotation.', 'utf8')),
      contentType: 'text/markdown',
    });
    expect(changed.version).toBe(2);
    expect(changed.new_version).toBe(true);
    const versions = await repos.knowledgeDocuments.listVersions('https://owasp.test/wstg/versioned-doc');
    expect(versions).toHaveLength(2);
    expect(versions.find((v) => v.version === 1)?.is_latest).toBe(false);
    expect(versions.find((v) => v.version === 2)?.is_latest).toBe(true);
    // Idempotent re-ingestion of identical content (§111).
    const again = await engine.ingestRaw({
      sourceId: owaspSourceId,
      url: 'https://owasp.test/wstg/versioned-doc',
      bytes: new Uint8Array(Buffer.from('# Updated\n\nSecond version content about session rotation.', 'utf8')),
      contentType: 'text/markdown',
    });
    expect(again.version).toBe(2);
    expect(again.chunks_created).toBe(0);
  });
});

// ---------------------------------------------------------------------------
// CTF case memory + similar cases (§36-§42, §100, §102).
// ---------------------------------------------------------------------------

describe('part5 ctf case memory', () => {
  it('similar cases: clue phrases retrieve concept-matching write-ups (§100, §124)', async () => {
    const result = await engine.similarCases({
      engagement_id: null,
      observation: 'The old door still remembers',
      hypothesis_category: null,
      technology: null,
      workflow_description: null,
      retrieval_mode: 'PATTERN_RETRIEVAL',
      max_results: 3,
    });
    expect(result.cases.length).toBeGreaterThan(0);
    expect(result.cases.some((c) => c.title.includes('Forgotten Door'))).toBe(true);
    // Patterns, not solutions: the retrieved case carries the technique.
    expect(result.cases.some((c) => c.technique?.includes('legacy API'))).toBe(true);
    expect(result.notes.some((n) => n.includes('Clue concepts expanded'))).toBe(true);
  });

  it('EXACT_CASE_RETRIEVAL matches by challenge name and stays distinct (§102)', async () => {
    const result = await engine.similarCases({
      engagement_id: null,
      observation: 'Ghost Session',
      hypothesis_category: null,
      technology: null,
      workflow_description: null,
      retrieval_mode: 'EXACT_CASE_RETRIEVAL',
      max_results: 3,
    });
    expect(result.cases.some((c) => c.title.includes('Ghost Session'))).toBe(true);
  });

  it('structured patterns landed in security_techniques (§42)', async () => {
    const techniques = await repos.securityTechniques.list(500);
    const legacy = techniques.find((t) => t.name.includes('legacy API discovery'));
    expect(legacy).toBeDefined();
    expect(legacy!.preconditions.some((p) => p.includes('multiple API versions'))).toBe(true);
    expect(legacy!.false_positive_conditions.length).toBeGreaterThan(0);
  });
});

// ---------------------------------------------------------------------------
// Live research with a bounded fake provider (§72, §73, §111, §83).
// ---------------------------------------------------------------------------

describe('part5 research', () => {
  it('planQueries derives a bounded query set (§71)', () => {
    const queries = planQueries('Does SameSite Lax block cross-site POST requests? Are GET top-level navigations exempt?', 3);
    expect(queries.length).toBeGreaterThan(0);
    expect(queries.length).toBeLessThanOrEqual(3);
  });

  it('classifyDomain: search results are UNTRUSTED until classified (§32)', () => {
    expect(classifyDomain('owasp.org', ['owasp.org'])).toBe('OFFICIAL');
    expect(classifyDomain('portswigger.net', ['owasp.org'])).toBe('TRUSTED_TRAINING');
    expect(classifyDomain('ctftime.org', ['ctftime.org'])).toBe('CTF');
    expect(classifyDomain('random-unknown.test', [])).toBe('UNTRUSTED');
  });

  it('extractRelevantSection picks the query-relevant window (§31)', () => {
    const page = 'irrelevant header footer navigation '.repeat(20) + 'The SameSite Lax attribute permits top-level GET navigations. ' + 'unrelated tail content '.repeat(20);
    const section = extractRelevantSection(page, 'SameSite Lax top-level GET navigation', 400);
    expect(section).toContain('SameSite Lax');
  });

  it('research runs the bounded loop, persists sources + result (§72, §83, §85)', async () => {
    const researchEngine = new ResearchEngine({
      repos,
      searchProvider: fakeSearch,
      budget: { maxSearches: 2, maxPages: 2, maxBytes: 1_000_000, maxTimeMs: 10_000, maxTokens: 4000 },
      publish: async () => undefined,
      curatedDomains: ['owasp.org', 'portswigger.net', 'rfc-editor.org'],
    });
    const result = await researchEngine.research(
      {
        question: 'Does SameSite Lax allow top-level GET navigations?',
        engagement_id: null,
        hypothesis: 'session cookie policy bypass',
        required_evidence: ['official cookie spec'],
        source_constraints: [],
        mode: 'CURATED_WEB',
        max_sources: 2,
        max_tokens: 3000,
      },
      'integration-test',
    );
    expect(result.status).toBe('COMPLETED');
    expect(result.evidence.length).toBeGreaterThan(0);
    // Trust-ranked selection: the portswigger + rfc results selected.
    expect(result.evidence.every((e) => e.trust_level !== 'UNTRUSTED')).toBe(true);
    const task = await repos.researchTasks.findById(result.research_id);
    expect(task?.status).toBe('COMPLETED');
    const sources = await repos.researchSources.findByResearchTask(result.research_id);
    expect(sources.length).toBeGreaterThan(0);
    // Disagreement preserved, never averaged (§73/§111).
    expect(result.corroboration.length + result.disagreements.length).toBeGreaterThan(0);
  });

  it('search budget exhaustion is recorded honestly (§83)', async () => {
    const zeroBudget = new ResearchEngine({
      repos,
      searchProvider: fakeSearch,
      budget: { maxSearches: 0, maxPages: 0, maxBytes: 0, maxTimeMs: 5000, maxTokens: 2000 },
      publish: async () => undefined,
    });
    const result = await zeroBudget.research(
      {
        question: 'anything',
        engagement_id: null,
        hypothesis: null,
        required_evidence: [],
        source_constraints: [],
        mode: 'OPEN_RESEARCH',
        max_sources: 2,
        max_tokens: 2000,
      },
      'integration-test',
    );
    expect(result.notes.some((n) => n.includes('budget') || n.includes('deadline'))).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// Query cache (§65) + audit trail (§85).
// ---------------------------------------------------------------------------

describe('part5 query cache and audit', () => {
  it('identical context+version queries hit the cache (§65)', async () => {
    const request = {
      query: 'object level authorization comparison',
      engagement_id: null,
      hypothesis_id: null,
      categories: [] as never[],
      technologies: [] as string[],
      mode: 'LOCAL_ONLY' as const,
      max_results: 5,
      max_tokens: 2500,
    };
    const first = await engine.search(request, 'cache-test');
    expect(first.cache_hit).toBe(false);
    const second = await engine.search(request, 'cache-test');
    expect(second.cache_hit).toBe(true);
    expect(second.results.map((r) => r.chunk_id)).toEqual(first.results.map((r) => r.chunk_id));
    // Audit rows persist for both queries (§85).
    const rows = await repos.knowledgeQueries.listRecent(10);
    expect(rows.filter((row) => row.query === request.query).length).toBeGreaterThanOrEqual(2);
  });
});

// ---------------------------------------------------------------------------
// Agent knowledge-context seam (§87, §120).
// ---------------------------------------------------------------------------

describe('part5 agent context seam', () => {
  it('buildKnowledgeContext returns a trust-separated bounded packet (§87, §120)', async () => {
    const context = await engine.buildKnowledgeContext(engagementId);
    // Trusted summary: source metadata, no page content.
    const trusted = context.trusted_summary as { sources?: Array<{ name: string }>; packet_tokens?: number };
    expect(trusted.sources).toBeDefined();
    expect(trusted.sources!.length).toBeGreaterThan(0);
    expect(trusted.packet_tokens).toBeLessThanOrEqual(4000);
    // Untrusted detail: excerpts only, rendered inside delimiters upstream.
    const untrusted = context.untrusted_detail as { knowledge_excerpts?: Array<{ excerpt: string }> } | null;
    expect(untrusted?.knowledge_excerpts).toBeDefined();
    expect(untrusted!.knowledge_excerpts!.length).toBeGreaterThan(0);
    // Trusted side must not leak full page content.
    expect(JSON.stringify(context.trusted_summary)).not.toContain('How to Test');
  });

  it('no active hypotheses -> no retrieval (§123: targeted, not every request)', async () => {
    // The seeded engagement HAS a hypothesis; assert the null-path shape with
    // a nonexistent engagement (hypotheses list empty).
    const none = await engine.buildKnowledgeContext('ENG_DOESNOTEXIST0000');
    expect((none.trusted_summary as { note?: string }).note).toContain('no active hypotheses');
    expect(none.untrusted_detail).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// PDF ingestion over the real pipeline (§55).
// ---------------------------------------------------------------------------

describe('part5 pdf ingestion', () => {
  it('a generated PDF document is extracted, chunked and searchable', async () => {
    // Build a minimal two-page PDF with content streams (helper mirrors unit
    // test construction but exercises the full engine path).
    const mk = (text: string): Uint8Array => {
      const content = `BT /F1 12 Tf 72 720 Td (${text}) Tj ET`;
      const objects = [
        '<< /Type /Catalog /Pages 2 0 R >>',
        '<< /Type /Pages /Kids [3 0 R] /Count 1 >>',
        `<< /Type /Page /Parent 2 0 R /Contents 4 0 R >>`,
        `<< /Length ${content.length} >>`,
      ];
      let pdf = '%PDF-1.4\n';
      const offsets: number[] = [0];
      for (let i = 0; i < 4; i += 1) {
        offsets[i + 1] = pdf.length;
        pdf += `${i + 1} 0 obj\n${objects[i]}\n`;
        if (i === 3) {
          pdf += `stream\n${content}\nendstream\n`;
        }
        pdf += 'endobj\n';
      }
      const xref = pdf.length;
      pdf += `xref\n0 5\n0000000000 65535 f \n`;
      for (let i = 1; i <= 4; i += 1) pdf += `${String(offsets[i]).padStart(10, '0')} 00000 n \n`;
      pdf += `trailer\n<< /Size 5 /Root 1 0 R >>\nstartxref\n${xref}\n%%EOF\n`;
      return new Uint8Array(Buffer.from(pdf, 'latin1'));
    };
    const pdfBytes = mk('Race condition testing requires concurrent duplicate submissions.');
    const extraction = extractPdf(pdfBytes);
    expect(extraction.pageCount).toBe(1);
    const outcome = await engine.ingestRaw({
      sourceId: owaspSourceId,
      url: 'https://owasp.test/wstg/race-condition-pdf',
      bytes: pdfBytes,
      contentType: 'application/pdf',
    });
    expect(outcome.ingestion_status).toBe('INDEXED');
    const packet = await engine.search(
      { query: 'race condition concurrent duplicate submissions', engagement_id: null, hypothesis_id: null, categories: [], technologies: [], mode: 'LOCAL_ONLY', max_results: 4, max_tokens: 2000 },
      'integration-test',
    );
    expect(packet.results.some((r) => r.url.includes('race-condition-pdf'))).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// Retrieval evaluation over the fixture corpus (§96-§97).
// ---------------------------------------------------------------------------

describe('part5 retrieval evaluation', () => {
  it('benchmark queries produce useful metrics (Recall@K, MRR) (§97)', async () => {
    const queries: Array<{ query: string; expected: string[] }> = [
      { query: 'object level authorization', expected: ['object-authorization'] },
      { query: 'jwt audience validation algorithm', expected: ['jwt-validation'] },
      { query: 'websocket origin validation', expected: ['websocket-auth'] },
      { query: 'graphql depth authorization', expected: ['graphql-authorization'] },
    ];
    const datasets: Array<{ expectedDocumentIds: string[]; results: Array<{ document_id: string; token_estimate: number }> }> = [];
    for (const { query, expected } of queries) {
      const packet = await engine.search(
        { query, engagement_id: null, hypothesis_id: null, categories: [], technologies: [], mode: 'LOCAL_ONLY', max_results: 5, max_tokens: 3000 },
        'eval-test',
      );
      // Deduplicate to distinct documents: chunk-level repetition from the
      // same doc is expected retrieval behaviour, not duplication noise.
      const distinct = [...new Map(packet.results.map((r) => [r.document_id, r])).values()];
      datasets.push({
        expectedDocumentIds: expected.map((slug) => distinct.find((r) => r.url.includes(slug))?.document_id ?? `missing-${slug}`),
        results: distinct.map((r) => ({ document_id: r.document_id, token_estimate: r.token_estimate })),
      });
    }
    const metrics = computeMetrics(datasets as never, 5);
    expect(metrics.queries).toBe(4);
    // The fixture corpus is small and topic-aligned: recall should be high.
    expect(metrics.recallAtK).toBeGreaterThanOrEqual(0.75);
    expect(metrics.mrr).toBeGreaterThanOrEqual(0.5);
    expect(metrics.duplicateRate).toBeLessThan(0.3);
  });
});

// ---------------------------------------------------------------------------
// Knowledge fetcher URL policy (SSRF defence, §26, §80).
// ---------------------------------------------------------------------------

describe('part5 knowledge fetcher policy', () => {
  it('rejects loopback/private/link-local targets unless explicitly allowed (§26)', async () => {
    const { validateKnowledgeUrl } = await import('@aegis/knowledge');
    await expect(validateKnowledgeUrl('http://127.0.0.1:9/x', {}, { allowLoopback: false })).rejects.toMatchObject({
      code: 'NON_PUBLIC_ADDRESS',
    });
    await expect(validateKnowledgeUrl('http://10.0.0.1/x', {}, { allowLoopback: false })).rejects.toMatchObject({
      code: 'NON_PUBLIC_ADDRESS',
    });
    await expect(validateKnowledgeUrl('http://192.168.1.10/x', {}, { allowLoopback: false })).rejects.toMatchObject({
      code: 'NON_PUBLIC_ADDRESS',
    });
    await expect(validateKnowledgeUrl('file:///etc/passwd', {}, { allowLoopback: false })).rejects.toMatchObject({
      code: 'SCHEME_NOT_ALLOWED',
    });
    await expect(validateKnowledgeUrl('https://user:pass@owasp.test/doc', {}, { allowLoopback: false })).rejects.toMatchObject({
      code: 'USERINFO_NOT_ALLOWED',
    });
    // Loopback allowed (lab policy) passes.
    const allowed = await validateKnowledgeUrl('http://127.0.0.1:9/x', {}, { allowLoopback: true });
    expect(allowed.hostname).toBe('127.0.0.1');
  });

  it('enforces the domain allowlist (§80)', async () => {
    const { validateKnowledgeUrl } = await import('@aegis/knowledge');
    await expect(
      validateKnowledgeUrl('https://evil.test/doc', { allowedDomains: ['owasp.test'] }, { allowLoopback: false }),
    ).rejects.toMatchObject({ code: 'DOMAIN_NOT_ALLOWED' });
    await expect(
      validateKnowledgeUrl('https://owasp.test.evil.test/doc', { allowedDomains: ['owasp.test'] }, { allowLoopback: false }),
    ).rejects.toMatchObject({ code: 'DOMAIN_NOT_ALLOWED' });
    await expect(
      validateKnowledgeUrl('http://8.8.8.8/doc', { allowedDomains: ['8.8.8.8'] }, { allowLoopback: false }),
    ).resolves.toBeInstanceOf(URL);
  });

  it('bounded fetch: size limit truncates with an explicit flag (§27)', async () => {
    const fetcher = new KnowledgeFetcher({
      limits: {
        maxPageBytes: 1024,
        maxRedirects: 2,
        timeoutMs: 2000,
        maxConcurrency: 1,
        ratePerSourcePerMinute: 60,
        dailyFetchBudget: 10,
        allowLoopback: true,
      },
      fetchImpl: (async (_url: unknown, init?: RequestInit) => {
        void init;
        return new Response('x'.repeat(4096), { status: 200, headers: { 'content-type': 'text/plain' } });
      }) as typeof fetch,
    });
    const fetched = await fetcher.fetch('http://127.0.0.1:1/doc', { allowedDomains: [] });
    expect(fetched.truncated).toBe(true);
    expect(fetched.byteLength).toBeLessThanOrEqual(1024);
  });
});
