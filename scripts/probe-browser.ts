/** Debug probe: browser network capture + DOM extraction against lab app. */
import { createPool } from '@aegis/database';
import { createRepositories } from '@aegis/database';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createLogger } from '@aegis/logging';
import { InMemoryEventBus } from '@aegis/events';
import { EvidenceService, LocalFileSystemObjectStore } from '@aegis/evidence';
import { EncryptedFileSecretStore } from '@aegis/security';
import { HttpTrafficRecorder } from '@aegis/target-http';
import { SessionManager } from '@aegis/session-manager';
import { BrowserService } from '@aegis/browser';
import { startLabApp } from '../tests/fixtures/labApp.js';
import { generateId } from '@aegis/shared';

async function main() {
  const pool = createPool('postgres://postgres:postgres@127.0.0.1:5433/aegis_test', { max: 4 });
  const repos = createRepositories(pool);
  const tempDir = mkdtempSync(join(tmpdir(), 'probe-'));
  const logger = createLogger({ level: 'warn' });
  const eventBus = new InMemoryEventBus();
  const objectStore = new LocalFileSystemObjectStore(join(tempDir, 'artifacts'));
  const evidence = new EvidenceService({ repository: repos.evidence, objectStore, logger });
  const secretStore = new EncryptedFileSecretStore({ filePath: join(tempDir, 'secrets.json') });
  const sessionManager = new SessionManager({ sessions: repos.sessions, workflows: repos.authWorkflows, identities: repos.identities, secretStore, eventBus });
  const trafficRepository = {
    insertRequest: (input: Parameters<typeof repos.httpRequests.insert>[0]) => repos.httpRequests.insert(input),
    insertResponse: (input: Parameters<typeof repos.httpResponses.insert>[0]) => repos.httpResponses.insert(input),
    findRequestById: (id: string) => repos.httpRequests.findById(id),
    listRequestsByEngagement: (e: string, l: number, o: number) => repos.httpRequests.listByEngagement(e, l, o),
    countRequestsByEngagement: (e: string) => repos.httpRequests.countByEngagement(e),
  };
  const recorder = new HttpTrafficRecorder({ repository: trafficRepository, evidence, eventBus });

  const lab = await startLabApp();
  const scope = {
    allowed_hosts: [lab.host],
    allowed_domains: [],
    allowed_ports: [lab.port],
    allowed_schemes: ['http', 'https'],
    excluded_hosts: [],
    excluded_paths: [],
    rate_limit: null,
    concurrency_limit: null,
    destructive_actions_allowed: false,
  };

  const browser = new BrowserService({
    contexts: repos.browserContexts,
    pagesRepo: repos.browserPages,
    events: repos.browserEvents,
    cookies: repos.cookies,
    storage: repos.storageEntries,
    downloads: repos.downloads,
    websockets: repos.websockets,
    domSnapshots: repos.domSnapshots,
    evidence,
    recorder,
    httpRepository: trafficRepository,
    eventBus,
    secretStore,
    sessionManager,
    securityPolicy: { downloadsEnabled: true },
  });

  const engagementId = 'ENG_PROBE0000000001';
  const users = new (await import('@aegis/database')).UsersRepository(pool);
  const user = await users.create({ email: `probe-${Date.now()}@x.local`, name: 'p', passwordHash: 'h' });
  const project = await repos.projects.create({ ownerId: user.id, name: 'probe', description: '' });
  const engagement = await repos.engagements.create({ projectId: project.id, name: 'probe', mode: 'PENTEST', description: '' });
  await repos.scope.upsert(engagement.id, {
    allowed_hosts: scope.allowed_hosts, allowed_domains: [], allowed_ports: scope.allowed_ports,
    allowed_schemes: scope.allowed_schemes, excluded_hosts: [], excluded_paths: [],
    rate_limit: null, concurrency_limit: null, destructive_actions_allowed: false,
  });
  const engagementAny = engagement.id;
  void engagementId;

  const handle = await browser.getContextHandle(engagementAny, null);
  const result = await browser.performAction(engagementAny, {
    context_id: handle.id,
    page_id: null,
    action: 'navigate',
    url: `${lab.url}/login`,
    timeout_ms: 15000,
  }, scope);
  console.log('navigate ok:', result.ok, 'http_records:', result.http_records, 'error:', result.error);

  const snapshot = await browser.performAction(engagementAny, {
    context_id: handle.id,
    page_id: null,
    action: 'snapshot',
  }, scope);
  console.log('snapshot ok:', snapshot.ok, 'details:', JSON.stringify((snapshot.details as { counts?: unknown }).counts ?? snapshot.details).slice(0, 400));

  const events = await repos.browserEvents.listByEngagement(engagementAny, 500);
  console.log('event types:', events.map((e) => e.event_type).join(', '));

  // WS probe
  const handle2 = handle;
  const page = [...handle2.pages.keys()][0]!;
  console.log('pages:', handle2.pages.size);
  await page.evaluate((url) => {
    return new Promise<void>((resolve) => {
      const ws = new WebSocket(url);
      ws.onopen = () => { ws.send('hello-probe'); setTimeout(() => { ws.close(); resolve(); }, 300); };
      ws.onerror = () => resolve();
    });
  }, `${lab.url.replace('http', 'ws')}/ws`);
  await new Promise((resolve) => setTimeout(resolve, 1500));
  await browser.performAction(engagementAny, { context_id: handle2.id, page_id: null, action: 'snapshot' }, scope);
  await new Promise((resolve) => setTimeout(resolve, 500));
  const connections2 = await repos.websockets.listConnections(engagementAny);
  console.log('ws connections:', connections2.length);
  for (const conn of connections2) {
    const messages = await repos.websockets.listMessages(conn.id as string, 50);
    console.log('  conn', conn.id, 'messages:', messages.length, messages.map((m) => m.direction).join(','));
  }

  await browser.closeEngagement(engagementAny);
  await lab.close();
  await pool.end();
}

main().catch((error) => {
  console.error('PROBE FAILED:', error);
  process.exit(1);
});
void generateId;
