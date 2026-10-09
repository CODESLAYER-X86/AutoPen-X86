/**
 * Part 3 integration helpers: composes the real interaction stack
 * (engine + recorder + session manager + browser + tools + gateway) over
 * the test database and a local lab app (§82-§83).
 */
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { Pool } from 'pg';
import { createRepositories, type Repositories } from '@aegis/database';
import { createLogger, createMemorySink } from '@aegis/logging';
import { PersistingEventBus, InMemoryEventBus } from '@aegis/events';
import { EvidenceService, LocalFileSystemObjectStore, type ObjectStore } from '@aegis/evidence';
import { EncryptedFileSecretStore, type SecretStore } from '@aegis/security';
import { ToolGateway, ToolRegistry, createDefaultToolRegistry } from '@aegis/tools';
import { HttpEngine, HttpTrafficRecorder, LAB_NETWORK_POLICY } from '@aegis/target-http';
import { SessionManager } from '@aegis/session-manager';
import { BrowserService } from '@aegis/browser';
import { createPart3Tools } from '@aegis/toolbox';
import { startLabApp, type LabApp } from '../fixtures/labApp.js';
import type { ScopeRules } from '@aegis/security';

export interface InteractionStack {
  repos: Repositories;
  pool: Pool;
  eventBus: PersistingEventBus;
  evidence: EvidenceService;
  objectStore: ObjectStore;
  secretStore: SecretStore;
  sessionManager: SessionManager;
  engine: HttpEngine;
  recorder: HttpTrafficRecorder;
  browser: BrowserService;
  registry: ToolRegistry;
  gateway: ToolGateway;
  lab: LabApp;
  scope: ScopeRules;
  tempDir: string;
  close(): Promise<void>;
}

export interface BuildStackOptions {
  pool: Pool;
  /** Scope override (defaults to the lab app's host:port). */
  scope?: ScopeRules;
  browser?: {
    downloadsEnabled?: boolean;
  };
}

export async function buildInteractionStack(options: BuildStackOptions): Promise<InteractionStack> {
  const pool = options.pool;
  const repos = createRepositories(pool);
  const tempDir = mkdtempSync(join(tmpdir(), 'aegis-p3-'));
  const memory = createMemorySink();
  const logger = createLogger({ level: 'warn', sink: memory.sink });

  const eventBus = new PersistingEventBus(new InMemoryEventBus(), async (event) => {
    await repos.events.insert(event);
  });

  const objectStore = new LocalFileSystemObjectStore(join(tempDir, 'artifacts'));
  const evidence = new EvidenceService({ repository: repos.evidence, objectStore, logger });
  const secretStore = new EncryptedFileSecretStore({ filePath: join(tempDir, 'secrets.json') });

  const sessionManager = new SessionManager({
    sessions: repos.sessions,
    workflows: repos.authWorkflows,
    identities: repos.identities,
    secretStore,
    eventBus,
  });

  const engine = new HttpEngine({
    limits: {
      maxResponseBytes: 2_097_152,
      maxHtmlBytes: 2_097_152,
      maxScriptBytes: 4_194_304,
      maxRequestBytes: 1_048_576,
      timeoutMs: 10_000,
    },
    networkPolicy: LAB_NETWORK_POLICY,
  });

  const trafficRepository = {
    insertRequest: (input: Parameters<typeof repos.httpRequests.insert>[0]) => repos.httpRequests.insert(input),
    insertResponse: (input: Parameters<typeof repos.httpResponses.insert>[0]) => repos.httpResponses.insert(input),
    findRequestById: (id: string) => repos.httpRequests.findById(id),
    listRequestsByEngagement: (engagementId: string, limit: number, offset: number) =>
      repos.httpRequests.listByEngagement(engagementId, limit, offset),
    countRequestsByEngagement: (engagementId: string) => repos.httpRequests.countByEngagement(engagementId),
  };
  const recorder = new HttpTrafficRecorder({ repository: trafficRepository, evidence, eventBus });

  const lab = await startLabApp();
  const scope: ScopeRules =
    options.scope ?? {
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
    securityPolicy: { downloadsEnabled: options.browser?.downloadsEnabled ?? true },
    limits: { maxNavigationTimeMs: 15_000, maxTotalBrowserTimeMs: 120_000 },
    launch: {
      headless: true,
      executablePath: null,
      networkPolicy: {
        allowLoopback: true,
        allowPrivateNetworks: true,
        allowedSchemes: ['http', 'https'],
        maxRedirects: 5,
      },
    },
  });

  const registry = createDefaultToolRegistry();
  registry.registerAll(
    createPart3Tools({
      engine,
      recorder,
      browser,
      sessionManager,
      evidence,
      objectStore,
      repos,
      eventBus,
    }),
  );
  const gateway = new ToolGateway(registry);

  return {
    repos,
    pool,
    eventBus,
    evidence,
    objectStore,
    secretStore,
    sessionManager,
    engine,
    recorder,
    browser,
    registry,
    gateway,
    lab,
    scope,
    tempDir,
    close: async () => {
      await browser.closeEngagement('any').catch(() => undefined);
      await lab.close();
      await pool.end().catch(() => undefined);
    },
  };
}

/** Gateway execution context for tests. */
export function gatewayContext(stack: InteractionStack, engagementId: string, overrides: Record<string, unknown> = {}) {
  return {
    engagementId,
    scope: stack.scope,
    permissions: { network: true, browser: true, destructive: false },
    ...overrides,
  };
}

/** Seed a project + engagement + scope + identities; returns ids. */
export async function seedEngagement(
  stack: InteractionStack,
  userId: string,
): Promise<{ engagementId: string; identityA: string; identityB: string; anonymous: string }> {
  const project = await stack.repos.projects.create({
    ownerId: userId,
    name: `p3-${Date.now()}`,
    description: 'part3 integration test',
  });
  const engagement = await stack.repos.engagements.create({
    projectId: project.id,
    name: 'part3-test',
    mode: 'PENTEST',
    description: '',
  });
  await stack.repos.scope.upsert(engagement.id, {
    allowed_hosts: stack.scope.allowed_hosts,
    allowed_domains: [],
    allowed_ports: stack.scope.allowed_ports,
    allowed_schemes: ['http', 'https'],
    excluded_hosts: [],
    excluded_paths: [],
    rate_limit: null,
    concurrency_limit: null,
    destructive_actions_allowed: false,
  });
  const identityA = await stack.repos.identities.create({
    engagementId: engagement.id,
    name: 'usera',
    role: 'user',
    type: 'USER',
    metadata: {},
  });
  const identityB = await stack.repos.identities.create({
    engagementId: engagement.id,
    name: 'userb',
    role: 'user',
    type: 'USER',
    metadata: {},
  });
  const anonymous = await stack.repos.identities.create({
    engagementId: engagement.id,
    name: 'anonymous',
    role: '',
    type: 'ANONYMOUS',
    metadata: {},
  });
  return { engagementId: engagement.id, identityA: identityA.id, identityB: identityB.id, anonymous: anonymous.id };
}
