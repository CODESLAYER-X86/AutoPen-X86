/**
 * Application context (composition root). Wires repositories, event bus,
 * orchestrator, evidence, secret store, tool registry and model runtime
 * together. Tests inject config/pool/logger overrides here.
 */
import type { Pool } from 'pg';
import type { AppConfig } from '@aegis/config';
import { loadConfig } from '@aegis/config';
import type { Logger } from '@aegis/logging';
import { createLogger } from '@aegis/logging';
import {
  createPool,
  createRepositories,
  type Repositories,
} from '@aegis/database';
import { PersistingEventBus, InMemoryEventBus, type EventBus } from '@aegis/events';
import { ModelRouter, MockModelProvider, GoogleModelProvider, type ModelProvider } from '@aegis/model-runtime';
import { ToolGateway, ToolRegistry, createDefaultToolRegistry } from '@aegis/tools';
import { EncryptedFileSecretStore, type SecretStore } from '@aegis/security';
import { OrchestratorService } from '@aegis/orchestrator';
import { EvidenceService, LocalFileSystemObjectStore, type ObjectStore } from '@aegis/evidence';
import { HttpEngine, HttpTrafficRecorder, LAB_NETWORK_POLICY, DEFAULT_NETWORK_POLICY, type NetworkPolicy } from '@aegis/target-http';
import { SessionManager } from '@aegis/session-manager';
import { BrowserService, DEFAULT_LAUNCH_OPTIONS } from '@aegis/browser';
import { createPart3Tools } from '@aegis/toolbox';
import { createPart4Tools } from '@aegis/toolbox';
import { SecurityReasoningEngine } from '@aegis/reasoning';
import { ConfigurationError, type ModelRole } from '@aegis/shared';
import { AgentEngineRegistry } from './agent-engine.js';

export interface AppContext {
  config: AppConfig;
  logger: Logger;
  pool: Pool;
  repos: Repositories;
  eventBus: EventBus;
  orchestrator: OrchestratorService;
  agentEngines: AgentEngineRegistry;
  evidence: EvidenceService;
  objectStore: ObjectStore;
  secretStore: SecretStore;
  toolRegistry: ToolRegistry;
  toolGateway: ToolGateway;
  modelRouter: ModelRouter;
  /** Part 3 — interaction layer. */
  httpEngine: HttpEngine;
  trafficRecorder: HttpTrafficRecorder;
  sessionManager: SessionManager;
  browserService: BrowserService;
  /** Part 4 — security reasoning engine (null when disabled by config). */
  reasoning: SecurityReasoningEngine | null;
  /** Stops the reasoning event subscription (called on app close). */
  stopReasoning: () => void;
  /** Route-level audit trail (spec §30). */
  audit: (entry: {
    actorUserId: string | null;
    action: string;
    resource: string;
    resourceId?: string | null;
    engagementId?: string | null;
    metadata?: Record<string, unknown>;
  }) => Promise<void>;
}

export interface CreateContextOptions {
  config?: AppConfig;
  logger?: Logger;
  pool?: Pool;
}

function buildModelProvider(
  role: ModelRole,
  spec: { provider: 'mock' | 'google'; modelId: string },
  timeoutMs: number,
): ModelProvider {
  if (spec.provider === 'mock') {
    return new MockModelProvider(spec.modelId);
  }
  // Secret flow: environment -> provider. Never stored in config or DB.
  const apiKey = process.env.GOOGLE_API_KEY ?? '';
  if (!apiKey) {
    throw new ConfigurationError(
      `STRATEGIC/TACTICAL model provider 'google' requires GOOGLE_API_KEY in the environment (role: ${role})`,
      undefined,
      'MODEL_PROVIDER_NOT_CONFIGURED',
    );
  }
  return new GoogleModelProvider({ apiKey, model: spec.modelId, timeoutMs });
}

export function createContext(options: CreateContextOptions = {}): AppContext {
  const config = options.config ?? loadConfig();
  const logger =
    options.logger ??
    createLogger({
      level: config.app.logLevel,
      bindings: { service: 'api', env: config.app.env },
    });
  const pool = options.pool ?? createPool(config.database.url, { max: config.database.poolMax });
  const repos = createRepositories(pool);

  const eventBus = new PersistingEventBus(new InMemoryEventBus(), async (event) => {
    await repos.events.insert(event);
  });

  const objectStore = new LocalFileSystemObjectStore(config.storage.localPath);
  const evidence = new EvidenceService({ repository: repos.evidence, objectStore, logger });

  const secretStore = new EncryptedFileSecretStore({
    filePath: config.secretStore.path,
    masterKey: config.secretStore.masterKey,
    onDevKey: (keyPath) => {
      logger.warn('secret_store.dev_key_generated', {
        path: keyPath,
        note: 'A development master key was generated; set SECRET_STORE_MASTER_KEY for real use',
      });
    },
  });

  // --- Part 3: interaction layer composition -----------------------------
  // Network policy: dev/test targets run on loopback (embedded fixture
  // apps); production keeps the restrictive default (§50).
  const networkPolicy: NetworkPolicy =
    config.app.env === 'production' ? DEFAULT_NETWORK_POLICY : LAB_NETWORK_POLICY;

  const httpEngine = new HttpEngine({
    limits: {
      maxResponseBytes: config.http.maxBodyBytes,
      maxHtmlBytes: config.http.maxBodyBytes,
      maxRequestBytes: config.http.maxBodyBytes,
      timeoutMs: config.http.timeoutMs,
    },
    networkPolicy,
  });

  // Adapter: two repos (requests + responses) behind the recorder surface.
  const trafficRepository = {
    insertRequest: (input: Parameters<typeof repos.httpRequests.insert>[0]) => repos.httpRequests.insert(input),
    insertResponse: (input: Parameters<typeof repos.httpResponses.insert>[0]) => repos.httpResponses.insert(input),
    findRequestById: (id: string) => repos.httpRequests.findById(id),
    listRequestsByEngagement: (engagementId: string, limit: number, offset: number) =>
      repos.httpRequests.listByEngagement(engagementId, limit, offset),
    countRequestsByEngagement: (engagementId: string) => repos.httpRequests.countByEngagement(engagementId),
  };

  const trafficRecorder = new HttpTrafficRecorder({
    repository: trafficRepository,
    evidence,
    eventBus,
  });

  const sessionManager = new SessionManager({
    sessions: repos.sessions,
    workflows: repos.authWorkflows,
    identities: repos.identities,
    secretStore,
    eventBus,
  });

  const browserService = new BrowserService({
    contexts: repos.browserContexts,
    pagesRepo: repos.browserPages,
    events: repos.browserEvents,
    cookies: repos.cookies,
    storage: repos.storageEntries,
    downloads: repos.downloads,
    websockets: repos.websockets,
    domSnapshots: repos.domSnapshots,
    evidence,
    recorder: trafficRecorder,
    httpRepository: trafficRepository,
    eventBus,
    secretStore,
    sessionManager,
    launch: {
      ...DEFAULT_LAUNCH_OPTIONS,
      headless: true,
      networkPolicy: {
        allowLoopback: networkPolicy.allowLoopback,
        allowPrivateNetworks: networkPolicy.allowPrivateNetworks,
        allowedSchemes: networkPolicy.allowedSchemes,
        maxRedirects: networkPolicy.maxRedirects,
      },
    },
  });

  const toolRegistry = createDefaultToolRegistry();
  if (config.features.toolsHttp || config.features.toolsBrowser) {
    toolRegistry.registerAll(
      createPart3Tools({
        engine: httpEngine,
        recorder: trafficRecorder,
        browser: browserService,
        sessionManager,
        evidence,
        objectStore,
        repos,
        eventBus,
      }),
    );
  }

  // --- Part 4: security reasoning engine (§108, §109, §113) ------------
  // Deterministic intelligence over captured observations. Subscribes to
  // the event bus so derived state updates as traffic arrives; failures are
  // isolated per event (§112) and never surface as engagement errors.
  let reasoningEngine: SecurityReasoningEngine | null = null;
  let stopReasoning: () => void = () => undefined;
  if (config.features.securityReasoning) {
    reasoningEngine = new SecurityReasoningEngine({
      repos,
      eventBus,
      logger,
      limits: {
        maxGraphNodes: config.reasoning.maxGraphNodes,
        maxGraphEdges: config.reasoning.maxGraphEdges,
        maxSignals: config.reasoning.maxSignals,
        maxParameters: config.reasoning.maxParameters,
        maxEndpoints: config.reasoning.maxEndpoints,
        maxObjects: config.reasoning.maxObjects,
        maxExampleValues: config.reasoning.maxExampleValues,
        maxComparisonBytes: config.reasoning.maxComparisonBytes,
        maxMutationCandidates: config.reasoning.maxMutationCandidates,
      },
      // Destructive test planning follows the engagement security policy
      // (§132): the engine only PLANS candidates; execution stays gated.
      allowDestructive: false,
    });
    toolRegistry.registerAll(
      createPart4Tools({
        reasoning: reasoningEngine,
        repos,
        eventBus,
      }),
    );
    stopReasoning = reasoningEngine.processor.subscribe();
  }
  const toolGateway = new ToolGateway(toolRegistry);

  const modelRouter = new ModelRouter({
    strategic: buildModelProvider('strategic', config.models.strategic, config.models.requestTimeoutMs),
    tactical: buildModelProvider('tactical', config.models.tactical, config.models.requestTimeoutMs),
  });

  const agentEngines = new AgentEngineRegistry({
    config,
    logger,
    repos,
    eventBus,
    modelRouter,
    toolRegistry,
    toolGateway,
    security: reasoningEngine ?? undefined,
  });

  const orchestratorWithAgent = new OrchestratorService({
    engagements: repos.engagements,
    targets: repos.targets,
    scope: repos.scope,
    events: repos.events,
    audit: repos.audit,
    eventBus,
    logger,
    agentLauncher: agentEngines,
  });

  return {
    config,
    logger,
    pool,
    repos,
    eventBus,
    orchestrator: orchestratorWithAgent,
    agentEngines,
    evidence,
    objectStore,
    secretStore,
    toolRegistry,
    toolGateway,
    modelRouter,
    httpEngine,
    trafficRecorder,
    sessionManager,
    browserService,
    reasoning: reasoningEngine,
    stopReasoning,
    audit: async (entry) => {
      await repos.audit.create(entry);
    },
  };
}
