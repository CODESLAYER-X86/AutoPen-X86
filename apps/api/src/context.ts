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
import { ConfigurationError, type ModelRole } from '@aegis/shared';

export interface AppContext {
  config: AppConfig;
  logger: Logger;
  pool: Pool;
  repos: Repositories;
  eventBus: EventBus;
  orchestrator: OrchestratorService;
  evidence: EvidenceService;
  objectStore: ObjectStore;
  secretStore: SecretStore;
  toolRegistry: ToolRegistry;
  toolGateway: ToolGateway;
  modelRouter: ModelRouter;
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

  const orchestrator = new OrchestratorService({
    engagements: repos.engagements,
    targets: repos.targets,
    scope: repos.scope,
    events: repos.events,
    audit: repos.audit,
    eventBus,
    logger,
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

  const toolRegistry = createDefaultToolRegistry();
  const toolGateway = new ToolGateway(toolRegistry);

  const modelRouter = new ModelRouter({
    strategic: buildModelProvider('strategic', config.models.strategic, config.models.requestTimeoutMs),
    tactical: buildModelProvider('tactical', config.models.tactical, config.models.requestTimeoutMs),
  });

  return {
    config,
    logger,
    pool,
    repos,
    eventBus,
    orchestrator,
    evidence,
    objectStore,
    secretStore,
    toolRegistry,
    toolGateway,
    modelRouter,
    audit: async (entry) => {
      await repos.audit.create(entry);
    },
  };
}
