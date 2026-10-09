/**
 * Session manager — identity authentication state (spec Part 3 §4, §23-§30).
 *
 * Owns the deterministic mapping:
 *
 *   Identity -> (HTTP session material, browser context state)
 *
 * The worker only ever names an identity_id (§4); the session manager
 * resolves the identity to its authenticated state. Secret material is
 * held in the encrypted secret store and injected at the point of use —
 * never into model context, logs, or ordinary SQL rows (§23, §26).
 *
 * Expiration detection (§27) produces observations; the manager never
 * re-authenticates automatically — that is a strategic decision (§27).
 */
import { generateId, PlatformError, type AuthStateKind, type SessionExpirationSignal, type SessionStatus, type SessionType } from '@aegis/shared';
import type { PlainHeader } from './types.js';

export class SessionManagerError extends PlatformError {
  constructor(message: string, code: string) {
    super(message, { code, category: 'AUTHENTICATION', statusCode: 400 });
    this.name = 'SessionManagerError';
  }
}

// ---------------------------------------------------------------------------
// Secret material shapes (stored encrypted; resolved at use time).
// ---------------------------------------------------------------------------

export interface CookieMaterial {
  name: string;
  value: string;
  domain: string;
  path: string;
  secure: boolean;
  httpOnly: boolean;
  sameSite: 'Strict' | 'Lax' | 'None' | null;
  expires: number | null; // epoch seconds
}

export interface StorageMaterial {
  origin: string;
  area: 'LOCAL' | 'SESSION';
  key: string;
  value: string;
}

export interface AuthMaterial {
  kind: AuthStateKind;
  cookies?: CookieMaterial[];
  token?: string;
  headers?: Array<{ name: string; value: string }>;
  storage?: StorageMaterial[];
  /** Login workflow that produced this state (audit, §28). */
  workflowId?: string;
}

// ---------------------------------------------------------------------------
// Repository surfaces (implemented by the database layer).
// ---------------------------------------------------------------------------

export interface SessionRepositorySurface {
  create(input: {
    identityId: string;
    type: SessionType;
    secretReference: string;
    metadata?: Record<string, unknown>;
    expiresAt?: Date | null;
  }): Promise<SessionRow>;
  findActiveByIdentity(identityId: string): Promise<SessionRow | null>;
  updateStatus(sessionId: string, status: SessionStatus, reason: string | null): Promise<SessionRow | null>;
  listByIdentity(identityId: string): Promise<SessionRow[]>;
}

export interface SessionRow {
  id: string;
  identity_id: string;
  type: SessionType;
  status: SessionStatus;
  secret_reference: string;
  metadata: Record<string, unknown>;
  /** ISO-8601 string (repo records are JSON-stable). */
  expires_at: string | null;
  created_at: string;
  status_reason?: string | null;
  engagement_id?: string | null;
}

export interface WorkflowRepositorySurface {
  insert(input: {
    engagementId: string;
    identityId: string;
    steps: Array<{ action: string; detail: string; success: boolean }>;
    sessionId: string | null;
    evidenceIds: string[];
  }): Promise<{ id: string; created_at: Date }>;
  listByEngagement(engagementId: string): Promise<Array<Record<string, unknown>>>;
}

export interface SecretStoreSurface {
  store(plaintext: string): Promise<string>;
  resolve(reference: string): Promise<string>;
}

export interface EventBusSurface2 {
  publish(event: import('@aegis/contracts').PlatformEvent): Promise<void>;
}

export interface IdentityRowSurface {
  id: string;
  engagement_id: string;
  name: string;
  type: string;
}

export interface IdentityRepositorySurface {
  findById(identityId: string): Promise<IdentityRowSurface | null>;
}

// ---------------------------------------------------------------------------
// Manager
// ---------------------------------------------------------------------------

export interface RegisterAuthStateInput {
  engagementId: string;
  identityId: string;
  material: AuthMaterial;
  expiresAt?: Date | null;
  workflow?: { steps: Array<{ action: string; detail: string; success: boolean }>; evidenceIds?: string[] } | null;
}

export interface HttpAuthInjection {
  headers: PlainHeader[];
  cookieHeader: string | null;
}

export interface BrowserAuthState {
  cookies: CookieMaterial[];
  storageOrigins: Map<string, Array<{ area: 'LOCAL' | 'SESSION'; key: string; value: string }>>;
}

export interface ExpirationDetection {
  signal: SessionExpirationSignal | null;
  detail: string;
}

/** URL path fragments that smell like an authentication redirect (§27). */
const AUTH_REDIRECT_PATTERNS = [/login/i, /signin/i, /sign-in/i, /auth/i, /session\/?/i, /sso/i];

export class SessionManager {
  constructor(
    private readonly deps: {
      sessions: SessionRepositorySurface;
      workflows: WorkflowRepositorySurface;
      identities: IdentityRepositorySurface;
      secretStore: SecretStoreSurface;
      eventBus: EventBusSurface2;
    },
  ) {}

  /**
   * Register authentication material for an identity (§28: the result of a
   * recorded login workflow becomes a reusable identity-associated session).
   */
  async registerAuthState(input: RegisterAuthStateInput): Promise<SessionRow> {
    const identity = await this.deps.identities.findById(input.identityId);
    if (!identity) {
      throw new SessionManagerError(`Identity '${input.identityId}' not found`, 'IDENTITY_NOT_FOUND');
    }
    if (identity.engagement_id !== input.engagementId) {
      throw new SessionManagerError(
        'Identity does not belong to this engagement',
        'IDENTITY_ENAGEMENT_MISMATCH',
      );
    }

    const secretReference = await this.deps.secretStore.store(JSON.stringify(input.material));
    const session = await this.deps.sessions.create({
      identityId: input.identityId,
      type: materialToSessionType(input.material.kind),
      secretReference,
      metadata: {
        kind: input.material.kind,
        names: describeMaterial(input.material),
        domains: input.material.cookies?.map((c) => c.domain) ?? [],
        engagement_id: input.engagementId,
      },
      expiresAt: input.expiresAt ?? null,
    });

    if (input.workflow) {
      const workflow = await this.deps.workflows.insert({
        engagementId: input.engagementId,
        identityId: input.identityId,
        steps: input.workflow.steps,
        sessionId: session.id,
        evidenceIds: input.workflow.evidenceIds ?? [],
      });
      await this.deps.eventBus.publish({
        type: 'AUTH_WORKFLOW_RECORDED',
        engagement_id: input.engagementId,
        task_id: null,
        trace_id: generateId('TRC'),
        actor_id: null,
        payload: {
          workflow_id: workflow.id,
          identity_id: input.identityId,
          session_id: session.id,
          steps: input.workflow.steps.length,
        },
        occurred_at: new Date().toISOString(),
        dedup_key: `auth-workflow:${workflow.id}`,
      });
    }

    return session;
  }

  /**
   * HTTP auth injection (§26): resolve the identity's ACTIVE session into
   * headers. Anonymous (identityId = null) injects nothing (§30).
   */
  async resolveForHttp(identityId: string | null): Promise<HttpAuthInjection> {
    if (!identityId) return { headers: [], cookieHeader: null };

    const session = await this.deps.sessions.findActiveByIdentity(identityId);
    if (!session) {
      throw new SessionManagerError(
        `No active authentication session for identity '${identityId}'`,
        'SESSION_NOT_FOUND',
      );
    }
    if (session.expires_at && new Date(session.expires_at).getTime() < Date.now()) {
      const identity = await this.deps.identities.findById(identityId);
      await this.expireSession(
        session.id,
        'HTTP_401',
        'Session expired before use',
        identity?.engagement_id ?? session.engagement_id ?? identityId,
      );
      throw new SessionManagerError(
        `Authentication session for identity '${identityId}' has expired`,
        'SESSION_EXPIRED',
      );
    }

    const material = await this.resolveMaterial(session);
    const headers: PlainHeader[] = [];
    let cookieHeader: string | null = null;

    switch (material.kind) {
      case 'COOKIE': {
        const cookies = material.cookies ?? [];
        cookieHeader = cookies.map((c) => `${c.name}=${c.value}`).join('; ');
        break;
      }
      case 'BEARER':
      case 'JWT': {
        if (!material.token) throw new SessionManagerError('Token session has no token material', 'SESSION_MATERIAL_INVALID');
        headers.push({ name: 'authorization', value: `Bearer ${material.token}` });
        break;
      }
      case 'API_KEY':
      case 'CUSTOM_HEADER': {
        for (const h of material.headers ?? []) headers.push({ name: h.name, value: h.value });
        break;
      }
      case 'BROWSER_STORAGE': {
        // Browser-storage identities carry no HTTP-level material.
        break;
      }
    }
    return { headers, cookieHeader };
  }

  /**
   * Browser context import state (§23-§24): cookies + per-origin storage.
   * Identities WITHOUT a registered session get a CLEAN context — the
   * browser login workflow itself creates the session (§28).
   */
  async resolveForBrowser(identityId: string | null): Promise<BrowserAuthState> {
    if (!identityId) return { cookies: [], storageOrigins: new Map() };
    const session = await this.deps.sessions.findActiveByIdentity(identityId);
    if (!session) {
      return { cookies: [], storageOrigins: new Map() };
    }
    const material = await this.resolveMaterial(session);
    const storageOrigins = new Map<string, Array<{ area: 'LOCAL' | 'SESSION'; key: string; value: string }>>();
    for (const entry of material.storage ?? []) {
      const list = storageOrigins.get(entry.origin) ?? [];
      list.push({ area: entry.area, key: entry.key, value: entry.value });
      storageOrigins.set(entry.origin, list);
    }
    return { cookies: material.cookies ?? [], storageOrigins };
  }

  /**
   * Expiration detection from an HTTP exchange (§27). Pure decision —
   * persistence happens in `expireSession`.
   */
  detectExpiration(input: {
    status: number;
    location: string | null;
    setCookies: string[];
    finalUrl: string;
  }): ExpirationDetection {
    if (input.status === 401) {
      return { signal: 'HTTP_401', detail: 'Target responded with 401 Unauthorized' };
    }
    if (input.status === 403) {
      return { signal: 'HTTP_403', detail: 'Target responded with 403 Forbidden' };
    }
    const redirectTarget = input.location ?? '';
    if (redirectTarget !== '' && AUTH_REDIRECT_PATTERNS.some((p) => p.test(new URL(redirectTarget, input.finalUrl).pathname))) {
      return { signal: 'AUTH_REDIRECT', detail: `Redirected to authentication page: ${redirectTarget}` };
    }
    for (const setCookie of input.setCookies) {
      if (/expires=Thu, 01 Jan 1970|max-age=0|max-age=-\d/i.test(setCookie)) {
        return { signal: 'LOGOUT_DETECTED', detail: 'Session cookie cleared by the target (Set-Cookie expiry)' };
      }
    }
    return { signal: null, detail: 'No expiration signal detected' };
  }

  /** Mark a session expired + emit the observation event (never re-auth). */
  async expireSession(
    sessionId: string,
    signal: SessionExpirationSignal,
    detail: string,
    engagementId: string,
  ): Promise<void> {
    await this.deps.sessions.updateStatus(sessionId, 'EXPIRED', `${signal}: ${detail}`);
    await this.deps.eventBus.publish({
      type: 'SESSION_EXPIRATION_DETECTED',
      engagement_id: engagementId,
      task_id: null,
      trace_id: generateId('TRC'),
      actor_id: null,
      payload: { session_id: sessionId, signal, detail },
      occurred_at: new Date().toISOString(),
      dedup_key: `session-expired:${sessionId}:${signal}`,
    });
  }

  async listSessions(identityId: string): Promise<SessionRow[]> {
    return this.deps.sessions.listByIdentity(identityId);
  }

  private async resolveMaterial(session: SessionRow): Promise<AuthMaterial> {
    let plaintext: string;
    try {
      plaintext = await this.deps.secretStore.resolve(session.secret_reference);
    } catch {
      throw new SessionManagerError(
        `Session material could not be resolved for session '${session.id}'`,
        'SESSION_MATERIAL_UNRESOLVABLE',
      );
    }
    try {
      return JSON.parse(plaintext) as AuthMaterial;
    } catch {
      throw new SessionManagerError('Session material is corrupt', 'SESSION_MATERIAL_INVALID');
    }
  }
}

function materialToSessionType(kind: AuthStateKind): SessionType {
  switch (kind) {
    case 'COOKIE':
      return 'COOKIE';
    case 'BEARER':
    case 'JWT':
      return 'JWT';
    case 'API_KEY':
      return 'API_KEY';
    case 'CUSTOM_HEADER':
    case 'BROWSER_STORAGE':
      return 'CUSTOM';
  }
}

function describeMaterial(material: AuthMaterial): string[] {
  switch (material.kind) {
    case 'COOKIE':
      return (material.cookies ?? []).map((c) => c.name);
    case 'BEARER':
    case 'JWT':
      return ['authorization'];
    case 'API_KEY':
    case 'CUSTOM_HEADER':
      return (material.headers ?? []).map((h) => h.name);
    case 'BROWSER_STORAGE':
      return (material.storage ?? []).map((s) => `${s.origin}:${s.key}`);
  }
}
