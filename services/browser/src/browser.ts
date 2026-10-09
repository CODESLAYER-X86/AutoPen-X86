/**
 * Browser service (spec Part 3 §2-§10, §30, §38-§39, §60, §73-§75).
 *
 * Owns the entire Playwright surface. Neither the LLM nor the workers
 * ever see Playwright — they see deterministic browser tools backed by
 * this service (§2). Isolation model (§3):
 *
 *   Engagement -> Browser (one chromium process)
 *     -> BrowserContext per identity (anonymous = its own context)
 *       -> Pages (bounded)
 *
 * Contexts are independently disposable and NEVER share cookies or
 * storage (§3, §29). Cleanup runs in finally-style paths so a worker
 * crash cannot leak browser processes (§5, §75).
 */
import type { Browser, BrowserContext, Page } from 'playwright-core';
import { chromium } from 'playwright-core';
import {
  AuthorizationError,
  generateId,
  ScopeViolationError,
  ToolError,
  type BrowserAction,
  type BrowserContextStatus,
  type HttpProvenanceSource,
  type HttpRequestSource,
} from '@aegis/shared';
import { ScopeChecker, type ScopeRules } from '@aegis/security';
import type { BrowserActionRequest, DomSnapshot, ScreenshotOutput } from '@aegis/contracts';
import { HttpTrafficRecorder, type EvidenceServiceSurface, type EventBusSurface, type HttpTrafficRepositorySurface } from '@aegis/target-http';
import type { SessionManager } from '@aegis/session-manager';
import { DEFAULT_BROWSER_RESOURCE_LIMITS, DEFAULT_BROWSER_SECURITY_POLICY, policyToContextOptions, POPUP_BLOCK_INIT_SCRIPT, type BrowserResourceLimits, type BrowserSecurityPolicy } from './security.js';
import { BrowserEventBuffer, consolePayload, type BrowserEventSink } from './events.js';
import { attachContextCapture, PageNetworkCapture, type CapturedExchange } from './network.js';
import { captureCookies, captureStorage, type CookieRepositorySurface, type StorageRepositorySurface } from './storage.js';
import { captureDownload, createWebSocketObserver, type DownloadRepositorySurface, type WebSocketRepositorySurface, type WsMessageRecord } from './capture.js';
import { diffSnapshots, extractDomSnapshot, extractScriptInventory } from './dom.js';
import { toLocator, describeSelector } from './selectors.js';

// ---------------------------------------------------------------------------
// Repository surfaces
// ---------------------------------------------------------------------------

export interface ContextRepositorySurface {
  insert(input: {
    id: string;
    engagementId: string;
    identityId: string | null;
    status: BrowserContextStatus;
    securityPolicy: Record<string, unknown>;
    createdAt: string;
  }): Promise<Record<string, unknown>>;
  updateStatus(id: string, status: BrowserContextStatus): Promise<void>;
  findById(id: string): Promise<Record<string, unknown> | null>;
  listByEngagement(engagementId: string): Promise<Array<Record<string, unknown>>>;
}

export interface PageRepositorySurface {
  insert(input: { id: string; contextId: string; createdAt: string; closedAt: string | null }): Promise<void>;
  markClosed(id: string): Promise<void>;
}

export interface DomSnapshotRepositorySurface {
  insert(input: {
    id: string;
    engagementId: string;
    contextId: string;
    pageId: string;
    url: string;
    title: string | null;
    snapshot: Record<string, unknown>;
    evidenceId: string;
    createdAt: string;
  }): Promise<void>;
  listByEngagement(engagementId: string, limit: number): Promise<Array<Record<string, unknown>>>;
}

export interface BrowserLaunchOptions {
  headless: boolean;
  executablePath: string | null;
  /** Lab networks allow loopback (fixture apps); production denies it. */
  networkPolicy: {
    allowLoopback: boolean;
    allowPrivateNetworks: boolean;
    allowedSchemes: string[];
    maxRedirects: number;
  };
}

export const DEFAULT_LAUNCH_OPTIONS: BrowserLaunchOptions = {
  headless: true,
  executablePath: null,
  networkPolicy: {
    allowLoopback: true,
    allowPrivateNetworks: true,
    allowedSchemes: ['http', 'https'],
    maxRedirects: 5,
  },
};

// ---------------------------------------------------------------------------
// Context handle (internal)
// ---------------------------------------------------------------------------

interface ContextHandle {
  id: string;
  engagementId: string;
  identityId: string | null;
  pw: BrowserContext;
  status: BrowserContextStatus;
  events: BrowserEventBuffer;
  pages: Map<Page, { id: string; capture: PageNetworkCapture }>;
  websockets: Map<import('playwright-core').WebSocket, { observer: ReturnType<typeof createWebSocketObserver> }>;
  closed: boolean;
  createdAt: number;
}

export interface ActionResult {
  action: BrowserAction;
  ok: boolean;
  page_id: string | null;
  url: string | null;
  details: Record<string, unknown>;
  evidence_ids: string[];
  http_records: string[];
  error: { code: string; message: string } | null;
}

export interface BrowserServiceDeps {
  contexts: ContextRepositorySurface;
  pagesRepo: PageRepositorySurface;
  events: BrowserEventSink;
  cookies: CookieRepositorySurface;
  storage: StorageRepositorySurface;
  downloads: DownloadRepositorySurface;
  websockets: WebSocketRepositorySurface;
  domSnapshots: DomSnapshotRepositorySurface;
  evidence: EvidenceServiceSurface;
  recorder: HttpTrafficRecorder;
  httpRepository: HttpTrafficRepositorySurface;
  eventBus: EventBusSurface;
  secretStore: { store(plaintext: string): Promise<string> };
  sessionManager: SessionManager;
  securityPolicy?: Partial<BrowserSecurityPolicy>;
  limits?: Partial<BrowserResourceLimits>;
  launch?: Partial<BrowserLaunchOptions>;
}

// ---------------------------------------------------------------------------
// Service
// ---------------------------------------------------------------------------

export class BrowserService {
  private readonly deps: BrowserServiceDeps;
  private readonly policy: BrowserSecurityPolicy;
  private readonly limits: BrowserResourceLimits;
  private readonly launch: BrowserLaunchOptions;
  private readonly browsers = new Map<string, Browser>();
  private readonly contexts = new Map<string, ContextHandle>();
  private readonly contextByKey = new Map<string, string>();

  constructor(deps: BrowserServiceDeps) {
    this.deps = deps;
    this.policy = { ...DEFAULT_BROWSER_SECURITY_POLICY, ...deps.securityPolicy };
    this.limits = { ...DEFAULT_BROWSER_RESOURCE_LIMITS, ...deps.limits };
    this.launch = { ...DEFAULT_LAUNCH_OPTIONS, ...deps.launch };
  }

  // -- Lifecycle ------------------------------------------------------------

  private async ensureBrowser(engagementId: string): Promise<Browser> {
    const existing = this.browsers.get(engagementId);
    if (existing && existing.isConnected()) return existing;
    const browser = await chromium.launch({
      headless: this.launch.headless,
      executablePath: this.launch.executablePath ?? undefined,
      args: ['--no-sandbox', '--disable-dev-shm-usage', '--disable-gpu'],
    });
    this.browsers.set(engagementId, browser);
    browser.on('disconnected', () => {
      for (const [, handle] of this.contexts) {
        if (handle.engagementId === engagementId && !handle.closed) {
          handle.status = 'FAILED';
          void this.deps.contexts.updateStatus(handle.id, 'FAILED');
        }
      }
      this.browsers.delete(engagementId);
    });
    await this.deps.eventBus.publish({
      type: 'BROWSER_SESSION_STARTED',
      engagement_id: engagementId,
      task_id: null,
      trace_id: generateId('TRC'),
      actor_id: null,
      payload: { headless: this.launch.headless },
      occurred_at: new Date().toISOString(),
      dedup_key: `browser-session:${engagementId}:${Date.now()}`,
    });
    return browser;
  }

  /**
   * Resolve (or create) the browser context for an identity (§3-§4, §30).
   * Anonymous requests get their own isolated context — never a shared one.
   */
  async getContextHandle(
    engagementId: string,
    identityId: string | null,
  ): Promise<ContextHandle> {
    const key = `${engagementId}:${identityId ?? 'ANONYMOUS'}`;
    const existingId = this.contextByKey.get(key);
    if (existingId) {
      const handle = this.contexts.get(existingId);
      if (handle && !handle.closed) return handle;
    }

    // Resource limit: contexts per engagement (§74).
    const engagementContexts = [...this.contexts.values()].filter(
      (c) => c.engagementId === engagementId && !c.closed,
    );
    if (engagementContexts.length >= this.limits.maxContextsPerEngagement) {
      throw new ToolError(
        `Engagement already holds ${engagementContexts.length} browser contexts (limit ${this.limits.maxContextsPerEngagement})`,
        'BROWSER_CONTEXT_LIMIT',
      );
    }

    const browser = await this.ensureBrowser(engagementId);
    const contextId = generateId('CTX');

    // CREATE -> INITIALIZE (§5).
    await this.deps.contexts.insert({
      id: contextId,
      engagementId,
      identityId,
      status: 'INITIALIZE',
      securityPolicy: this.policy as unknown as Record<string, unknown>,
      createdAt: new Date().toISOString(),
    });

    const pw = await browser.newContext({
      ...policyToContextOptions(this.policy),
      // Isolation: every context gets a fresh, random storage partition.
      storageState: undefined,
    });
    if (!this.policy.popupsEnabled) {
      await pw.addInitScript(POPUP_BLOCK_INIT_SCRIPT);
    }

    // Identity authentication import (§4, §26).
    if (identityId) {
      const state = await this.deps.sessionManager.resolveForBrowser(identityId);
      if (state.cookies.length > 0) {
        await pw.addCookies(
          state.cookies.map((c) => ({
            name: c.name,
            value: c.value,
            domain: c.domain,
            path: c.path,
            secure: c.secure,
            httpOnly: c.httpOnly,
            sameSite: c.sameSite ?? undefined,
            expires: c.expires ?? undefined,
          })),
        );
      }
      for (const [origin, entries] of state.storageOrigins) {
        const script = buildStorageInitScript(origin, entries);
        await pw.addInitScript(script);
      }
    }

    const handle: ContextHandle = {
      id: contextId,
      engagementId,
      identityId,
      pw,
      status: 'READY',
      events: new BrowserEventBuffer(engagementId, contextId),
      pages: new Map(),
      websockets: new Map(),
      closed: false,
      createdAt: Date.now(),
    };
    this.contexts.set(contextId, handle);
    this.contextByKey.set(key, contextId);

    attachContextCapture(pw, { maxBodyBytes: this.limits.maxDownloadBytes }).forEach((capture, page) => {
      this.registerPage(handle, page, capture);
    });
    pw.on('page', (page) => {
      const capture = new PageNetworkCapture(page, { maxBodyBytes: this.limits.maxDownloadBytes });
      capture.attach();
      this.registerPage(handle, page, capture);
    });
    pw.on('close', () => {
      handle.closed = true;
    });

    // READY (§5).
    await this.deps.contexts.updateStatus(contextId, 'READY');
    handle.events.emit('BROWSER_CONTEXT_CREATED' as never, { identity_id: identityId }, { pageId: null, url: null });
    await this.flushEvents(handle);
    return handle;
  }

  private registerPage(handle: ContextHandle, page: Page, capture: import('./network.js').PageNetworkCapture): void {
    const pageId = generateId('PGE');
    void this.deps.pagesRepo.insert({ id: pageId, contextId: handle.id, createdAt: new Date().toISOString(), closedAt: null });
    handle.pages.set(page, { id: pageId, capture });
    handle.events.emit('PAGE_CREATED', {}, { pageId, url: page.url() });
    page.on('close', () => {
      handle.events.emit('PAGE_CLOSED', {}, { pageId, url: null });
      void this.deps.pagesRepo.markClosed(pageId);
      handle.pages.delete(page);
    });
    page.on('console', (message) => {
      const text = message.text();
      if (handle.events.size < 1900) {
        handle.events.emit('CONSOLE_MESSAGE', consolePayload(message.type(), text), { pageId, url: page.url() });
      }
    });
    page.on('pageerror', (error) => {
      handle.events.emit('PAGE_ERROR', { message: String(error.message).slice(0, 2048) }, { pageId, url: page.url() });
    });
    page.on('framenavigated', (frame) => {
      if (frame === page.mainFrame()) {
        handle.events.emit('NAVIGATION_COMPLETED', { url: frame.url().slice(0, 2048) }, { pageId, url: frame.url() });
      }
    });
    page.on('websocket', (ws) => {
      const observer = createWebSocketObserver(ws, { maxMessageBytes: this.limits.maxWebSocketMessageBytes }, (record) => {
        handle.events.emit('WEBSOCKET_MESSAGE', {
          direction: record.direction,
          is_binary: record.isBinary,
          bytes: record.byteSize,
        }, { pageId, url: ws.url() });
      });
      handle.websockets.set(ws, { observer });
      handle.events.emit('WEBSOCKET_CREATED', { url: ws.url() }, { pageId, url: ws.url() });
      ws.on('close', () => {
        handle.events.emit('WEBSOCKET_CLOSED', { url: ws.url() }, { pageId, url: ws.url() });
        // Connection row FIRST (FK), then drain remaining frames (§36).
        void this.deps.websockets
          .insertConnection({
            id: observer.id,
            engagementId: handle.engagementId,
            contextId: handle.id,
            pageId,
            url: observer.url,
            origin: observer.origin,
            openedAt: new Date(handle.createdAt).toISOString(),
            closedAt: observer.closeInfo.closedAt,
            closeCode: observer.closeInfo.closeCode,
          })
          .catch(() => undefined)
          .then(async () => {
            await observer.drain(async (message) => {
              await this.persistWsMessage(handle, observer.id, message);
            });
          })
          .catch(() => undefined);
        handle.websockets.delete(ws);
      });
    });
    // Downloads (§37) arrive on the page; untrusted content is captured
    // as evidence or explicitly cancelled when policy blocks retention.
    page.on('download', (download) => {
      void this.handleDownload(handle, pageId, download);
    });
  }

  private async handleDownload(handle: ContextHandle, pageId: string, download: import('playwright-core').Download): Promise<void> {
    handle.events.emit('DOWNLOAD_STARTED', { url: download.url() }, { pageId, url: download.url() });
    if (!this.policy.downloadsEnabled) {
      // Policy blocks retention: the download is cancelled explicitly.
      await download.cancel().catch(() => undefined);
      handle.events.emit('DOWNLOAD_COMPLETED', { blocked: true, reason: 'downloads disabled by policy' }, { pageId, url: download.url() });
      return;
    }
    const captured = await captureDownload(download, {
      engagementId: handle.engagementId,
      contextId: handle.id,
      pageId,
      repository: this.deps.downloads,
      evidence: this.deps.evidence,
      limits: { maxBytes: this.limits.maxDownloadBytes },
    });
    handle.events.emit(
      'DOWNLOAD_COMPLETED',
      { id: captured.id, filename: captured.filename, size: captured.size, sha256: captured.sha256, truncated: captured.truncated },
      { pageId, url: captured.url },
    );
    await this.deps.eventBus.publish({
      type: 'DOWNLOAD_CAPTURED',
      engagement_id: handle.engagementId,
      task_id: null,
      trace_id: generateId('TRC'),
      actor_id: null,
      payload: { download_id: captured.id, filename: captured.filename, sha256: captured.sha256, size: captured.size },
      occurred_at: new Date().toISOString(),
      dedup_key: `download:${captured.id}`,
    });
  }

  // -- Actions (§7-§8) -------------------------------------------------------

  /**
   * Execute a structured browser action. The URL scope check (§49) happens
   * BEFORE navigation; interactive actions are deterministic Playwright
   * operations with normalized errors (§9).
   */
  async performAction(
    engagementId: string,
    request: BrowserActionRequest,
    scope: ScopeRules,
  ): Promise<ActionResult> {
    const handle = await this.resolveContext(engagementId, request.context_id);
    if (handle.closed || handle.status === 'FAILED') {
      throw new ToolError(`Browser context '${request.context_id}' is closed or failed`, 'BROWSER_CONTEXT_CLOSED');
    }
    handle.status = 'ACTIVE';
    void this.deps.contexts.updateStatus(handle.id, 'ACTIVE');

    const page = await this.resolvePage(handle, request.page_id);
    const evidenceIds: string[] = [];
    const httpRecords: string[] = [];
    const startedAt = Date.now();

    try {
      const outcome = await this.executeAction(handle, page, request, scope, evidenceIds);
      // Network capture drain + HTTP record promotion (§14).
      const records = await this.drainAndRecord(handle, page);
      httpRecords.push(...records);
      // WebSocket message persistence at action boundaries (§36).
      await this.drainWebsockets(handle);
      await this.flushEvents(handle);
      const elapsed = Date.now() - startedAt;
      if (elapsed > this.limits.maxTotalBrowserTimeMs) {
        throw new ToolError('Browser total time budget exceeded', 'BROWSER_TIME_EXCEEDED');
      }
      return {
        action: request.action,
        ok: true,
        page_id: this.pageId(handle, page),
        url: page.url() === 'about:blank' ? null : page.url(),
        details: outcome.details,
        evidence_ids: evidenceIds,
        http_records: httpRecords,
        error: null,
      };
    } catch (error) {
      await this.flushEvents(handle).catch(() => undefined);
      const code = isPlatformToolError(error) ? (error as { code: string }).code : 'BROWSER_ACTION_FAILED';
      const message = error instanceof Error ? error.message : 'browser action failed';
      handle.events.emit('PAGE_ERROR', { action: request.action, code, message: message.slice(0, 1024) }, { pageId: this.pageId(handle, page), url: null });
      return {
        action: request.action,
        ok: false,
        page_id: this.pageId(handle, page),
        url: null,
        details: {},
        evidence_ids: evidenceIds,
        http_records: httpRecords,
        error: { code, message: message.slice(0, 1024) },
      };
    }
  }

  private async executeAction(
    handle: ContextHandle,
    page: Page,
    request: BrowserActionRequest,
    scope: ScopeRules,
    evidenceIds: string[],
  ): Promise<{ details: Record<string, unknown> }> {
    const timeout = Math.min(request.timeout_ms ?? this.limits.maxNavigationTimeMs, this.limits.maxNavigationTimeMs);

    switch (request.action) {
      case 'navigate': {
        if (!request.url) throw new ToolError('navigate requires a url', 'BROWSER_ACTION_INPUT_INVALID');
        await this.validateUrlInScope(request.url, scope);
        handle.events.emit('NAVIGATION_STARTED', { url: request.url.slice(0, 2048) }, { pageId: this.pageId(handle, page), url: request.url });
        const response = await page.goto(request.url, { timeout, waitUntil: 'domcontentloaded' });
        const finalUrl = page.url();
        return {
          details: {
            status: response?.status() ?? null,
            final_url: finalUrl,
            title: await safeTitle(page),
          },
        };
      }
      case 'go_back': {
        const response = await page.goBack({ timeout });
        return { details: { status: response?.status() ?? null, url: page.url() } };
      }
      case 'go_forward': {
        const response = await page.goForward({ timeout });
        return { details: { status: response?.status() ?? null, url: page.url() } };
      }
      case 'reload': {
        const response = await page.reload({ timeout });
        return { details: { status: response?.status() ?? null } };
      }
      case 'click': {
        const selector = requireSelector(request);
        const locator = toLocator(page, selector);
        await locator.click({ timeout });
        handle.events.emit('CLICK', { selector: describeSelector(selector) }, { pageId: this.pageId(handle, page), url: page.url() });
        return { details: { selector: describeSelector(selector) } };
      }
      case 'fill': {
        const selector = requireSelector(request);
        if (request.value === undefined) throw new ToolError('fill requires a value', 'BROWSER_ACTION_INPUT_INVALID');
        const locator = toLocator(page, selector);
        await locator.fill(request.value, { timeout });
        handle.events.emit('INPUT', { selector: describeSelector(selector), value_length: request.value.length }, { pageId: this.pageId(handle, page), url: page.url() });
        return { details: { selector: describeSelector(selector) } };
      }
      case 'select_option': {
        const selector = requireSelector(request);
        const locator = toLocator(page, selector);
        await locator.selectOption(request.values ?? (request.value ? [request.value] : []), { timeout });
        handle.events.emit('INPUT', { selector: describeSelector(selector), kind: 'select' }, { pageId: this.pageId(handle, page), url: page.url() });
        return { details: { selector: describeSelector(selector) } };
      }
      case 'check': {
        const locator = toLocator(page, requireSelector(request));
        await locator.check({ timeout });
        return { details: {} };
      }
      case 'uncheck': {
        const locator = toLocator(page, requireSelector(request));
        await locator.uncheck({ timeout });
        return { details: {} };
      }
      case 'press': {
        if (!request.key) throw new ToolError('press requires a key', 'BROWSER_ACTION_INPUT_INVALID');
        await page.keyboard.press(request.key);
        return { details: { key: request.key } };
      }
      case 'hover': {
        const locator = toLocator(page, requireSelector(request));
        await locator.hover({ timeout });
        return { details: { selector: describeSelector(requireSelector(request)) } };
      }
      case 'wait_for_url': {
        if (!request.url) throw new ToolError('wait_for_url requires a url pattern', 'BROWSER_ACTION_INPUT_INVALID');
        await page.waitForURL(request.url, { timeout });
        return { details: { url: page.url() } };
      }
      case 'wait_for_selector': {
        const selector = requireSelector(request);
        const locator = toLocator(page, selector);
        await locator.waitFor({ state: 'visible', timeout });
        return { details: { selector: describeSelector(selector) } };
      }
      case 'screenshot': {
        const bytes = await page.screenshot({ type: 'png', fullPage: false });
        const capped = this.capBytes(new Uint8Array(bytes), this.limits.maxScreenshotBytes);
        const evidence = await this.deps.evidence.store({
          engagement_id: handle.engagementId,
          type: 'SCREENSHOT',
          source: 'browser',
          content: capped.bytes,
          metadata: {
            classification: 'SCREENSHOT',
            context_id: handle.id,
            page_id: this.pageId(handle, page),
            url: page.url(),
            truncated: capped.truncated,
          },
        });
        evidenceIds.push(evidence.id);
        const output: ScreenshotOutput = {
          context_id: handle.id,
          page_id: this.pageId(handle, page),
          evidence_id: evidence.id,
          sha256: evidence.sha256,
          byte_size: capped.bytes.byteLength,
          truncated: capped.truncated,
        };
        return { details: output as unknown as Record<string, unknown> };
      }
      case 'snapshot': {
        const snapshot = await this.captureSnapshot(handle, page, evidenceIds);
        return { details: snapshot };
      }
    }
  }

  /** DOM snapshot capture + persistence + events (§31-§33, §38). */
  async captureSnapshot(handle: ContextHandle, page: Page, evidenceIds: string[]): Promise<Record<string, unknown>> {
    const raw = await extractDomSnapshot(page);
    const snapshotId = generateId('DMS');
    const scripts = await extractScriptInventory(page);
    const evidence = await this.deps.evidence.store({
      engagement_id: handle.engagementId,
      type: 'DERIVED',
      source: 'browser-dom-snapshot',
      content: JSON.stringify(raw),
      metadata: { classification: 'DERIVED', context_id: handle.id, page_id: this.pageId(handle, page), url: page.url() },
    });
    evidenceIds.push(evidence.id);

    const snapshot: DomSnapshot = {
      id: snapshotId,
      context_id: handle.id,
      page_id: this.pageId(handle, page) ?? '',
      url: page.url().slice(0, 2048),
      title: raw.title,
      elements: raw.elements,
      links: raw.links,
      buttons: raw.buttons,
      iframes: raw.iframes,
      scripts,
      stylesheets: raw.stylesheets,
      images: raw.images,
      created_at: new Date().toISOString(),
    };

    await this.deps.domSnapshots.insert({
      id: snapshotId,
      engagementId: handle.engagementId,
      contextId: handle.id,
      pageId: this.pageId(handle, page) ?? '',
      url: snapshot.url,
      title: snapshot.title,
      snapshot: snapshot as unknown as Record<string, unknown>,
      evidenceId: evidence.id,
      createdAt: snapshot.created_at,
    });

    handle.events.emit('DOM_SNAPSHOT_CAPTURED' as never, {
      snapshot_id: snapshotId,
      elements: raw.elements.length,
      links: raw.links.length,
      scripts: scripts.length,
    }, { pageId: this.pageId(handle, page), url: page.url() });

    await this.deps.eventBus.publish({
      type: 'DOM_SNAPSHOT_CAPTURED',
      engagement_id: handle.engagementId,
      task_id: null,
      trace_id: generateId('TRC'),
      actor_id: null,
      payload: { snapshot_id: snapshotId, url: snapshot.url, elements: raw.elements.length },
      occurred_at: new Date().toISOString(),
      dedup_key: `dom-snapshot:${snapshotId}`,
    });

    return {
      snapshot_id: snapshotId,
      evidence_id: evidence.id,
      url: snapshot.url,
      title: snapshot.title,
      counts: {
        elements: raw.elements.length,
        links: raw.links.length,
        buttons: raw.buttons.length,
        forms: raw.elements.filter((e) => e.tag === 'form').length,
        inputs: raw.elements.filter((e) => ['input', 'select', 'textarea'].includes(e.tag)).length,
        iframes: raw.iframes.length,
        scripts: scripts.length,
        stylesheets: raw.stylesheets.length,
        images: raw.images.length,
      },
    };
  }

  /** Capture cookies + storage for a context (§23-§24). */
  async captureContextState(
    engagementId: string,
    contextId: string,
  ): Promise<{ cookies: { count: number; sensitive: number }; storage: { origins: number; entries: number; sensitive: number } }> {
    const handle = await this.resolveContext(engagementId, contextId);
    const cookieResult = await captureCookies(handle.pw, {
      engagementId,
      contextId,
      identityId: handle.identityId,
      repository: this.deps.cookies,
      secretStore: this.deps.secretStore,
    });
    let storageResult = { origins: 0, entries: 0, sensitiveCount: 0 };
    const page = handle.pages.keys().next();
    if (!page.done && page.value) {
      storageResult = await captureStorage(page.value, {
        engagementId,
        contextId,
        identityId: handle.identityId,
        repository: this.deps.storage,
        secretStore: this.deps.secretStore,
      });
    }
    handle.events.emit('COOKIE_CHANGED', { captured: cookieResult.count }, { pageId: null, url: null });
    handle.events.emit('STORAGE_CHANGED', { entries: storageResult.entries }, { pageId: null, url: null });
    await this.flushEvents(handle);
    return {
      cookies: { count: cookieResult.count, sensitive: cookieResult.sensitiveCount },
      storage: { origins: storageResult.origins, entries: storageResult.entries, sensitive: storageResult.sensitiveCount },
    };
  }

  /** DOM diff between the current page and a stored snapshot (§33). */
  async diffAgainstSnapshot(
    engagementId: string,
    contextId: string,
    beforeSnapshotId: string,
  ): Promise<{ added: string[]; removed: string[]; changed: Array<{ selector: string; before: string | null; after: string | null }> }> {
    const handle = await this.resolveContext(engagementId, contextId);
    const page = [...handle.pages.keys()][0];
    if (!page) throw new ToolError('No open page in this context', 'BROWSER_NO_PAGE');
    const before = await this.loadSnapshotElements(handle.engagementId, beforeSnapshotId);
    const after = await extractDomSnapshot(page);
    const diff = diffSnapshots(
      { elements: before.elements, links: before.links },
      { elements: after.elements, links: after.links },
    );
    handle.events.emit('DOM_CHANGE_DETECTED' as never, { added: diff.added.length, removed: diff.removed.length, changed: diff.changed.length }, { pageId: this.pageId(handle, page), url: page.url() });
    await this.flushEvents(handle);
    return diff;
  }

  private async loadSnapshotElements(
    engagementId: string,
    snapshotId: string,
  ): Promise<{ elements: DomSnapshot['elements']; links: DomSnapshot['links'] }> {
    const all = await this.deps.domSnapshots.listByEngagement(engagementId, 200);
    const row = all.find((r) => r.id === snapshotId);
    if (!row) throw new ToolError(`Snapshot '${snapshotId}' not found`, 'SNAPSHOT_NOT_FOUND');
    const snapshot = (row.snapshot ?? {}) as Record<string, unknown>;
    return {
      elements: (snapshot.elements ?? []) as DomSnapshot['elements'],
      links: (snapshot.links ?? []) as DomSnapshot['links'],
    };
  }

  // -- Cleanup (§75) ---------------------------------------------------------

  /** Close one context: pages -> flush artifacts -> persist events -> close. */
  async closeContext(engagementId: string, contextId: string, status: BrowserContextStatus = 'CLOSED'): Promise<void> {
    const handle = this.contexts.get(contextId);
    if (!handle) return;
    if (handle.closed) {
      this.contexts.delete(contextId);
      return;
    }
    await this.deps.contexts.updateStatus(contextId, 'CLOSING');
    try {
      // Final capture drain (flush artifacts before teardown).
      for (const [, entry] of handle.pages) {
        const captures = await entry.capture.drain();
        await this.persistCaptures(handle, captures);
      }
      // Persist websocket messages + connections.
      for (const [, ws] of handle.websockets) {
        await ws.observer.drain(async (message) => {
          await this.persistWsMessage(handle, ws.observer.id, message);
        });
      }
      await this.flushEvents(handle);
      // Cookies survive into the cookie table before context disposal (§75).
      await captureCookies(handle.pw, {
        engagementId,
        contextId,
        identityId: handle.identityId,
        repository: this.deps.cookies,
        secretStore: this.deps.secretStore,
      }).catch(() => undefined);
      await handle.pw.close();
    } finally {
      handle.closed = true;
      handle.status = status;
      this.contexts.delete(contextId);
      for (const [key, value] of this.contextByKey) {
        if (value === contextId) this.contextByKey.delete(key);
      }
      await this.deps.contexts.updateStatus(contextId, status).catch(() => undefined);
      await this.deps.eventBus.publish({
        type: 'BROWSER_CONTEXT_CLOSED',
        engagement_id: engagementId,
        task_id: null,
        trace_id: generateId('TRC'),
        actor_id: null,
        payload: { context_id: contextId, identity_id: handle.identityId, status },
        occurred_at: new Date().toISOString(),
        dedup_key: `browser-context-closed:${contextId}`,
      });
    }
  }

  /** Close every context + browser for an engagement (worker crash safe). */
  async closeEngagement(engagementId: string): Promise<void> {
    const ids = [...this.contexts.values()]
      .filter((c) => c.engagementId === engagementId)
      .map((c) => c.id);
    for (const id of ids) {
      await this.closeContext(engagementId, id).catch(() => undefined);
    }
    const browser = this.browsers.get(engagementId);
    if (browser) {
      await browser.close().catch(() => undefined);
      this.browsers.delete(engagementId);
    }
    await this.deps.eventBus.publish({
      type: 'BROWSER_SESSION_CLOSED',
      engagement_id: engagementId,
      task_id: null,
      trace_id: generateId('TRC'),
      actor_id: null,
      payload: { contexts_closed: ids.length },
      occurred_at: new Date().toISOString(),
      dedup_key: `browser-session-closed:${engagementId}:${Date.now()}`,
    });
  }

  listContexts(engagementId: string): Promise<Array<Record<string, unknown>>> {
    return this.deps.contexts.listByEngagement(engagementId);
  }

  // -- Internals --------------------------------------------------------------

  private async resolveContext(engagementId: string, contextId: string): Promise<ContextHandle> {
    const handle = this.contexts.get(contextId);
    if (handle) {
      if (handle.engagementId !== engagementId) {
        throw new AuthorizationError('Browser context belongs to a different engagement', 'BROWSER_CONTEXT_ENGAGEMENT_MISMATCH');
      }
      return handle;
    }
    throw new ToolError(`Browser context '${contextId}' is not open`, 'BROWSER_CONTEXT_NOT_FOUND');
  }

  private async resolvePage(handle: ContextHandle, pageId: string | null): Promise<Page> {
    if (pageId) {
      for (const [page, entry] of handle.pages) {
        if (entry.id === pageId) return page;
      }
      throw new ToolError(`Page '${pageId}' not found in context`, 'BROWSER_PAGE_NOT_FOUND');
    }
    const first = [...handle.pages.keys()][0];
    if (first) return first;
    const page = await handle.pw.newPage();
    // Pages limit (§74).
    if (handle.pages.size > this.limits.maxPagesPerContext) {
      await page.close();
      throw new ToolError(`Context exceeds ${this.limits.maxPagesPerContext} pages`, 'BROWSER_PAGE_LIMIT');
    }
    return page;
  }

  private pageId(handle: ContextHandle, page: Page): string | null {
    return handle.pages.get(page)?.id ?? null;
  }

  private async validateUrlInScope(url: string, scope: ScopeRules): Promise<void> {
    const checker = new ScopeChecker(scope);
    const result = checker.checkUrl(url);
    if (!result.allowed) {
      throw new ScopeViolationError(
        `Browser navigation refused: ${result.reason}`,
        result.code,
      );
    }
  }

  private async drainAndRecord(handle: ContextHandle, page: Page): Promise<string[]> {
    const entry = handle.pages.get(page);
    if (!entry) return [];
    const captures = await entry.capture.drain();
    return this.persistCaptures(handle, captures);
  }

  /** Promote browser captures into shared HTTP records (§14, §62). */
  private async persistCaptures(handle: ContextHandle, captures: CapturedExchange[]): Promise<string[]> {
    const ids: string[] = [];
    for (const capture of captures) {
      handle.events.emit(
        capture.shouldPersistRecord ? 'RESPONSE_RECEIVED' : 'REQUEST_FINISHED',
        {
          method: capture.exchange.request.method,
          url: capture.exchange.request.url.slice(0, 2048),
          status: capture.exchange.response.status,
          resource_type: capture.resourceType,
          truncated: capture.exchange.response.truncated,
        },
        { pageId: null, url: capture.exchange.request.url },
      );
      if (!capture.shouldPersistRecord) continue;
      const recorded = await this.deps.recorder.recordExchange({
        engagementId: handle.engagementId,
        taskId: null,
        identityId: handle.identityId,
        exchange: capture.exchange,
        source: 'BROWSER' as HttpRequestSource,
        provenance: {
          source: 'browser_observation' as HttpProvenanceSource,
          parentTaskId: null,
          hypothesisId: null,
          testId: null,
          reason: 'browser network capture',
        },
        parentRequestId: null,
        browserContextId: handle.id,
        browserPageId: null,
        correlationId: handle.id,
      });
      ids.push(recorded.request.id);
    }
    return ids;
  }

  private async persistWsMessage(handle: ContextHandle, connectionId: string, message: WsMessageRecord): Promise<void> {
    let artifactRef: string | null = null;
    if (message.byteSize > 2048) {
      const evidence = await this.deps.evidence.store({
        engagement_id: handle.engagementId,
        type: 'RAW',
        source: 'websocket-message',
        content: message.payload,
        metadata: { classification: 'RAW', connection_id: connectionId, direction: message.direction },
      });
      artifactRef = evidence.id;
    }
    await this.deps.websockets.insertMessage({
      id: generateId('WSM'),
      connectionId,
      direction: message.direction,
      isBinary: message.isBinary,
      payloadArtifactRef: artifactRef,
      payloadPreview: message.payload.slice(0, 2048),
      byteSize: message.byteSize,
      truncated: message.payload.length < message.byteSize,
    });
  }

  private async flushEvents(handle: ContextHandle): Promise<void> {
    await handle.events.flush(this.deps.events);
  }

  /** Persist buffered WebSocket frames for all live connections (§36). */
  private async drainWebsockets(handle: ContextHandle): Promise<void> {
    for (const [, ws] of handle.websockets) {
      await ws.observer.drain(async (message) => {
        await this.persistWsMessage(handle, ws.observer.id, message);
      });
    }
  }

  private capBytes(bytes: Uint8Array, limit: number): { bytes: Uint8Array; truncated: boolean } {
    if (bytes.byteLength <= limit) return { bytes, truncated: false };
    return { bytes: bytes.slice(0, limit), truncated: true };
  }
}

function requireSelector(request: BrowserActionRequest): NonNullable<BrowserActionRequest['selector']> {
  if (!request.selector) {
    throw new ToolError(`Action '${request.action}' requires a selector`, 'BROWSER_SELECTOR_REQUIRED');
  }
  return request.selector;
}

async function safeTitle(page: Page): Promise<string | null> {
  try {
    return (await page.title()).slice(0, 1024);
  } catch {
    return null;
  }
}

function isPlatformToolError(error: unknown): boolean {
  return error instanceof ToolError || error instanceof AuthorizationError || error instanceof ScopeViolationError;
}

function buildStorageInitScript(origin: string, entries: Array<{ area: 'LOCAL' | 'SESSION'; key: string; value: string }>): string {
  const payload = JSON.stringify({ origin, entries });
  return `(() => {
  try {
    const state = ${payload};
    if (location.origin !== state.origin) return;
    for (const entry of state.entries) {
      const store = entry.area === 'LOCAL' ? localStorage : sessionStorage;
      store.setItem(entry.key, entry.value);
    }
  } catch (e) { /* isolated world */ }
})();`;
}
