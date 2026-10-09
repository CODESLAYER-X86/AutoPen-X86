/**
 * Cookie + browser storage capture (spec Part 3 §23-§24, §66).
 *
 * Cookie VALUES and sensitive storage values never enter model context or
 * SQL: they are moved to the encrypted secret store and referenced as
 * opaque `SEC_…` / `COOKIE_REF_…` handles (§23). Non-sensitive storage is
 * recorded directly. The secret-store / repo surfaces are injected so this
 * module stays testable in isolation.
 */
import type { BrowserContext, Page } from 'playwright-core';
import { generateId } from '@aegis/shared';

export interface CookieRepositorySurface {
  upsert(input: {
    id: string;
    engagementId: string;
    contextId: string;
    identityId: string | null;
    name: string;
    domain: string;
    path: string;
    secure: boolean;
    httpOnly: boolean;
    sameSite: string | null;
    expiration: string | null;
    secretReference: string;
  }): Promise<void>;
  listByContext(contextId: string): Promise<Array<Record<string, unknown>>>;
}

export interface StorageRepositorySurface {
  upsert(input: {
    id: string;
    engagementId: string;
    contextId: string;
    identityId: string | null;
    origin: string;
    area: 'LOCAL' | 'SESSION';
    key: string;
    valueRedacted: string;
    isSensitive: boolean;
    secretReference: string | null;
  }): Promise<void>;
  listByContext(contextId: string): Promise<Array<Record<string, unknown>>>;
}

export interface SecretStoreSurface {
  store(plaintext: string): Promise<string>;
}

/** Cookie names that are treated as sensitive for storage redaction. */
const SENSITIVE_STORAGE_KEYS = [
  /token/i,
  /auth/i,
  /session/i,
  /secret/i,
  /password/i,
  /credential/i,
  /jwt/i,
  /key/i,
];

export interface CapturedCookie {
  name: string;
  domain: string;
  path: string;
  secure: boolean;
  httpOnly: boolean;
  sameSite: string | null;
  expires: number;
}

export interface CookieCaptureResult {
  count: number;
  sensitiveCount: number;
  /** Reference handles for downstream tools (never values). */
  references: string[];
}

/**
 * Capture cookies from a context into secret store + cookie table (§23).
 */
export async function captureCookies(
  context: BrowserContext,
  input: {
    engagementId: string;
    contextId: string;
    identityId: string | null;
    repository: CookieRepositorySurface;
    secretStore: SecretStoreSurface;
  },
): Promise<CookieCaptureResult> {
  const cookies = await context.cookies();
  let sensitiveCount = 0;
  const references: string[] = [];
  for (const cookie of cookies.slice(0, 256)) {
    const reference = `COOKIE_REF_${generateId('SEC').slice(4)}`;
    await input.secretStore.store(JSON.stringify({ name: cookie.name, value: cookie.value }));
    const isSensitive = isSensitiveCookieName(cookie.name) || cookie.httpOnly;
    if (isSensitive) sensitiveCount += 1;
    references.push(reference);
    await input.repository.upsert({
      id: generateId('CKE'),
      engagementId: input.engagementId,
      contextId: input.contextId,
      identityId: input.identityId,
      name: cookie.name,
      domain: cookie.domain,
      path: cookie.path,
      secure: cookie.secure,
      httpOnly: cookie.httpOnly,
      sameSite: cookie.sameSite ?? null,
      expiration: cookie.expires > 0 ? new Date(cookie.expires * 1000).toISOString() : null,
      secretReference: reference,
    });
  }
  return { count: cookies.length, sensitiveCount, references };
}

export interface StorageCaptureResult {
  origins: number;
  entries: number;
  sensitiveCount: number;
}

/** In-page, read-only storage extraction (§24). Fixed platform script. */
const EXTRACT_STORAGE_SCRIPT = `(() => {
  const cap = (arr, n) => arr.slice(0, n);
  const out = [];
  try {
    for (let i = 0; i < localStorage.length; i += 1) {
      const key = localStorage.key(i);
      if (key) out.push({ area: 'LOCAL', key: key.slice(0, 512), value: String(localStorage.getItem(key) || '').slice(0, 8192) });
    }
  } catch (e) {}
  try {
    for (let i = 0; i < sessionStorage.length; i += 1) {
      const key = sessionStorage.key(i);
      if (key) out.push({ area: 'SESSION', key: key.slice(0, 512), value: String(sessionStorage.getItem(key) || '').slice(0, 8192) });
    }
  } catch (e) {}
  return cap(out, 512);
})()`;

export async function captureStorage(
  page: Page,
  input: {
    engagementId: string;
    contextId: string;
    identityId: string | null;
    repository: StorageRepositorySurface;
    secretStore: SecretStoreSurface;
  },
): Promise<StorageCaptureResult> {
  const entries = (await page.evaluate(EXTRACT_STORAGE_SCRIPT)) as Array<{
    area: 'LOCAL' | 'SESSION';
    key: string;
    value: string;
  }>;
  const origins = new Set<string>();
  let sensitiveCount = 0;
  const origin = new URL(page.url()).origin;

  for (const entry of entries.slice(0, 512)) {
    origins.add(origin);
    const sensitive = SENSITIVE_STORAGE_KEYS.some((p) => p.test(entry.key));
    let secretReference: string | null = null;
    let valueRedacted = entry.value.slice(0, 2048);
    if (sensitive) {
      sensitiveCount += 1;
      secretReference = await input.secretStore.store(JSON.stringify({ origin, key: entry.key, value: entry.value }));
      valueRedacted = '«redacted»';
    }
    await input.repository.upsert({
      id: generateId('STE'),
      engagementId: input.engagementId,
      contextId: input.contextId,
      identityId: input.identityId,
      origin,
      area: entry.area,
      key: entry.key,
      valueRedacted,
      isSensitive: sensitive,
      secretReference,
    });
  }
  return { origins: origins.size, entries: entries.length, sensitiveCount };
}

function isSensitiveCookieName(name: string): boolean {
  return SENSITIVE_STORAGE_KEYS.some((p) => p.test(name));
}
