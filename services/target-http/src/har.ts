/**
 * HAR import (spec Part 3 §41, §80).
 *
 * Imports standard HTTP Archive entries as request records. Imported
 * traffic is UNTRUSTED: scope validation happens at import (skipping
 * out-of-scope entries with an explicit report) AND again at replay.
 * Burp remains an optional integration, not the architectural center.
 */
import type { ScopeRules } from '@aegis/security';
import type { HarImportInput, HttpBodyInput } from '@aegis/contracts';
import { ScopeChecker } from '@aegis/security';
import type { PlainHeader } from './normalize.js';

export interface HarImportEntryResult {
  url: string;
  method: string;
  status: number | null;
  imported: boolean;
  reason?: string;
}

export interface HarImportSummary {
  total: number;
  imported: number;
  skipped: number;
  entries: HarImportEntryResult[];
}

export interface HarParsedEntry {
  method: string;
  url: string;
  headers: PlainHeader[];
  body: HttpBodyInput | null;
  responseStatus: number | null;
  responseContentType: string | null;
  responseBodyText: string | null;
}

const MAX_HAR_BODY_CHARS = 1_048_576;

/**
 * Validate + parse HAR entries against the engagement scope. Returns the
 * parseable in-scope entries plus a per-entry report. Out-of-scope,
 * malformed and oversized entries are skipped explicitly — never silently.
 */
export function parseHarForScope(input: HarImportInput, scope: ScopeRules): { summary: HarImportSummary; entries: HarParsedEntry[] } {
  const checker = new ScopeChecker(scope);
  const results: HarImportEntryResult[] = [];
  const entries: HarParsedEntry[] = [];

  for (const raw of input.har.log.entries) {
    const method = raw.request.method.toUpperCase();
    const url = raw.request.url;
    const status = raw.response?.status ?? null;

    if (!/^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)$/.test(method)) {
      results.push({ url: safeUrl(url), method, status, imported: false, reason: 'unsupported method' });
      continue;
    }

    let parsedUrl: URL;
    try {
      parsedUrl = new URL(url);
    } catch {
      results.push({ url: '(unparseable)', method, status, imported: false, reason: 'malformed URL' });
      continue;
    }

    const scopeResult = checker.checkUrl(parsedUrl.toString());
    if (!scopeResult.allowed) {
      results.push({
        url: safeUrl(url),
        method,
        status,
        imported: false,
        reason: `out of scope: ${scopeResult.reason}`,
      });
      continue;
    }

    const headers: PlainHeader[] = (raw.request.headers ?? []).slice(0, 64).map((h) => ({
      name: h.name.slice(0, 128),
      value: h.value.slice(0, 8192),
    }));

    let body: HttpBodyInput | null = null;
    const postText = raw.request.postData?.text;
    if (typeof postText === 'string' && postText.length > 0 && postText.length <= MAX_HAR_BODY_CHARS) {
      const mimeType = raw.request.postData?.mimeType ?? '';
      if (mimeType.includes('application/json')) {
        try {
          body = { body_type: 'JSON', data: JSON.parse(postText) as unknown };
        } catch {
          body = { body_type: 'TEXT', text: postText };
        }
      } else if (mimeType.includes('application/x-www-form-urlencoded')) {
        const fields: Array<{ name: string; value: string }> = [];
        for (const pair of postText.split('&')) {
          const eq = pair.indexOf('=');
          if (eq === -1) {
            if (pair) fields.push({ name: decodeMaybe(pair), value: '' });
          } else {
            fields.push({ name: decodeMaybe(pair.slice(0, eq)), value: decodeMaybe(pair.slice(eq + 1)) });
          }
        }
        body = { body_type: 'FORM_URLENCODED', fields };
      } else {
        body = { body_type: 'TEXT', text: postText };
      }
    } else if (typeof postText === 'string' && postText.length > MAX_HAR_BODY_CHARS) {
      results.push({ url: safeUrl(url), method, status, imported: false, reason: 'body exceeds import size limit' });
      continue;
    }

    entries.push({
      method,
      url: parsedUrl.toString(),
      headers,
      body,
      responseStatus: status,
      responseContentType: raw.response?.content?.mimeType ?? null,
      responseBodyText:
        typeof raw.response?.content?.text === 'string' && raw.response.content.text.length <= MAX_HAR_BODY_CHARS
          ? raw.response.content.text
          : null,
    });
    results.push({ url: safeUrl(url), method, status, imported: true });
  }

  return {
    summary: {
      total: input.har.log.entries.length,
      imported: entries.length,
      skipped: results.length - entries.length,
      entries: results,
    },
    entries,
  };
}

function safeUrl(url: string): string {
  try {
    const parsed = new URL(url);
    return `${parsed.protocol}//${parsed.host}${parsed.pathname}`;
  } catch {
    return '(unparseable URL)';
  }
}

function decodeMaybe(value: string): string {
  try {
    return decodeURIComponent(value);
  } catch {
    return value;
  }
}
