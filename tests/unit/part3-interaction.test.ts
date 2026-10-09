/**
 * Part 3 unit tests — normalization (§18), redaction (§66), body
 * serialization (§67-§68), mutation engine (§20-§22, §69-§72), URL policy
 * (§49-§52), rate limiting (§53), selectors (§9), DOM diff (§33).
 */
import { describe, expect, it } from 'vitest';
import {
  canonicalizeJson,
  classifyContent,
  fingerprintNormalized,
  isSensitiveHeader,
  isSensitiveFieldName,
  normalizeHeaders,
  normalizeUrlForComparison,
  parseQuery,
  redactHeaders,
  redactParsedBody,
  redactFormFields,
} from '@aegis/target-http';
import { serializeBody } from '@aegis/target-http';
import { applyMutations } from '@aegis/target-http';
import { classifyIp } from '@aegis/target-http';
import { SlidingWindowRateLimiter, Semaphore } from '@aegis/target-http';
import { validateAndNormalizeUrl, validateRedirectTarget } from '@aegis/target-http';
import { diffSnapshots } from '../../services/browser/src/dom.js';
import { toLocator, describeSelector, SelectorError } from '../../services/browser/src/selectors.js';
import { parseHarForScope } from '@aegis/target-http';
import { DEFAULT_NETWORK_POLICY, LAB_NETWORK_POLICY } from '@aegis/target-http';
import type { ScopeRules } from '@aegis/security';

const LAB_SCOPE: ScopeRules = {
  allowed_hosts: ['127.0.0.1'],
  allowed_domains: [],
  allowed_ports: [8080, 9999],
  allowed_schemes: ['http', 'https'],
  excluded_hosts: [],
  excluded_paths: [],
  rate_limit: null,
  concurrency_limit: null,
  destructive_actions_allowed: false,
};

// -- §18 normalization ------------------------------------------------------

describe('HTTP normalization (§18)', () => {
  it('sorts headers case-insensitively and trims values', () => {
    const normalized = normalizeHeaders([
      { name: 'B', value: ' 2 ' },
      { name: 'a', value: '1' },
    ]);
    expect(normalized).toEqual([
      { name: 'a', value: '1' },
      { name: 'b', value: '2' },
    ]);
  });

  it('parses query parameters preserving duplicates and empty values', () => {
    const query = parseQuery('http://x.test/p?a=1&b=&a=2');
    expect(query).toEqual([
      { name: 'a', value: '1' },
      { name: 'a', value: '2' },
      { name: 'b', value: '' },
    ]);
  });

  it('canonicalizes JSON with recursively sorted keys', () => {
    expect(canonicalizeJson({ b: 2, a: { d: [3, { z: 1, y: 2 }], c: true } })).toBe(
      JSON.stringify({ a: { c: true, d: [3, { y: 2, z: 1 }] }, b: 2 }),
    );
  });

  it('strips default ports and normalizes the host for comparison', () => {
    expect(normalizeUrlForComparison('http://Example.COM:80/a?b=2&a=1')).toBe(
      'http://example.com/a?a=1&b=2',
    );
    expect(normalizeUrlForComparison('https://x.test:443/a')).toBe('https://x.test/a');
  });

  it('fingerprints normalized parts deterministically (order-insensitive)', () => {
    const a = {
      method: 'GET',
      url: 'http://x.test/a?b=2&a=1',
      headers: [
        { name: 'accept', value: 'application/json' },
        { name: 'x-b', value: '1' },
      ],
      bodyCanonical: null as string | null,
    };
    const b = {
      method: 'GET',
      url: 'http://x.test/a?a=1&b=2',
      headers: [
        { name: 'x-b', value: '1' },
        { name: 'Accept', value: 'application/json' },
      ],
      bodyCanonical: null as string | null,
    };
    const fa = fingerprintNormalized({
      method: a.method,
      url: normalizeUrlForComparison(a.url),
      headers: normalizeHeaders(a.headers),
      query: parseQuery(a.url),
      bodyCanonical: null,
    });
    const fb = fingerprintNormalized({
      method: b.method,
      url: normalizeUrlForComparison(b.url),
      headers: normalizeHeaders(b.headers),
      query: parseQuery(b.url),
      bodyCanonical: null,
    });
    expect(fa).toBe(fb);
  });

  it('classifies response content kinds (§17)', () => {
    expect(classifyContent('application/json')).toBe('JSON');
    expect(classifyContent('application/vnd.api+json')).toBe('JSON');
    expect(classifyContent('text/html; charset=utf-8')).toBe('HTML');
    expect(classifyContent('application/soap+xml')).toBe('XML');
    expect(classifyContent('text/plain')).toBe('TEXT');
    expect(classifyContent('image/png')).toBe('IMAGE');
    expect(classifyContent('application/pdf')).toBe('FILE');
    expect(classifyContent('application/octet-stream')).toBe('FILE');
    expect(classifyContent('')).toBe('UNKNOWN');
  });
});

// -- §66 redaction ------------------------------------------------------------

describe('Sensitive data redaction (§66)', () => {
  it('marks and redacts sensitive headers', () => {
    expect(isSensitiveHeader('Authorization')).toBe(true);
    expect(isSensitiveHeader('set-cookie')).toBe(true);
    expect(isSensitiveHeader('x-api-key')).toBe(true);
    expect(isSensitiveHeader('content-type')).toBe(false);
    const redacted = redactHeaders([
      { name: 'authorization', value: 'Bearer sekret' },
      { name: 'x-custom', value: 'ok' },
    ]);
    expect(redacted[0]?.value).toBe('«redacted»');
    expect(redacted[1]?.value).toBe('ok');
  });

  it('redacts sensitive JSON body fields recursively', () => {
    const redacted = redactParsedBody({
      password: 'hunter2',
      nested: { access_token: 'abc', note: 'visible' },
      items: [{ api_key: 'k', name: 'n' }],
    }) as Record<string, unknown>;
    expect(redacted.password).toBe('«redacted»');
    const nested = redacted.nested as Record<string, unknown>;
    expect(nested.access_token).toBe('«redacted»');
    expect(nested.note).toBe('visible');
    const items = redacted.items as Array<Record<string, unknown>>;
    expect(items[0]?.api_key).toBe('«redacted»');
    expect(items[0]?.name).toBe('n');
  });

  it('redacts sensitive form field values', () => {
    const redacted = redactFormFields([
      { name: 'password', value: 'x' },
      { name: 'comment', value: 'hi' },
    ]);
    expect(redacted[0]?.value).toBe('«redacted»');
    expect(redacted[1]?.value).toBe('hi');
  });

  it('flags sensitive field names', () => {
    expect(isSensitiveFieldName('password')).toBe(true);
    expect(isSensitiveFieldName('refresh_token')).toBe(true);
    expect(isSensitiveFieldName('sessionid')).toBe(true); // matches /session/i — sensitive by design
    expect(isSensitiveFieldName('session_id')).toBe(true);
    expect(isSensitiveFieldName('username')).toBe(false);
  });
});

// -- §67-§68 body serialization ------------------------------------------------

describe('Body serialization (§67-§68)', () => {
  it('serializes JSON with a stable content type', () => {
    const result = serializeBody({ body_type: 'JSON', data: { a: 1 } });
    expect(result.contentType).toBe('application/json');
    expect(Buffer.from(result.bytes).toString('utf8')).toBe('{"a":1}');
    expect(result.byteLength).toBe(7);
  });

  it('serializes form-urlencoded fields', () => {
    const result = serializeBody({
      body_type: 'FORM_URLENCODED',
      fields: [
        { name: 'a b', value: '1&2' },
        { name: 'c', value: 'x' },
      ],
    });
    expect(result.contentType).toBe('application/x-www-form-urlencoded');
    expect(Buffer.from(result.bytes).toString('utf8')).toBe('a%20b=1%262&c=x');
  });

  it('serializes multipart deterministically with engine-owned boundaries', () => {
    const input = {
      body_type: 'MULTIPART' as const,
      fields: [{ name: 'field1', value: 'value1' }],
      files: [{ name: 'file1', filename: 'a.bin', content_b64: Buffer.from('binary-content').toString('base64') }],
    };
    const a = serializeBody(input);
    const b = serializeBody({ ...input });
    expect(a.bytes).toEqual(b.bytes);
    expect(a.contentType).toContain('multipart/form-data; boundary=');
    const text = Buffer.from(a.bytes).toString('utf8');
    expect(text).toContain('Content-Disposition: form-data; name="field1"');
    expect(text).toContain('filename="a.bin"');
  });

  it('round-trips binary bodies', () => {
    const bytes = Buffer.from([0, 1, 2, 255, 254]);
    const result = serializeBody({ body_type: 'BINARY', content_b64: bytes.toString('base64') });
    expect(Buffer.from(result.bytes).toString('base64')).toBe(bytes.toString('base64'));
    expect(result.contentType).toBe('application/octet-stream');
  });

  it('produces an empty body for EMPTY', () => {
    const result = serializeBody({ body_type: 'EMPTY' });
    expect(result.byteLength).toBe(0);
    expect(result.contentType).toBeNull();
  });
});

// -- §20-§22, §69-§72 mutations ----------------------------------------------------

describe('Mutation engine (§20-§22, §69-§72)', () => {
  const base = {
    method: 'GET',
    url: 'http://x.test/api/orders?user_id=381&verbose=1',
    headers: [
      { name: 'accept', value: 'application/json' },
      { name: 'authorization', value: 'Bearer old' },
    ],
    body: null,
  } as Parameters<typeof applyMutations>[0];

  it('adds, replaces, removes and duplicates query parameters (§70)', () => {
    const { request } = applyMutations(base, [
      { location: 'query', name: 'extra', operation: 'add', value: '42' },
      { location: 'query', name: 'user_id', operation: 'replace', value: '382' },
    ]);
    const url = new URL(request.url);
    expect(url.searchParams.get('user_id')).toBe('382');
    expect(url.searchParams.get('extra')).toBe('42');
    expect(url.searchParams.get('verbose')).toBe('1');

    const removed = applyMutations(request, [{ location: 'query', name: 'verbose', operation: 'remove' }]);
    expect(new URL(removed.request.url).searchParams.get('verbose')).toBeNull();

    const duplicated = applyMutations(base, [{ location: 'query', name: 'user_id', operation: 'duplicate' }]);
    expect(new URL(duplicated.request.url).searchParams.getAll('user_id')).toEqual(['381', '381']);
  });

  it('replaces JSON fields by path, never by string replacement (§69)', () => {
    const jsonBase = {
      ...base,
      method: 'POST',
      url: 'http://x.test/api/orders',
      body: { body_type: 'JSON' as const, data: { user: { id: 381, role: 'user' }, action: 'update' } },
    };
    const { request } = applyMutations(jsonBase, [
      { location: 'body_json', path: 'user.id', operation: 'replace', value: 999 },
      { location: 'body_json', path: 'user.role', operation: 'replace', value: 'admin' },
    ]);
    const data = (request.body as { data: Record<string, unknown> }).data as Record<string, unknown>;
    const user = data.user as Record<string, unknown>;
    expect(user.id).toBe(999);
    expect(user.role).toBe('admin');
    expect(data.action).toBe('update');
  });

  it('fails closed on missing mutation targets (§22 determinism)', () => {
    expect(() =>
      applyMutations(base, [{ location: 'query', name: 'nope', operation: 'replace', value: '1' }]),
    ).toThrowError();
    expect(() =>
      applyMutations(base, [{ location: 'body_json', path: 'user.id', operation: 'replace', value: 1 }]),
    ).toThrowError();
    expect(() =>
      applyMutations({ ...base, method: 'GET' }, [{ location: 'method', operation: 'replace', value: 'TRACE' }]),
    ).toThrowError();
  });

  it('mutates headers, cookies and method (§71-§72)', () => {
    const { request } = applyMutations(base, [
      { location: 'header', name: 'x-custom', operation: 'add', value: 'yes' },
      { location: 'header', name: 'authorization', operation: 'remove' },
      { location: 'method', operation: 'replace', value: 'post' },
    ]);
    expect(request.method).toBe('POST');
    expect(request.headers).toEqual([{ name: 'accept', value: 'application/json' }, { name: 'x-custom', value: 'yes' }]);

    const cookie = applyMutations(base, [{ location: 'cookie', name: 'SESSION', operation: 'add', value: 'tok' }]);
    expect(cookie.request.headers).toContainEqual({ name: 'cookie', value: 'SESSION=tok' });
  });

  it('mutates path segments (change_path_segment §20)', () => {
    const { request } = applyMutations(base, [{ location: 'path', name: 'orders', operation: 'replace', value: 'users' }]);
    expect(new URL(request.url).pathname).toBe('/api/users');
  });

  it('mutates form fields (change_form_field §20)', () => {
    const formBase = {
      ...base,
      method: 'POST',
      body: { body_type: 'FORM_URLENCODED' as const, fields: [{ name: 'a', value: '1' }] },
    };
    const { request } = applyMutations(formBase, [
      { location: 'body_form', name: 'b', operation: 'add', value: '2' },
      { location: 'body_form', name: 'a', operation: 'replace', value: '9' },
    ]);
    expect((request.body as { fields: Array<{ name: string; value: string }> }).fields).toEqual([
      { name: 'a', value: '9' },
      { name: 'b', value: '2' },
    ]);
  });

  it('never modifies the original request object (§21 immutability)', () => {
    const snapshot = JSON.stringify(base);
    applyMutations(base, [
      { location: 'query', name: 'q', operation: 'add', value: '1' },
      { location: 'header', name: 'h', operation: 'add', value: '2' },
    ]);
    expect(JSON.stringify(base)).toBe(snapshot);
  });
});

// -- §49-§52 URL policy / SSRF --------------------------------------------------

describe('URL policy + SSRF defence (§49-§52)', () => {
  it('classifies IP addresses correctly', () => {
    expect(classifyIp('127.0.0.1')).toBe('LOOPBACK');
    expect(classifyIp('127.8.8.8')).toBe('LOOPBACK');
    expect(classifyIp('10.1.2.3')).toBe('PRIVATE');
    expect(classifyIp('192.168.0.1')).toBe('PRIVATE');
    expect(classifyIp('172.16.5.5')).toBe('PRIVATE');
    expect(classifyIp('169.254.1.1')).toBe('LINK_LOCAL');
    expect(classifyIp('0.0.0.0')).toBe('UNSPECIFIED');
    expect(classifyIp('8.8.8.8')).toBe('PUBLIC');
    expect(classifyIp('::1')).toBe('LOOPBACK');
    expect(classifyIp('::ffff:10.0.0.1')).toBe('PRIVATE');
  });

  it('rejects URLs out of engagement scope', async () => {
    await expect(
      validateAndNormalizeUrl('http://other.example.com/x', LAB_SCOPE, LAB_NETWORK_POLICY),
    ).rejects.toThrowError(/scope/i);
  });

  it('rejects non-allowed schemes and embedded credentials', async () => {
    await expect(
      validateAndNormalizeUrl('ftp://127.0.0.1/x', LAB_SCOPE, LAB_NETWORK_POLICY),
    ).rejects.toThrowError(/scheme/i);
    await expect(
      validateAndNormalizeUrl('http://user:pass@127.0.0.1/x', LAB_SCOPE, LAB_NETWORK_POLICY),
    ).rejects.toThrowError(/credentials/i);
  });

  it('rejects loopback under the restrictive production policy even when in scope', async () => {
    const loopbackScope: ScopeRules = { ...LAB_SCOPE, allowed_hosts: ['127.0.0.1'] };
    await expect(
      validateAndNormalizeUrl('http://127.0.0.1:8080/x', loopbackScope, DEFAULT_NETWORK_POLICY),
    ).rejects.toThrowError(/loopback/i);
  });

  it('allows loopback under the lab policy', async () => {
    const normalized = await validateAndNormalizeUrl('http://127.0.0.1:8080/x', LAB_SCOPE, LAB_NETWORK_POLICY);
    expect(normalized.host).toBe('127.0.0.1');
    expect(normalized.port).toBe(8080);
  });

  it('re-validates redirect targets per hop (§51)', async () => {
    await expect(
      validateRedirectTarget('http://evil.example.com/x', 'http://127.0.0.1/y', LAB_SCOPE, LAB_NETWORK_POLICY),
    ).rejects.toThrowError(/scope/i);
    const ok = await validateRedirectTarget('/login', 'http://127.0.0.1:8080/x', LAB_SCOPE, LAB_NETWORK_POLICY);
    expect(ok.href).toBe('http://127.0.0.1:8080/login');
  });

  it('rejects malformed and oversized URLs', async () => {
    await expect(validateAndNormalizeUrl('not-a-url', LAB_SCOPE, LAB_NETWORK_POLICY)).rejects.toThrowError();
    await expect(
      validateAndNormalizeUrl(`http://127.0.0.1/${'a'.repeat(2100)}`, LAB_SCOPE, LAB_NETWORK_POLICY),
    ).rejects.toThrowError(/2048/);
  });
});

// -- §53 rate limiting -----------------------------------------------------------

describe('Rate + concurrency control (§53-§54)', () => {
  it('blocks requests beyond the sliding window', () => {
    const limiter = new SlidingWindowRateLimiter({ perEngagement: 3, perHost: 2, windowMs: 60_000 });
    const engage = (host: string): void => {
      limiter.check('ENG_TEST', host);
      limiter.consume('ENG_TEST', host);
    };
    engage('a.test');
    engage('a.test');
    expect(() => engage('a.test')).toThrowError(/host/);
  });

  it('semaphores bound concurrency', async () => {
    const semaphore = new Semaphore(2);
    await semaphore.acquire();
    await semaphore.acquire();
    let second = false;
    const pending = semaphore.acquire().then(() => {
      second = true;
    });
    await new Promise((resolve) => setTimeout(resolve, 10));
    expect(second).toBe(false);
    semaphore.release();
    await pending;
    expect(second).toBe(true);
  });
});

// -- §9 selectors ------------------------------------------------------------------

describe('Selector strategies (§9)', () => {
  const fakePage = {
    getByRole: () => 'role',
    getByText: () => 'text',
    locator: () => 'locator',
  } as never as import('playwright-core').Page;

  it('rejects role selectors without a role', () => {
    expect(() => toLocator(fakePage, { strategy: 'role', value: 'x' })).toThrowError(SelectorError);
  });

  it('maps semantic strategies onto Playwright locators', () => {
    expect(toLocator(fakePage, { strategy: 'text', value: 'Login' })).toBe('text');
    expect(toLocator(fakePage, { strategy: 'role', value: 'ignored', role: 'button', name: 'Login' })).toBe('role');
  });

  it('blocks frame-piercing and unlisted CSS pseudo-classes', () => {
    expect(() => toLocator(fakePage, { strategy: 'css', value: 'internal:role=button' })).toThrowError(/frame/i);
    expect(() => toLocator(fakePage, { strategy: 'css', value: 'a:has(a)' })).toThrowError(/pseudo/i);
    expect(toLocator(fakePage, { strategy: 'css', value: 'div#main > a:first-child' })).toBeDefined();
  });

  it('describes selectors for logs', () => {
    expect(describeSelector({ strategy: 'role', value: 'b', role: 'button', name: 'Go' })).toContain('role=button');
  });
});

// -- §33 DOM diff ---------------------------------------------------------------------

describe('DOM diff (§33)', () => {
  it('detects added, removed and changed elements', () => {
    const before = {
      elements: [
        { tag: 'button', role: null, text: 'Submit', attributes: { id: 'btn' } as Record<string, string>, forms: [] },
        { tag: 'a', role: null, text: 'Link', attributes: { id: 'lnk' } as Record<string, string>, forms: [] },
      ],
      links: [{ href: '/a', text: null }],
    };
    const after = {
      elements: [
        { tag: 'button', role: null, text: 'Submit (changed)', attributes: { id: 'btn' } as Record<string, string>, forms: [] },
        { tag: 'input', role: null, text: null, attributes: { name: 'email' } as Record<string, string>, forms: [] },
      ],
      links: [{ href: '/a', text: null }, { href: '/b', text: null }],
    };
    const diff = diffSnapshots(before, after);
    expect(diff.removed).toContain('a#lnk');
    expect(diff.changed).toHaveLength(1);
    expect(diff.changed[0]?.before).toBe('Submit');
    expect(diff.changed[0]?.after).toBe('Submit (changed)');
    expect(diff.added.some((entry) => entry.includes('email'))).toBe(true);
    expect(diff.added.some((entry) => entry.includes('/b'))).toBe(true);
  });
});

// -- §80 HAR import ----------------------------------------------------------------------

describe('HAR import (§80)', () => {
  it('imports in-scope entries and skips out-of-scope entries with reasons', () => {
    const har = {
      har: {
        log: {
          entries: [
            {
              request: { method: 'GET', url: 'http://127.0.0.1:9999/a', headers: [{ name: 'x-a', value: '1' }] },
              response: { status: 200, content: { text: 'ok', mimeType: 'text/plain' } },
            },
            {
              request: { method: 'GET', url: 'http://other.example.com/b' },
              response: { status: 200 },
            },
            {
              request: { method: 'TRACE', url: 'http://127.0.0.1:9999/c' },
            },
          ],
        },
      },
    };
    const { summary, entries } = parseHarForScope(har, LAB_SCOPE);
    expect(summary.total).toBe(3);
    expect(summary.imported).toBe(1);
    expect(summary.skipped).toBe(2);
    expect(entries).toHaveLength(1);
    expect(entries[0]?.url).toContain('/a');
    const skippedReasons = summary.entries.filter((e) => !e.imported).map((e) => e.reason);
    expect(skippedReasons.some((r) => r?.includes('scope'))).toBe(true);
    expect(skippedReasons.some((r) => r?.includes('method'))).toBe(true);
  });

  it('parses JSON post data from HAR entries', () => {
    const har = {
      har: {
        log: {
          entries: [
            {
              request: {
                method: 'POST',
                url: 'http://127.0.0.1:9999/api',
                postData: { text: '{"a":1}', mimeType: 'application/json' },
              },
            },
          ],
        },
      },
    };
    const { entries } = parseHarForScope(har, LAB_SCOPE);
    expect(entries[0]?.body).toEqual({ body_type: 'JSON', data: { a: 1 } });
  });
});
