/**
 * DOM snapshot + change detection (spec Part 3 §31-§33).
 *
 * Snapshots are NORMALIZED STRUCTURE — element roles, texts, attributes,
 * forms, inputs, links, buttons, ARIA labels — never serialized HTML.
 * Reconnaissance data (§31) is stored as structured observations first;
 * interpretation belongs to the LLM later.
 *
 * The in-page extraction script is fixed platform code: it never uses
 * target-supplied scripts, and it caps every array to bound memory.
 */
import type { Page } from 'playwright-core';
import { ToolError } from '@aegis/shared';
import type { DomElement, DomSnapshot } from '@aegis/contracts';

/** Runs INSIDE the page; returns plain JSON only. */
const EXTRACT_SNAPSHOT_SCRIPT = `(() => {
  const cap = (arr, n) => arr.slice(0, n);
  const interesting = new Set(['a','button','input','select','textarea','form','iframe','script','img','link']);
  // Structurally relevant elements (§32): interesting tags OR any element
  // carrying identity/semantic attributes (id, role, data-testid, name).
  const isRelevant = (el) => interesting.has(el.tagName.toLowerCase())
    || el.id || el.getAttribute('role') || el.getAttribute('data-testid') || el.getAttribute('name');
  const elements = [];
  const links = [];
  const buttons = [];
  const iframes = [];
  const scripts = [];
  const stylesheets = [];
  const images = [];
  const all = document.querySelectorAll('*');
  for (const el of cap(Array.from(all), 8000)) {
    const tag = (el.tagName || '').toLowerCase();
    if (!tag) continue;
    if (isRelevant(el)) {
      const record = {
        tag,
        role: el.getAttribute('role') || null,
        text: (el.textContent || '').trim().slice(0, 512) || null,
        attributes: {},
        forms: [],
      };
      const keepAttrs = ['id','name','type','href','action','method','value','placeholder','aria-label','aria-labelledby','for','src','alt','data-testid'];
      for (const attr of keepAttrs) {
        const v = el.getAttribute(attr);
        if (v !== null && v !== '') record.attributes[attr] = v.slice(0, 256);
      }
      if (tag === 'a') links.push({ href: (el.getAttribute('href') || '').slice(0, 2048), text: record.text });
      if (tag === 'button') buttons.push({ text: record.text, aria: record.attributes['aria-label'] || null });
      if (tag === 'iframe') iframes.push({ src: (el.getAttribute('src') || '').slice(0, 2048) || null });
      if (tag === 'script' && el.src) scripts.push(el.src.slice(0, 2048));
      if (tag === 'img') images.push({ src: (el.getAttribute('src') || '').slice(0, 2048), alt: (el.getAttribute('alt') || '').slice(0, 512) || null });
      if (tag === 'form') {
        const inputs = cap(Array.from(el.querySelectorAll('input,select,textarea')).map(i => ({
          name: i.getAttribute('name'),
          type: i.getAttribute('type') || (i.tagName.toLowerCase() === 'select' ? 'select' : i.tagName.toLowerCase() === 'textarea' ? 'textarea' : null),
          required: i.hasAttribute('required'),
        })), 128);
        record.forms.push({ action: el.getAttribute('action'), method: el.getAttribute('method'), inputs });
      }
      if (Object.keys(record.attributes).length > 0 || record.role || record.text || tag === 'form') {
        elements.push(record);
      }
    }
  }
  for (const sheet of cap(Array.from(document.styleSheets), 64)) {
    try { if (sheet.href) stylesheets.push({ href: sheet.href.slice(0, 2048) }); } catch (e) {}
  }
  return {
    title: (document.title || '').slice(0, 1024) || null,
    elements: cap(elements, 2000),
    links: cap(links, 1000),
    buttons: cap(buttons, 500),
    iframes: cap(iframes, 128),
    scripts: cap(scripts, 500),
    stylesheets: cap(stylesheets, 256),
    images: cap(images, 1000),
  };
})()`;

export interface RawSnapshotData {
  title: string | null;
  elements: DomElement[];
  links: Array<{ href: string; text: string | null }>;
  buttons: Array<{ text: string | null; aria: string | null }>;
  iframes: Array<{ src: string | null }>;
  scripts: Array<{ url: string }>;
  stylesheets: Array<{ href: string }>;
  images: Array<{ src: string; alt: string | null }>;
}

export async function extractDomSnapshot(page: Page): Promise<RawSnapshotData> {
  const data = await page.evaluate(EXTRACT_SNAPSHOT_SCRIPT);
  if (!data || typeof data !== 'object') {
    throw new ToolError('DOM extraction returned no data', 'DOM_SNAPSHOT_FAILED');
  }
  return data as RawSnapshotData;
}

/**
 * JavaScript resource discovery (§34): script URLs + sizes. Fetching script
 * content is deferred (source worker, Part 4+); here we record references.
 */
export async function extractScriptInventory(page: Page): Promise<
  Array<{ url: string; content_type: string | null; size: number; hash: string | null }>
> {
  return page.evaluate(`(() => {
    const out = [];
    for (const script of Array.from(document.querySelectorAll('script[src]')).slice(0, 500)) {
      const perf = performance.getEntriesByName(script.src).find(e => e.entryType === 'resource');
      out.push({
        url: script.src.slice(0, 2048),
        content_type: (script.type || 'application/javascript').slice(0, 128),
        size: perf ? Math.round(perf.transferSize || perf.encodedBodySize || 0) : 0,
        hash: null,
      });
    }
    return out;
  })()`);
}

/** Compare two snapshots (§33): added/removed/changed elements. */
export function diffSnapshots(
  before: { elements: DomElement[]; links: Array<{ href: string; text: string | null }> },
  after: { elements: DomElement[]; links: Array<{ href: string; text: string | null }> },
  limits = { maxEntries: 500 },
): { added: string[]; removed: string[]; changed: Array<{ selector: string; before: string | null; after: string | null }> } {
  const describe = (el: DomElement): string => {
    const id = el.attributes.id ? `#${el.attributes.id}` : '';
    const name = el.attributes.name ? `[name=${el.attributes.name}]` : '';
    return `${el.tag}${id}${name}`.slice(0, 256);
  };

  const keyOf = (el: DomElement): string => `${el.tag}|${el.attributes.id ?? ''}|${el.attributes.name ?? ''}|${el.attributes['data-testid'] ?? ''}`;

  const beforeMap = new Map<string, DomElement>();
  for (const el of before.elements) beforeMap.set(keyOf(el), el);
  const afterMap = new Map<string, DomElement>();
  for (const el of after.elements) afterMap.set(keyOf(el), el);

  const added: string[] = [];
  const removed: string[] = [];
  const changed: Array<{ selector: string; before: string | null; after: string | null }> = [];

  for (const [key, el] of afterMap) {
    if (!beforeMap.has(key)) {
      if (added.length < limits.maxEntries) added.push(describe(el));
    } else {
      const prev = beforeMap.get(key)!;
      if (prev.text !== el.text && (added.length + changed.length) < limits.maxEntries) {
        changed.push({ selector: describe(el), before: prev.text?.slice(0, 512) ?? null, after: el.text?.slice(0, 512) ?? null });
      }
    }
  }
  for (const [key, el] of beforeMap) {
    if (!afterMap.has(key) && removed.length < limits.maxEntries) {
      removed.push(describe(el));
    }
  }

  const beforeLinks = new Set(before.links.map((l) => l.href));
  for (const link of after.links.slice(0, limits.maxEntries)) {
    if (!beforeLinks.has(link.href) && added.length < limits.maxEntries) {
      added.push(`a[href=${link.href.slice(0, 128)}]`);
    }
  }

  return { added, removed, changed };
}

/** Bound a snapshot for persistence (defensive caps). */
export function boundSnapshot(snapshot: DomSnapshot, caps: { elements: number; links: number }): DomSnapshot {
  return {
    ...snapshot,
    elements: snapshot.elements.slice(0, caps.elements),
    links: snapshot.links.slice(0, caps.links),
  };
}
