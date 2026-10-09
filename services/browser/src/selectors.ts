/**
 * Deterministic selector strategies (spec Part 3 §9).
 *
 * Workers describe elements SEMANTICALLY (role/text/label/placeholder/
 * test_id) and the browser service maps that description onto a Playwright
 * locator. Raw css/xpath remain available but are deliberately last-class.
 * Selector errors are normalized into structured failures.
 */
import type { Locator, Page } from 'playwright-core';
import { ValidationError } from '@aegis/shared';
import type { Selector } from '@aegis/contracts';

export class SelectorError extends ValidationError {
  constructor(message: string, code: string) {
    super(message, code);
    this.name = 'SelectorError';
  }
}

/** Map a semantic selector onto a Playwright locator. */
export function toLocator(page: Page, selector: Selector): Locator {
  switch (selector.strategy) {
    case 'role': {
      if (!selector.role) {
        throw new SelectorError("strategy 'role' requires a 'role' value (e.g. button, link)", 'SELECTOR_ROLE_MISSING');
      }
      const options: Record<string, unknown> = {};
      if (selector.name) options.name = selector.name;
      if (typeof options.name === 'string' && options.name.includes('/')) {
        // Treat /…/ as an accessible-name regex.
        const match = /^\/(.*)\/$/.exec(options.name as string);
        if (match) options.name = new RegExp(match[1]!);
      }
      return page.getByRole(selector.role as never, options as never);
    }
    case 'text': {
      return page.getByText(selector.value, { exact: selector.value.length < 32 });
    }
    case 'label': {
      return page.getByLabel(selector.value);
    }
    case 'placeholder': {
      return page.getByPlaceholder(selector.value);
    }
    case 'test_id': {
      return page.getByTestId(selector.value);
    }
    case 'css': {
      assertSafeCss(selector.value);
      return page.locator(selector.value);
    }
    case 'xpath': {
      assertSafeXpath(selector.value);
      return page.locator(`xpath=${selector.value}`);
    }
  }
}

/**
 * Block selector values that smuggle frame/pierce escapes or injection
 * payloads. CSS pseudo-classes that pierce the DOM boundary
 * (`:has-text` excepted — internal to Playwright and deterministic) are
 * limited to a conservative allowlist of structural pseudo-classes.
 */
const ALLOWED_CSS_PSEUDO = new Set([
  ':first-child',
  ':last-child',
  ':only-child',
  ':nth-child(',
  ':first-of-type',
  ':last-of-type',
  ':not(',
  ':has-text(',
  ':visible',
  ':checked',
  ':disabled',
  ':enabled',
  ':required',
]);

function assertSafeCss(value: string): void {
  if (value.length > 1024) {
    throw new SelectorError('CSS selector exceeds 1024 characters', 'SELECTOR_TOO_LONG');
  }
  // Reject frame piercing and internal engine escapes.
  if (/^(internal|iframe)[:]|\bframeLocator\b/i.test(value)) {
    throw new SelectorError('Frame-piercing selectors are not permitted', 'SELECTOR_FRAME_ESCAPE_FORBIDDEN');
  }
  const pseudos = value.match(/::?[a-zA-Z-]+(\(|$)/g) ?? [];
  for (const raw of pseudos) {
    const pseudo = raw.replace(/\($/, '').replace(/^::?/, ':');
    const normalized = pseudo.endsWith('(') ? pseudo : `${pseudo}(`;
    if (!ALLOWED_CSS_PSEUDO.has(normalized) && !ALLOWED_CSS_PSEUDO.has(pseudo)) {
      throw new SelectorError(
        `CSS pseudo-class '${pseudo}' is not in the deterministic allowlist`,
        'SELECTOR_PSEUDO_FORBIDDEN',
      );
    }
  }
}

function assertSafeXpath(value: string): void {
  if (value.length > 1024) {
    throw new SelectorError('XPath selector exceeds 1024 characters', 'SELECTOR_TOO_LONG');
  }
  if (!value.startsWith('/') && !value.startsWith('(')) {
    throw new SelectorError('XPath must be an absolute path expression (starting with / or (', 'SELECTOR_XPATH_INVALID');
  }
}

/** Human-readable rendering for logs (no raw page content). */
export function describeSelector(selector: Selector): string {
  const base = `${selector.strategy}:${selector.value}`;
  return selector.role ? `${base} (role=${selector.role}${selector.name ? `, name=${selector.name}` : ''})` : base;
}
