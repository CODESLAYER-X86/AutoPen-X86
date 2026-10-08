/**
 * Browser automation interface (spec §3 — Browser Worker).
 *
 * Part 1 defines the contract only. The Playwright-backed implementation
 * arrives in Part 4 and will be scope-gated per navigation.
 */
import { NotImplementedError } from '@aegis/shared';

export interface BrowserPageRef {
  page_id: string;
}

export interface BrowserSnapshot {
  url: string;
  dom: string;
  screenshot_reference: string;
}

export interface BrowserAutomation {
  navigate(url: string): Promise<BrowserPageRef>;
  click(pageId: string, selector: string): Promise<void>;
  fill(pageId: string, selector: string, value: string): Promise<void>;
  submit(pageId: string, selector: string): Promise<void>;
  snapshot(pageId: string): Promise<BrowserSnapshot>;
  close(pageId: string): Promise<void>;
}

export function createNotImplementedBrowserAutomation(): BrowserAutomation {
  const notImplemented = async (): Promise<never> => {
    throw new NotImplementedError(
      'The browser worker is not implemented in Part 1; it is the subject of Part 4',
      'BROWSER_WORKER_NOT_IMPLEMENTED',
    );
  };
  return {
    navigate: notImplemented,
    click: notImplemented,
    fill: notImplemented,
    submit: notImplemented,
    snapshot: notImplemented,
    close: notImplemented,
  };
}
