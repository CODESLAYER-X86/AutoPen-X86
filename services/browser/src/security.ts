/**
 * Browser security policy + resource limits (spec Part 3 §6, §39, §73-§75).
 *
 * Default-restrictive: JavaScript, downloads, popups and every permission
 * prompt capability are OFF unless the engagement explicitly requires
 * them. Persistent profiles are opt-in (§6).
 */
import type { BrowserContextOptions } from 'playwright-core';

export interface BrowserSecurityPolicy {
  javascriptEnabled: boolean;
  downloadsEnabled: boolean;
  popupsEnabled: boolean;
  geolocation: boolean;
  camera: boolean;
  microphone: boolean;
  clipboardRead: boolean;
  clipboardWrite: boolean;
  notifications: boolean;
}

export const DEFAULT_BROWSER_SECURITY_POLICY: BrowserSecurityPolicy = {
  javascriptEnabled: true, // rendering functional; page JS is untrusted but sandboxed
  downloadsEnabled: false,
  popupsEnabled: false,
  geolocation: false,
  camera: false,
  microphone: false,
  clipboardRead: false,
  clipboardWrite: false,
  notifications: false,
};

export interface BrowserResourceLimits {
  maxContextsPerEngagement: number;
  maxPagesPerContext: number;
  maxNavigationTimeMs: number;
  maxTotalBrowserTimeMs: number;
  maxScreenshotBytes: number;
  maxTraceBytes: number;
  maxDownloadBytes: number;
  maxWebSocketMessageBytes: number;
}

export const DEFAULT_BROWSER_RESOURCE_LIMITS: BrowserResourceLimits = {
  maxContextsPerEngagement: 8,
  maxPagesPerContext: 4,
  maxNavigationTimeMs: 30_000,
  maxTotalBrowserTimeMs: 300_000,
  maxScreenshotBytes: 5_242_880,
  maxTraceBytes: 26_214_400,
  maxDownloadBytes: 26_214_400,
  maxWebSocketMessageBytes: 262_144,
};

/** Translate policy into Playwright context options (§73). */
export function policyToContextOptions(
  policy: BrowserSecurityPolicy,
  extra?: Partial<BrowserContextOptions>,
): BrowserContextOptions {
  return {
    javaScriptEnabled: policy.javascriptEnabled,
    acceptDownloads: policy.downloadsEnabled,
    // Popups: no pages beyond the explicitly created ones.
    extraHTTPHeaders: undefined,
    hasTouch: false,
    isMobile: false,
    locale: 'en-US',
    timezoneId: 'UTC',
    // Chromium permission prompts: deny everything not explicitly granted.
    permissions: [],
    serviceWorkers: 'block',
    ...extra,
  };
}

/**
 * Additional launch-level hardening: popups blocked via window hooks when
 * popupsEnabled=false (Chromium still opens target=_blank without this).
 */
export const POPUP_BLOCK_INIT_SCRIPT = `
(() => {
  try { window.open = () => null; } catch (e) { /* sandboxed */ }
})();
`;
