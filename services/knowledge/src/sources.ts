/**
 * Curated source catalog (spec Part 5 §4-§5, §28, §80).
 *
 * High-value INITIAL sources (§4) — the catalog is CONFIGURATION, not a
 * crawler: every entry carries a trust level, license notes and a bounded
 * crawl policy. The platform must not be hard-coded around any single
 * website (§4), so entries are data, and operators add/remove sources
 * through the registry.
 */
import type { KnowledgeSourceRecord } from '@aegis/database';
import type { KnowledgeTrustLevel } from '@aegis/shared';

export interface CatalogEntry {
  name: string;
  type: KnowledgeSourceRecord['type'];
  baseUrl: string;
  trustLevel: KnowledgeTrustLevel;
  updateStrategy: KnowledgeSourceRecord['update_strategy'];
  licenseNotes: string;
  crawlPolicy: { allowed_domains: string[]; entry_paths: string[] };
}

/**
 * Initial catalog (§4): official security guides, training material,
 * standards, technical documentation, research and CTF write-up sources.
 * entry_paths stay EMPTY by default: curators configure what to sync —
 * the system is curated and bounded, never an open crawler (§28).
 */
export const CURATED_SOURCE_CATALOG: CatalogEntry[] = [
  {
    name: 'OWASP Web Security Testing Guide',
    type: 'OFFICIAL_SECURITY',
    baseUrl: 'https://owasp.org/www-project-web-security-testing-guide/',
    trustLevel: 'OFFICIAL',
    updateStrategy: 'SCHEDULED',
    licenseNotes: 'CC BY-SA 4.0 — attribute OWASP WSTG when quoting',
    crawlPolicy: { allowed_domains: ['owasp.org'], entry_paths: [] },
  },
  {
    name: 'OWASP Application Security Verification Standard',
    type: 'STANDARDS',
    baseUrl: 'https://owasp.org/www-project-application-security-verification-standard/',
    trustLevel: 'OFFICIAL',
    updateStrategy: 'SCHEDULED',
    licenseNotes: 'CC BY-SA 4.0 — attribute OWASP ASVS',
    crawlPolicy: { allowed_domains: ['owasp.org'], entry_paths: [] },
  },
  {
    name: 'OWASP API Security Top 10',
    type: 'OFFICIAL_SECURITY',
    baseUrl: 'https://owasp.org/API-Security/',
    trustLevel: 'OFFICIAL',
    updateStrategy: 'SCHEDULED',
    licenseNotes: 'CC BY-SA 4.0 — attribute OWASP API Security Project',
    crawlPolicy: { allowed_domains: ['owasp.org'], entry_paths: [] },
  },
  {
    name: 'PortSwigger Web Security Academy',
    type: 'SECURITY_TRAINING',
    baseUrl: 'https://portswigger.net/web-security',
    trustLevel: 'TRUSTED_TRAINING',
    updateStrategy: 'INCREMENTAL',
    licenseNotes: 'Free training material; quote with attribution, respect ToS',
    crawlPolicy: { allowed_domains: ['portswigger.net'], entry_paths: [] },
  },
  {
    name: 'MDN Web Docs',
    type: 'TECHNICAL_DOCUMENTATION',
    baseUrl: 'https://developer.mozilla.org/',
    trustLevel: 'OFFICIAL',
    updateStrategy: 'SCHEDULED',
    licenseNotes: 'CC BY-SA 2.5+ — attribute MDN contributors',
    crawlPolicy: { allowed_domains: ['developer.mozilla.org'], entry_paths: [] },
  },
  {
    name: 'RFC Editor (HTTP standards)',
    type: 'STANDARDS',
    baseUrl: 'https://www.rfc-editor.org/',
    trustLevel: 'OFFICIAL',
    updateStrategy: 'ON_DEMAND',
    licenseNotes: 'RFCs are freely distributable with attribution',
    crawlPolicy: { allowed_domains: ['rfc-editor.org', 'ietf.org'], entry_paths: [] },
  },
  {
    name: 'CWE — Common Weakness Enumeration (MITRE)',
    type: 'STANDARDS',
    baseUrl: 'https://cwe.mitre.org/',
    trustLevel: 'OFFICIAL',
    updateStrategy: 'SCHEDULED',
    licenseNotes: 'CWE is a MITRE research project; terms apply',
    crawlPolicy: { allowed_domains: ['cwe.mitre.org'], entry_paths: [] },
  },
  {
    name: 'CTF write-ups (curated feed)',
    type: 'CTF_WRITEUPS',
    baseUrl: 'https://ctftime.org/',
    trustLevel: 'CTF',
    updateStrategy: 'INCREMENTAL',
    licenseNotes: 'Write-ups are third-party content; individual licenses vary',
    crawlPolicy: { allowed_domains: ['ctftime.org'], entry_paths: [] },
  },
];
