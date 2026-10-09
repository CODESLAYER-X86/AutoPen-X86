/**
 * Deterministic value analysis (spec §16-§17, §19).
 *
 * Deterministic parsers run BEFORE any LLM is asked (§83): value
 * characteristics, name-based semantic candidates and object-name patterns.
 * Semantic classifications are CANDIDATES, never trusted blindly (§16).
 */
import type { ParameterSemantic, ValueCharacteristic } from '@aegis/shared';
import type { SemanticCandidateRecord } from '@aegis/database';

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;
const URL_RE = /^https?:\/\/[^\s]+$/i;
const JWT_RE = /^ey[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]*$/;
const BASE64_RE = /^(?:[A-Za-z0-9+/]{16,}={0,2}|[A-Za-z0-9_-]{16,})$/;
const HEX_RE = /^[0-9a-f]{8,}$/i;
const NUMERIC_RE = /^-?\d+(?:\.\d+)?$/;
const ALNUM_MIXED_RE = /^(?=.*\d)[A-Za-z0-9_-]{8,64}$/;

const SENSITIVE_NAME_RE =
  /pass(word)?|pwd|secret|token|api[-_]?key|auth(orization)?|session|cookie|csrf|ssn|credit|card|cvv|private/i;

/** Detect deterministic value characteristics (spec §17). */
export function analyzeValue(raw: unknown): { characteristics: ValueCharacteristic[]; text: string | null } {
  if (raw === null || raw === undefined) return { characteristics: [], text: null };
  const text = typeof raw === 'string' ? raw : String(raw);
  if (text.length === 0 || text.length > 4096) return { characteristics: [], text: null };
  const characteristics: ValueCharacteristic[] = [];

  if (NUMERIC_RE.test(text)) characteristics.push('NUMERIC');
  if (UUID_RE.test(text)) characteristics.push('UUID');
  if (EMAIL_RE.test(text)) characteristics.push('EMAIL');
  if (URL_RE.test(text)) characteristics.push('URL');
  if (JWT_RE.test(text)) characteristics.push('JWT_LIKE');
  if (characteristics.includes('JWT_LIKE') || (!characteristics.includes('UUID') && BASE64_RE.test(text) && !HEX_RE.test(text))) {
    characteristics.push('BASE64_LIKE');
  }
  if (HEX_RE.test(text) && !NUMERIC_RE.test(text)) characteristics.push('HEXADECIMAL');
  if (looksLikeTimestamp(text)) characteristics.push('TIMESTAMP');
  if ((text.startsWith('{') || text.startsWith('[')) && isJson(text)) characteristics.push('JSON');
  if (
    characteristics.length === 0 &&
    text.length >= 16 &&
    ALNUM_MIXED_RE.test(text)
  ) {
    characteristics.push('OPAQUE_TOKEN');
  }
  if (characteristics.length === 0 && /^[A-Za-z0-9._-]{1,64}$/.test(text)) {
    characteristics.push('IDENTIFIER');
  }
  return { characteristics, text };
}

function looksLikeTimestamp(text: string): boolean {
  if (!/^\d{10}$|^\d{13}$/.test(text)) return false;
  const value = Number(text);
  const seconds = text.length === 13 ? Math.floor(value / 1000) : value;
  // Plausible range: 2001..2100 (spec §17 timestamp characteristic).
  return seconds > 1_000_000_000 && seconds < 4_102_444_800;
}

function isJson(text: string): boolean {
  try {
    JSON.parse(text);
    return true;
  } catch {
    return false;
  }
}

/**
 * Name-based semantic classification (spec §16). These are CANDIDATES with
 * explicit confidence and reason — the leader/LLM interprets, never trusts.
 */
export function classifyParameterName(name: string): SemanticCandidateRecord[] {
  const lower = name.toLowerCase();
  const candidates: Array<{ semantic: ParameterSemantic; confidence: number; reason: string }> = [];

  if (/(^|_)(id|uuid|guid|ref|no|num|number|key)$/.test(lower) || /_id$|^id_|ident/.test(lower) || /^id$/.test(lower)) {
    candidates.push({
      semantic: 'IDENTIFIER',
      confidence: 0.7,
      reason: `name "${name}" matches identifier patterns (spec §16 user_id -> identifier)`,
    });
  }
  if (/role|admin|priv|permission|authz|scope|is_?admin|user_?type|account_?type/.test(lower)) {
    candidates.push({ semantic: 'PRIVILEGE', confidence: 0.8, reason: `name "${name}" suggests privilege/role semantics` });
  }
  if (/redirect|callback|return_?to|next|url|uri|link|goto|dest/.test(lower)) {
    candidates.push({ semantic: 'URL', confidence: 0.7, reason: `name "${name}" suggests URL/redirect semantics` });
  }
  if (/token|session|auth|jwt|secret|password|credential|api_?key|signature|nonce|csrf/.test(lower)) {
    candidates.push({ semantic: 'AUTHENTICATION', confidence: 0.85, reason: `name "${name}" suggests authentication/session material` });
  }
  if (/price|amount|total|cost|fee|balance|discount|tax|currency/.test(lower)) {
    candidates.push({ semantic: 'MONETARY', confidence: 0.8, reason: `name "${name}" suggests monetary/business value` });
  }
  if (/qty|quantity|count|limit|offset|page|size|number/.test(lower)) {
    candidates.push({ semantic: 'NUMERIC', confidence: 0.6, reason: `name "${name}" suggests numeric semantics` });
  }
  if (/file|upload|attachment|image|avatar|document|photo|filename/.test(lower)) {
    candidates.push({ semantic: 'UPLOAD', confidence: 0.7, reason: `name "${name}" suggests file upload semantics` });
  }
  if (/search|query|q|term|keyword|filter|name|title|content|message|comment|text/.test(lower)) {
    candidates.push({ semantic: 'TEXT', confidence: 0.5, reason: `name "${name}" suggests free-text semantics` });
  }
  return candidates.slice(0, 4);
}

/** Sensitive-name detection (values stored redacted, §115). */
export function isSensitiveParameterName(name: string): boolean {
  return SENSITIVE_NAME_RE.test(name);
}

/**
 * Object candidate detection (spec §19): *_id / *Id / *_no style names that
 * plausibly reference application objects. An identifier existing is NOT an
 * authorization vulnerability (§19) — only a candidate.
 */
export function objectNameFromParameter(name: string): string | null {
  const lower = name.toLowerCase();
  const idMatch = lower.match(/^(.+?)[-_]?id$/) ?? lower.match(/^(.+?)[-_]?no$/);
  if (idMatch) {
    const base = idMatch[1]!;
    if (base.length >= 2) return base;
  }
  return null;
}

/** Infer a coarse object kind for the object model (§96). */
export function objectKindFromName(name: string): string {
  const lower = name.toLowerCase();
  const table: Array<[RegExp, string]> = [
    [/user|member|account|profile|customer/, 'USER'],
    [/order|purchase|cart|checkout|transaction|payment|invoice|billing/, 'TRANSACTION'],
    [/doc|file|report|attachment|note|post|article|page/, 'DOCUMENT'],
    [/msg|message|chat|comment|mail|notification/, 'MESSAGE'],
    [/project|workspace|team|group|org|tenant/, 'WORKSPACE'],
    [/token|key|secret|credential/, 'CREDENTIAL'],
  ];
  for (const [pattern, kind] of table) {
    if (pattern.test(lower)) return kind;
  }
  return 'RESOURCE';
}

/** Deterministic file-ish value detection (characteristic FILE). */
export function looksLikeFileValue(text: string): boolean {
  return /^[^\s/\\]+\.(?:pdf|zip|tar|gz|csv|txt|xml|json|docx?|xlsx?|png|jpe?g|gif|exe|sh|py|js)$/i.test(text) || /^data:/i.test(text);
}

/** Serialize an observed JSON type for parameter records. */
export function observedTypeOf(value: unknown): string | null {
  if (value === null) return 'null';
  if (Array.isArray(value)) return 'array';
  switch (typeof value) {
    case 'string':
      return 'string';
    case 'number':
      return 'number';
    case 'boolean':
      return 'boolean';
    case 'object':
      return 'object';
    default:
      return null;
  }
}
