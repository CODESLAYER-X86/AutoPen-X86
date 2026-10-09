/**
 * Deterministic redaction (spec Part 7 §24).
 *
 * Reports must never accidentally expose passwords, session cookies, JWTs,
 * API keys, personal data or internal credentials. Redaction is regex-based
 * and DETERMINISTIC: every occurrence is replaced with a labeled placeholder
 * and recorded so the manifest can prove what was removed. The original
 * evidence stays separately protected (immutable + hashed, §23).
 */

export interface RedactionRecord {
  location: string;
  rule: string;
}

interface RedactionRule {
  name: string;
  pattern: RegExp;
  replacement: string;
}

const RULES: RedactionRule[] = [
  {
    name: 'cookie_header',
    pattern: /((?:[Cc]ookie:)\s*)([^\r\n]{1,4096})/g,
    replacement: '$1<REDACTED>',
  },
  {
    name: 'set_cookie_header',
    pattern: /((?:[Ss]et-[Cc]ookie:)\s*)([^\r\n]{1,4096})/g,
    replacement: '$1<REDACTED>',
  },
  {
    name: 'authorization_header',
    pattern: /((?:[Aa]uthorization:)\s*)(?:[Bb]earer\s+)?([A-Za-z0-9\-._~+/]+=*[^\r\n]{0,4096})/g,
    replacement: '$1<REDACTED>',
  },
  {
    name: 'jwt_token',
    pattern: /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{8,}\b/g,
    replacement: '<REDACTED_JWT>',
  },
  {
    name: 'api_key_parameter',
    pattern: /((?:api[_-]?key|access[_-]?token|secret|password|passwd|token)["']?\s*[:=]\s*["']?)([^\s"',;}\r\n]{8,})/gi,
    replacement: '$1<REDACTED>',
  },
  {
    name: 'email_address',
    pattern: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g,
    replacement: '<REDACTED_EMAIL>',
  },
  {
    name: 'session_id_value',
    pattern: /((?:session[_-]?id|sess|sid|jsessionid|phpsessid|csrf[_-]?token)["']?\s*[:=]\s*["']?)([^\s"',;}\r\n]{8,})/gi,
    replacement: '$1<REDACTED>',
  },
  {
    name: 'private_key_block',
    pattern: /-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----/g,
    replacement: '<REDACTED_PRIVATE_KEY>',
  },
  {
    name: 'basic_auth_header',
    pattern: /((?:[Aa]uthorization:)\s*[Bb]asic\s+)([A-Za-z0-9+/=]{8,})/g,
    replacement: '$1<REDACTED>',
  },
];

export interface RedactionResult {
  text: string;
  records: RedactionRecord[];
  count: number;
}

/** Redact one text block, recording every rule application per location. */
export function redactText(text: string, location: string): RedactionResult {
  let output = text;
  const records: RedactionRecord[] = [];
  let count = 0;
  for (const rule of RULES) {
    const matches = output.match(rule.pattern);
    if (matches && matches.length > 0) {
      count += matches.length;
      records.push({ location, rule: rule.name });
      output = output.replace(rule.pattern, rule.replacement);
    }
  }
  return { text: output, records, count };
}

/** §65: validation hook — returns true when NO secret pattern survives. */
export function containsUnredactedSecret(text: string): { found: boolean; rule: string | null } {
  for (const rule of RULES) {
    // Only check reveal-style rules (value-bearing patterns).
    if (rule.name === 'cookie_header' || rule.name === 'set_cookie_header') {
      if (/[Cc]ookie:\s*[^\r\n<]/.test(text) && !/[Cc]ookie:\s*<REDACTED>/.test(text)) {
        return { found: true, rule: rule.name };
      }
      continue;
    }
    if (rule.name === 'authorization_header' || rule.name === 'basic_auth_header') {
      if (/[Aa]uthorization:\s*(?:[Bb]earer|[Bb]asic)\s+[A-Za-z0-9\-._~+/=]{8,}/.test(text)) {
        return { found: true, rule: rule.name };
      }
      continue;
    }
    const probe = new RegExp(rule.pattern.source);
    const matched = text.match(probe);
    if (matched && matched.length > 0 && !matched[0].includes('<REDACTED')) {
      return { found: true, rule: rule.name };
    }
  }
  return { found: false, rule: null };
}
