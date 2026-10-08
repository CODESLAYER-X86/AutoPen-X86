/**
 * Prefixed, collision-resistant identifier generation.
 *
 * Every persistent entity and every correlation carrier in the platform uses a
 * prefixed identifier (e.g. `ENG_K5XH7Q2M9PB4W8ZC`) so that autonomous agent
 * behaviour remains auditable across the whole system:
 *
 *   trace:  TRC_...   task:   TSK_...   tool call: TOOL_...
 *   http:   REQ_...   observation: OBS_... evidence: EVD_...
 *
 * The random component is 16 characters of base32 (128 bits of entropy from
 * a cryptographically secure source). The generator is isomorphic: it uses
 * the WebCrypto global available in Node >= 18 and browsers.
 */

const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'; // Crockford-style base32
const RANDOM_CHARS = 16;

export type IdPrefix =
  | 'USR'
  | 'PRJ'
  | 'ENG'
  | 'TGT'
  | 'SCP'
  | 'AST'
  | 'IDN'
  | 'SES'
  | 'TSK'
  | 'OBS'
  | 'HYP'
  | 'TST'
  | 'FND'
  | 'EVD'
  | 'EVT'
  | 'AUD'
  | 'TRC'
  | 'REQ'
  | 'TOOL'
  | 'SEC'
  | 'JOB'
  // Part 2 prefixes (Agent Operating System).
  | 'RUN' // agent run
  | 'DCS' // leader decision
  | 'ATT' // task attempt / worker run
  | 'DDE' // dead end
  | 'STG' // strategy snapshot
  | 'MSG' // agent message (prompt/response audit)
  | 'MCL' // model call (token usage log)
  | 'BGT'; // engagement budget

/** Matches `<PREFIX>_<16..32 base32 chars>` and is case sensitive. */
export const ID_PATTERN = /^[A-Z]{2,6}_[A-Z2-7]{16,32}$/;

function randomBase32(length: number): string {
  const bytes = new Uint8Array(length);
  const cryptoObj = globalThis.crypto;
  if (!cryptoObj?.getRandomValues) {
    // Should never happen on supported runtimes (Node >= 18, modern browsers).
    throw new Error('No secure randomness source available (globalThis.crypto)');
  }
  cryptoObj.getRandomValues(bytes);
  // 256 % 32 === 0, so byte % 32 is unbiased.
  let out = '';
  for (const byte of bytes) out += ALPHABET[byte % 32];
  return out;
}

export function generateId(prefix: IdPrefix): string {
  return `${prefix}_${randomBase32(RANDOM_CHARS)}`;
}

export function newTraceId(): string {
  return generateId('TRC');
}

export function newRequestId(): string {
  return generateId('REQ');
}

export function isValidId(value: unknown): value is string {
  return typeof value === 'string' && ID_PATTERN.test(value);
}
