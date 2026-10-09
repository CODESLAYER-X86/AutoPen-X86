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
  | 'BGT' // engagement budget
  // Part 3 prefixes (interaction layer).
  | 'RSP' // http response record
  | 'CTX' // browser context
  | 'PGE' // browser page
  | 'BEV' // browser event
  | 'CKE' // cookie record
  | 'STE' // storage entry
  | 'DMS' // dom snapshot
  | 'DLD' // download record
  | 'WSC' // websocket connection
  | 'WSM' // websocket message
  | 'TEX' // tool execution record
  | 'AUS' // target-side auth state (identity authentication material ref)
  | 'AWF' // recorded authentication workflow
  // Part 4 prefixes (security reasoning engine).
  | 'EPD' // endpoint record
  | 'PRM' // parameter record
  | 'AZM' // authorization matrix cell
  | 'WFL' // workflow candidate
  | 'WST' // workflow state
  | 'WTR' // workflow transition
  | 'DFL' // data flow record
  | 'SIG' // security signal
  | 'OBJ' // object candidate
  | 'AGN' // attack graph node
  | 'AGE' // attack graph edge
  | 'DFC' // differential comparison result
  | 'VER' // verification record
  | 'RFL' // reasoning processor failure
  // Part 5 prefixes (knowledge & web research).
  | 'KSR' // knowledge source
  | 'KDC' // knowledge document
  | 'KCK' // knowledge chunk
  | 'KTF' // security technique
  | 'KQR' // knowledge query (audit + cache)
  | 'KRT' // knowledge retrieval result row
  | 'KRF' // extracted knowledge reference (CVE/CWE/OWASP link)
  | 'RSC' // research task
  | 'RSR' // research source (selected/fetched during research)
  | 'KVR'; // knowledge index/embedding version marker

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
