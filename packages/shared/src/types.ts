/** Small shared structural types (isomorphic, no Node built-ins). */

/** ISO-8601 timestamp string (e.g. 2026-10-09T12:00:00.000Z). */
export type Iso8601 = string;

/** A plain JSON object. Target-controlled content must never be trusted
 *  merely because it is typed as this — it stays untrusted input. */
export type JsonRecord = Record<string, unknown>;

export interface Page<T> {
  items: T[];
  total: number;
}
