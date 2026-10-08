import { describe, expect, it } from 'vitest';
import { REDACTED, redactRecord, redactValue, scrubString } from '@aegis/logging';

describe('secret redaction', () => {
  it('redacts sensitive keys at any depth', () => {
    const input = {
      user: 'alice',
      password: 'hunter2hunter2',
      nested: {
        api_key: 'sk-1234567890abcdef1234',
        authorization: 'Bearer abc.def.ghi',
        metadata: { set_cookie: 'SESSIONID=xyz; Path=/' },
      },
      ok: 'value',
    };
    const output = redactRecord(input);
    expect(output.password).toBe(REDACTED);
    expect(output.nested.api_key).toBe(REDACTED);
    expect(output.nested.authorization).toBe(REDACTED);
    expect(output.nested.metadata.set_cookie).toBe(REDACTED);
    expect(output.user).toBe('alice');
    expect(output.ok).toBe('value');
  });

  it('scrubs bearer patterns inside free-form strings', () => {
    const result = scrubString('header was Authorization: Bearer abc123def456ghi789');
    expect(result).not.toContain('abc123def456ghi789');
    expect(result).toContain(REDACTED);
  });

  it('scrubs JWT-shaped strings', () => {
    const jwt = 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0GEsJi0';
    expect(scrubString(`token=${jwt}`)).not.toContain(jwt);
  });

  it('scrubs common API key formats in values', () => {
    expect(scrubString('key sk-abcdefghijklmnopqrstuvwxyz1234 end')).toContain(REDACTED);
    expect(scrubString('key AIzaSyA1234567890abcdefghijklmnopqrstuv end')).toContain(REDACTED);
  });

  it('redacts inside arrays', () => {
    const output = redactValue([{ token: 'abc' }, { name: 'ok' }]) as Record<string, unknown>[];
    expect(output[0]?.token).toBe(REDACTED);
    expect(output[1]?.name).toBe('ok');
  });

  it('handles circular references without crashing', () => {
    const circular: Record<string, unknown> = { name: 'x' };
    circular.self = circular;
    const output = redactRecord(circular);
    expect(output.self).toBe('[CIRCULAR]');
  });

  it('caps depth to bound cost', () => {
    const deep = { a: { b: { c: { d: { e: { f: { g: { h: { i: 'bottom' } } } } } } } } };
    const output = JSON.stringify(redactValue(deep));
    expect(output).toContain('TRUNCATED');
  });

  it('leaves non-sensitive primitives untouched', () => {
    const output = redactRecord({ count: 5, flag: true, note: 'plain text' });
    expect(output.count).toBe(5);
    expect(output.flag).toBe(true);
    expect(output.note).toBe('plain text');
  });
});
