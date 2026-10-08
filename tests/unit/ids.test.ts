import { describe, expect, it } from 'vitest';
import { generateId, isValidId, newRequestId, newTraceId } from '@aegis/shared';

describe('ID generation', () => {
  it('generates prefixed IDs with the expected shape', () => {
    const id = generateId('ENG');
    expect(id).toMatch(/^ENG_[A-Z2-7]{16}$/);
  });

  it('generates unique IDs', () => {
    const ids = new Set(Array.from({ length: 500 }, () => generateId('TSK')));
    expect(ids.size).toBe(500);
  });

  it('supports every documented prefix', () => {
    for (const prefix of ['USR', 'PRJ', 'ENG', 'TGT', 'SCP', 'IDN', 'SES', 'EVD', 'EVT', 'AUD', 'TRC', 'REQ', 'TOOL', 'SEC', 'JOB'] as const) {
      expect(generateId(prefix)).toMatch(new RegExp(`^${prefix}_[A-Z2-7]{16}$`));
    }
  });

  it('validates ID format', () => {
    expect(isValidId('ENG_ABCDEFGHIJKLMNOP')).toBe(true);
    expect(isValidId('eng_abcdefghijklmnop')).toBe(false);
    expect(isValidId('ENG_SHORT')).toBe(false);
    expect(isValidId('')).toBe(false);
    expect(isValidId(123)).toBe(false);
  });

  it('creates trace and request ids', () => {
    expect(newTraceId()).toMatch(/^TRC_/);
    expect(newRequestId()).toMatch(/^REQ_/);
  });
});
