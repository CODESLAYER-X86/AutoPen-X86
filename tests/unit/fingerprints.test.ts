import { describe, expect, it } from 'vitest';
import { canonicalJson, computeTestFingerprint, fingerprintsNearEquivalent } from '@aegis/agent';

describe('test fingerprints (spec Part 2 §29)', () => {
  it('is deterministic for identical inputs', () => {
    const a = computeTestFingerprint({
      endpoint: '/api/users/{id}',
      method: 'GET',
      identity: 'IDN_A',
      mutationType: 'AUTHORIZATION_ANALYSIS',
      relevantParameter: 'id',
      mutation: { id: '382' },
    });
    const b = computeTestFingerprint({
      endpoint: '/api/users/{id}',
      method: 'GET',
      identity: 'IDN_A',
      mutationType: 'AUTHORIZATION_ANALYSIS',
      relevantParameter: 'id',
      mutation: { id: '382' },
    });
    expect(a).toBe(b);
    expect(a).toMatch(/^[a-f0-9]{64}$/);
  });

  it('is independent of key order (canonical JSON)', () => {
    expect(canonicalJson({ b: 1, a: { d: 2, c: 3 } })).toBe(
      canonicalJson({ a: { c: 3, d: 2 }, b: 1 }),
    );
    expect(
      computeTestFingerprint({ endpoint: '/x', mutation: { p: 1, q: 2 } }),
    ).toBe(computeTestFingerprint({ endpoint: '/x', mutation: { q: 2, p: 1 } }));
  });

  it('distinguishes endpoint, method, identity, mutation type and parameter', () => {
    const base = {
      endpoint: '/api/users/{id}',
      method: 'GET',
      identity: 'IDN_A',
      mutationType: 'AUTHORIZATION_ANALYSIS',
    };
    const f0 = computeTestFingerprint(base);
    expect(computeTestFingerprint({ ...base, endpoint: '/api/orders/{id}' })).not.toBe(f0);
    expect(computeTestFingerprint({ ...base, method: 'POST' })).not.toBe(f0);
    expect(computeTestFingerprint({ ...base, identity: 'IDN_B' })).not.toBe(f0);
    expect(computeTestFingerprint({ ...base, mutationType: 'SESSION_ANALYSIS' })).not.toBe(f0);
    expect(computeTestFingerprint({ ...base, relevantParameter: 'userId' })).not.toBe(f0);
    expect(computeTestFingerprint({ ...base, mutation: { id: '999' } })).not.toBe(f0);
  });

  it('normalizes case and whitespace so near-equivalent tests collide', () => {
    const f0 = computeTestFingerprint({ endpoint: '/API/Users/', method: 'get' });
    const f1 = computeTestFingerprint({ endpoint: ' /api/users', method: 'GET' });
    expect(f0).toBe(f1);
    expect(fingerprintsNearEquivalent(f0, f1)).toBe(true);
  });

  it('never uses an LLM — pure deterministic hashing', () => {
    // 100 random-ish inputs produce stable hashes across re-computation.
    for (let i = 0; i < 100; i += 1) {
      const input = { endpoint: `/e/${i}`, method: 'GET', mutation: { i } };
      expect(computeTestFingerprint(input)).toBe(computeTestFingerprint(input));
    }
  });
});
