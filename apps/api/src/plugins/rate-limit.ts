/**
 * In-memory fixed-window rate limiter (spec §25, §29).
 *
 * Two buckets per client IP: a strict one for authentication endpoints
 * (brute-force protection) and a general one for the API. Single-instance
 * limitation is documented; the queue abstraction allows a Redis-backed
 * implementation later without changing call sites.
 */
import type { FastifyInstance } from 'fastify';
import { QuotaError } from '@aegis/shared';
import type { AppConfig } from '@aegis/config';

interface Bucket {
  count: number;
  resetAt: number;
}

export function registerRateLimit(app: FastifyInstance, config: AppConfig): void {
  const windowMs = config.rateLimits.windowMs;
  const generalMax = config.rateLimits.maxRequests;
  const authMax = config.auth.rateLimitMax;
  const buckets = new Map<string, Bucket>();

  // Opportunistic cleanup to bound memory.
  const sweep = (): void => {
    const now = Date.now();
    for (const [key, bucket] of buckets) {
      if (bucket.resetAt <= now) buckets.delete(key);
    }
  };

  const allow = (key: string, max: number): boolean => {
    const now = Date.now();
    const bucket = buckets.get(key);
    if (!bucket || bucket.resetAt <= now) {
      buckets.set(key, { count: 1, resetAt: now + windowMs });
      if (buckets.size > 10_000) sweep();
      return true;
    }
    bucket.count += 1;
    return bucket.count <= max;
  };

  app.addHook('onRequest', async (request) => {
    const path = request.raw.url?.split('?')[0] ?? '';
    const isAuthEndpoint =
      path === '/api/auth/login' || path === '/api/auth/register';
    const max = isAuthEndpoint ? authMax : generalMax;
    const key = `${request.ip}:${isAuthEndpoint ? 'auth' : 'api'}`;
    if (!allow(key, max)) {
      throw new QuotaError(
        'Rate limit exceeded — slow down and retry later',
        'RATE_LIMIT_EXCEEDED',
        { window_ms: windowMs, limit: max },
      );
    }
  });
}
