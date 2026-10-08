/** Security headers on every API response (spec §29). */
import type { FastifyInstance } from 'fastify';

export function registerSecurityHeaders(app: FastifyInstance): void {
  app.addHook('onSend', async (_request, reply, payload) => {
    reply.header('X-Content-Type-Options', 'nosniff');
    reply.header('X-Frame-Options', 'DENY');
    reply.header('Referrer-Policy', 'no-referrer');
    reply.header('X-Robots-Tag', 'noindex, nofollow');
    reply.header('Cache-Control', 'no-store');
    reply.header('Content-Security-Policy', "default-src 'none'; frame-ancestors 'none'");
    return payload;
  });
}
