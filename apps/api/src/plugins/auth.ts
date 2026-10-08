/**
 * Bearer-token authentication (platform auth sessions).
 *
 * Tokens are opaque 256-bit random strings; only their SHA-256 hash is
 * stored server-side. Expiry and revocation are enforced in SQL.
 */
import type { FastifyInstance } from 'fastify';
import { AuthenticationError } from '@aegis/shared';
import { hashToken } from '@aegis/security';
import type { RequestUser } from '../types.js';

export function registerAuthScope(app: FastifyInstance): void {
  app.addHook('onRequest', async (request) => {
    const header = request.headers.authorization;
    if (!header || !header.startsWith('Bearer ')) {
      throw new AuthenticationError('Missing or malformed Authorization header', 'UNAUTHENTICATED');
    }
    const token = header.slice('Bearer '.length).trim();
    if (token.length < 20 || token.length > 512) {
      throw new AuthenticationError('Invalid token', 'INVALID_TOKEN');
    }

    const ctx = request.server.ctx;
    const session = await ctx.repos.authSessions.findActiveByTokenHash(hashToken(token));
    if (!session) {
      throw new AuthenticationError('Invalid or expired token', 'INVALID_TOKEN');
    }
    const user = await ctx.repos.users.findById(session.user_id);
    if (!user) {
      throw new AuthenticationError('Session user no longer exists', 'INVALID_TOKEN');
    }

    const requestUser: RequestUser = { id: user.id, email: user.email, name: user.name };
    request.user = requestUser;
  });
}
