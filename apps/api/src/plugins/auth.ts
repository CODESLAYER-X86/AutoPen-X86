/**
 * Bearer-token authentication (platform auth sessions + Part 8 API keys).
 *
 * Tokens are opaque 256-bit random strings; only their SHA-256 hash is
 * stored server-side. Expiry and revocation are enforced in SQL.
 *
 * Part 8 §11: tokens prefixed `aegis_` are API credentials with their own
 * lifecycle (owner, scopes, expiry, last_used, revocation) — resolved
 * against api_credentials instead of auth_sessions.
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
    const user = token.startsWith('aegis_')
      ? await resolveApiCredentialUser(ctx, token)
      : await resolveSessionUser(ctx, token);

    const requestUser: RequestUser = { id: user.id, email: user.email, name: user.name };
    request.user = requestUser;
  });
}

async function resolveSessionUser(
  ctx: { repos: { authSessions: { findActiveByTokenHash(hash: string): Promise<{ user_id: string } | null> }; users: { findById(id: string): Promise<{ id: string; email: string; name: string } | null> } } },
  token: string,
): Promise<{ id: string; email: string; name: string }> {
  const session = await ctx.repos.authSessions.findActiveByTokenHash(hashToken(token));
  if (!session) {
    throw new AuthenticationError('Invalid or expired token', 'INVALID_TOKEN');
  }
  const user = await ctx.repos.users.findById(session.user_id);
  if (!user) {
    throw new AuthenticationError('Session user no longer exists', 'INVALID_TOKEN');
  }
  return user;
}

async function resolveApiCredentialUser(
  ctx: { repos: { apiCredentials: { findActiveByTokenHash(hash: string): Promise<{ id: string; user_id: string } | null>; touchLastUsed(id: string): Promise<void> }; users: { findById(id: string): Promise<{ id: string; email: string; name: string } | null> } } },
  token: string,
): Promise<{ id: string; email: string; name: string }> {
  const credential = await ctx.repos.apiCredentials.findActiveByTokenHash(hashToken(token));
  if (!credential) {
    throw new AuthenticationError('Invalid, expired or revoked API credential', 'INVALID_TOKEN');
  }
  // last_used_at feeds the §11 lifecycle view + stale-credential alerts.
  await ctx.repos.apiCredentials.touchLastUsed(credential.id).catch(() => undefined);
  const user = await ctx.repos.users.findById(credential.user_id);
  if (!user) {
    throw new AuthenticationError('API credential user no longer exists', 'INVALID_TOKEN');
  }
  return user;
}
