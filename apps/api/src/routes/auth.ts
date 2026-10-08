/** Authentication routes. register/login are public; me/logout require a
 *  bearer token and are registered inside the authenticated scope. */
import type { FastifyInstance } from 'fastify';
import {
  AuthenticationError,
  ValidationError,
} from '@aegis/shared';
import { hashPassword, verifyPassword, generateSessionToken, hashToken } from '@aegis/security';
import { AuthSessionSchema, LoginRequestSchema, RegisterRequestSchema, UserSchema } from '@aegis/contracts';
import { parseBody } from '../lib/validate.js';

function toUserResponse(user: {
  id: string;
  email: string;
  name: string;
  created_at: string;
  updated_at: string;
}) {
  return UserSchema.parse({
    id: user.id,
    email: user.email,
    name: user.name,
    created_at: user.created_at,
    updated_at: user.updated_at,
  });
}

export async function publicAuthRoutes(app: FastifyInstance): Promise<void> {
  const ctx = () => app.ctx;

  app.post('/api/auth/register', async (request, reply) => {
    const body = parseBody(RegisterRequestSchema, request.body);
    const c = ctx();

    const existing = await c.repos.users.findByEmail(body.email);
    if (existing) {
      throw new ValidationError('This email address is already registered', 'EMAIL_ALREADY_REGISTERED');
    }

    const user = await c.repos.users.create({
      email: body.email,
      name: body.name,
      passwordHash: hashPassword(body.password),
    });

    await c.audit({
      actorUserId: user.id,
      action: 'USER_REGISTERED',
      resource: 'user',
      resourceId: user.id,
    });

    reply.status(201);
    return toUserResponse(user);
  });

  app.post('/api/auth/login', async (request) => {
    const body = parseBody(LoginRequestSchema, request.body);
    const c = ctx();

    const user = await c.repos.users.findByEmail(body.email);
    if (!user || !verifyPassword(body.password, user.password_hash)) {
      // Generic failure: no information about which factor failed.
      await c.audit({
        actorUserId: null,
        action: 'LOGIN_FAILED',
        resource: 'user',
        metadata: { email_domain: body.email.split('@')[1] ?? '' },
      });
      throw new AuthenticationError('Invalid email or password', 'INVALID_CREDENTIALS');
    }

    const token = generateSessionToken();
    const expiresAt = new Date(Date.now() + c.config.auth.sessionTtlHours * 3600 * 1000);
    await c.repos.authSessions.create({
      userId: user.id,
      tokenHash: hashToken(token),
      expiresAt,
    });
    await c.repos.users.touchLastLogin(user.id);

    await c.audit({
      actorUserId: user.id,
      action: 'USER_LOGIN',
      resource: 'user',
      resourceId: user.id,
    });

    c.logger.info('auth.login', { user_id: user.id, request_id: request.id });

    return AuthSessionSchema.parse({
      token,
      expires_at: expiresAt.toISOString(),
      user: toUserResponse(user),
    });
  });
}

/** Routes that require authentication (registered inside the auth scope). */
export async function protectedAuthRoutes(app: FastifyInstance): Promise<void> {
  const ctx = () => app.ctx;

  app.post('/api/auth/logout', async (request, reply) => {
    const c = ctx();
    const header = request.headers.authorization;
    if (header?.startsWith('Bearer ')) {
      const token = header.slice('Bearer '.length).trim();
      if (token.length >= 20) {
        const revoked = await c.repos.authSessions.revokeByTokenHash(hashToken(token));
        if (revoked && request.user) {
          await c.audit({
            actorUserId: request.user.id,
            action: 'USER_LOGOUT',
            resource: 'user',
            resourceId: request.user.id,
          });
        }
      }
    }
    reply.status(204);
    return null;
  });

  app.get('/api/auth/me', async (request) => {
    if (!request.user) throw new AuthenticationError();
    const c = ctx();
    const user = await c.repos.users.findById(request.user.id);
    if (!user) throw new AuthenticationError('User no longer exists', 'INVALID_TOKEN');
    return toUserResponse(user);
  });
}
