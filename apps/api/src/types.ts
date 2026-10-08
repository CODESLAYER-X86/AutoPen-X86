/** Fastify type augmentation for request context and authenticated user. */
import type { FastifyInstance, FastifyRequest } from 'fastify';
import type { AppContext } from './context.js';

export interface RequestUser {
  id: string;
  email: string;
  name: string;
}

declare module 'fastify' {
  interface FastifyRequest {
    user?: RequestUser;
  }
  interface FastifyInstance {
    ctx: AppContext;
  }
}

export type { AppContext };
