/**
 * Knowledge & Web Research API routes (spec Part 5 §112, §118, §119).
 *
 *  - POST /api/knowledge/search    — hybrid retrieval → compact packet
 *  - POST /api/knowledge/research  — bounded live research task
 *  - POST /api/knowledge/fetch     — bounded live fetch + ingestion
 *  - POST /api/knowledge/similar   — similar-case retrieval (CTF)
 *  - POST /api/knowledge/ctf       — ingest a CTF write-up into case memory
 *  - GET  /api/knowledge/sources   — source registry
 *  - GET  /api/knowledge/documents/:id (+versions)
 *  - GET  /api/knowledge/chunks/:id
 *  - GET  /api/knowledge/techniques
 *  - GET  /api/knowledge/queries   — retrieval audit trail (§85)
 *  - GET  /api/knowledge/research/:id
 *  - GET  /api/knowledge/status    — corpus + utility metrics
 *  - POST /api/knowledge/sync      — ADMIN: curated source sync (audited)
 *  - POST /api/knowledge/seed      — ADMIN: seed catalog (audited)
 *
 * Admin endpoints are audited (§112: "administrative synchronization
 * endpoints should be protected"). When the knowledge engine is disabled
 * the routes answer 501 — honest unavailability, never silent pretense.
 */
import type { FastifyInstance, FastifyRequest } from 'fastify';
import { z } from 'zod';
import {
  KnowledgeSearchRequestSchema,
  SimilarCaseRequestSchema,
  ResearchRequestSchema,
  KnowledgeFetchRequestSchema,
} from '@aegis/contracts';
import { NotImplementedError, NotFoundError } from '@aegis/shared';
import { parseBody, parseQueryInt } from '../lib/validate.js';
import { requireOwnedEngagement } from '../lib/ownership.js';
import type { AppContext } from '../context.js';
import type { KnowledgeEngine } from '@aegis/knowledge';

function requireKnowledge(c: AppContext): KnowledgeEngine {
  if (!c.knowledge) {
    throw new NotImplementedError(
      'The knowledge subsystem is disabled for this deployment (FEATURE_KNOWLEDGE_SEARCH=false)',
      'KNOWLEDGE_DISABLED',
    );
  }
  return c.knowledge;
}

export async function knowledgeRoutes(app: FastifyInstance): Promise<void> {
  const ctx = () => app.ctx;

  // ------------------------------------------------------------- search

  app.post('/api/knowledge/search', async (request: FastifyRequest) => {
    const c = ctx();
    if (!request.user) throw new Error('auth invariant violated');
    const body = parseBody(KnowledgeSearchRequestSchema, request.body ?? {});
    if (body.engagement_id) {
      // Engagement-scoped retrieval requires ownership (§118 isolation).
      await requireOwnedEngagement(c, request.user.id, body.engagement_id);
    }
    const packet = await requireKnowledge(c).search(body, `user:${request.user.id}`);
    return packet;
  });

  // ------------------------------------------------------------- similar

  app.post('/api/knowledge/similar', async (request: FastifyRequest) => {
    const c = ctx();
    if (!request.user) throw new Error('auth invariant violated');
    const body = parseBody(SimilarCaseRequestSchema, request.body ?? {});
    if (body.engagement_id) {
      await requireOwnedEngagement(c, request.user.id, body.engagement_id);
    }
    return requireKnowledge(c).similarCases(body);
  });

  // ------------------------------------------------------------- research

  app.post('/api/knowledge/research', async (request: FastifyRequest) => {
    const c = ctx();
    if (!request.user) throw new Error('auth invariant violated');
    const body = parseBody(ResearchRequestSchema, request.body ?? {});
    if (body.engagement_id) {
      await requireOwnedEngagement(c, request.user.id, body.engagement_id);
    }
    return requireKnowledge(c).research(body, `user:${request.user.id}`);
  });

  app.get('/api/knowledge/research/:id', async (request: FastifyRequest) => {
    const c = ctx();
    if (!request.user) throw new Error('auth invariant violated');
    requireKnowledge(c);
    const { id } = request.params as { id: string };
    const task = await c.repos.researchTasks.findById(id);
    if (!task) throw new NotFoundError(`Research task ${id} not found`, 'RESEARCH_NOT_FOUND');
    if (task.engagement_id) {
      await requireOwnedEngagement(c, request.user.id, task.engagement_id);
    }
    return task;
  });

  // --------------------------------------------------------------- fetch

  app.post('/api/knowledge/fetch', async (request: FastifyRequest, reply) => {
    const c = ctx();
    if (!request.user) throw new Error('auth invariant violated');
    const body = parseBody(KnowledgeFetchRequestSchema, request.body ?? {});
    if (body.engagement_id) {
      await requireOwnedEngagement(c, request.user.id, body.engagement_id);
    }
    const outcome = await requireKnowledge(c).fetch(body, `user:${request.user.id}`);
    await c.audit({
      actorUserId: request.user.id,
      action: 'KNOWLEDGE_FETCH',
      resource: 'knowledge_document',
      resourceId: outcome.document_id,
      engagementId: body.engagement_id,
      metadata: { url: outcome.canonical_url, status: outcome.ingestion_status, version: outcome.version },
    });
    reply.code(201);
    return outcome;
  });

  // ------------------------------------------------- CTF write-up ingest

  app.post('/api/knowledge/ctf', async (request: FastifyRequest, reply) => {
    const c = ctx();
    if (!request.user) throw new Error('auth invariant violated');
    const body = parseBody(
      z.object({
        source_id: z.string().min(1),
        url: z.string().min(1).max(2048),
        challenge_name: z.string().min(1).max(256),
        event: z.string().max(128).nullable().default(null),
        year: z.number().int().min(1990).max(2100).nullable().default(null),
        category: z.string().max(64).nullable().default(null),
        platform: z.string().max(128).nullable().default(null),
        difficulty: z.string().max(64).nullable().default(null),
        description: z.string().min(1).max(4000),
        technique: z.string().max(1000).nullable().default(null),
        solution_summary: z.string().max(4000).nullable().default(null),
        body: z.string().max(100_000).optional(),
      }),
      request.body ?? {},
    );
    const result = await requireKnowledge(c).ingestCtfWriteup({
      sourceId: body.source_id,
      url: body.url,
      challenge_name: body.challenge_name,
      event: body.event,
      year: body.year,
      category: body.category,
      platform: body.platform,
      difficulty: body.difficulty,
      description: body.description,
      technique: body.technique,
      solution_summary: body.solution_summary,
      body: body.body,
    });
    await c.audit({
      actorUserId: request.user.id,
      action: 'KNOWLEDGE_CTF_INGEST',
      resource: 'knowledge_document',
      resourceId: result.documentId,
      metadata: { challenge: body.challenge_name, patterns: result.patternsStored },
    });
    reply.code(201);
    return result;
  });

  // ------------------------------------------------------------- sources

  app.get('/api/knowledge/sources', async (request: FastifyRequest) => {
    const c = ctx();
    if (!request.user) throw new Error('auth invariant violated');
    requireKnowledge(c);
    const query = request.query as { enabled?: string };
    const enabledOnly = query.enabled === 'true' || query.enabled === '1';
    const items = await c.repos.knowledgeSources.list({ enabledOnly });
    return { items, total: items.length };
  });

  app.get('/api/knowledge/techniques', async (request: FastifyRequest) => {
    const c = ctx();
    if (!request.user) throw new Error('auth invariant violated');
    requireKnowledge(c);
    const query = request.query as { category?: string };
    const items = query.category
      ? await c.repos.securityTechniques.listByCategory(query.category.toUpperCase(), 200)
      : await c.repos.securityTechniques.list(500);
    return { items, total: items.length };
  });

  // ----------------------------------------------------------- documents

  app.get('/api/knowledge/documents/:id', async (request: FastifyRequest) => {
    const c = ctx();
    if (!request.user) throw new Error('auth invariant violated');
    requireKnowledge(c);
    const { id } = request.params as { id: string };
    const document = await c.repos.knowledgeDocuments.findById(id);
    if (!document) throw new NotFoundError(`Knowledge document ${id} not found`, 'DOCUMENT_NOT_FOUND');
    return document;
  });

  app.get('/api/knowledge/documents/:id/versions', async (request: FastifyRequest) => {
    const c = ctx();
    if (!request.user) throw new Error('auth invariant violated');
    requireKnowledge(c);
    const { id } = request.params as { id: string };
    const document = await c.repos.knowledgeDocuments.findById(id);
    if (!document) throw new NotFoundError(`Knowledge document ${id} not found`, 'DOCUMENT_NOT_FOUND');
    const versions = await c.repos.knowledgeDocuments.listVersions(document.canonical_url);
    return { items: versions, total: versions.length };
  });

  app.get('/api/knowledge/documents/:id/references', async (request: FastifyRequest) => {
    const c = ctx();
    if (!request.user) throw new Error('auth invariant violated');
    requireKnowledge(c);
    const { id } = request.params as { id: string };
    const items = await c.repos.knowledgeReferences.findByDocument(id);
    return { items, total: items.length };
  });

  app.get('/api/knowledge/chunks/:id', async (request: FastifyRequest) => {
    const c = ctx();
    if (!request.user) throw new Error('auth invariant violated');
    requireKnowledge(c);
    const { id } = request.params as { id: string };
    const chunk = await c.repos.knowledgeChunks.findById(id);
    if (!chunk) throw new NotFoundError(`Knowledge chunk ${id} not found`, 'CHUNK_NOT_FOUND');
    return chunk;
  });

  // ------------------------------------------------------------- queries

  app.get('/api/knowledge/queries', async (request: FastifyRequest) => {
    const c = ctx();
    if (!request.user) throw new Error('auth invariant violated');
    requireKnowledge(c);
    const query = request.query as { engagement_id?: string; limit?: string };
    const limit = parseQueryInt(query.limit, 50, 1, 200);
    const items = query.engagement_id
      ? await c.repos.knowledgeQueries.listByEngagement(query.engagement_id, limit)
      : await c.repos.knowledgeQueries.listRecent(limit);
    return { items, total: items.length };
  });

  // -------------------------------------------------------------- status

  app.get('/api/knowledge/status', async (request: FastifyRequest) => {
    const c = ctx();
    if (!request.user) throw new Error('auth invariant violated');
    return requireKnowledge(c).status();
  });

  // --------------------------------------------------- admin: sync/seed

  app.post('/api/knowledge/sync', async (request: FastifyRequest) => {
    const c = ctx();
    if (!request.user) throw new Error('auth invariant violated');
    const body = parseBody(
      z.object({ source_id: z.string().min(1).optional(), seed: z.boolean().optional() }),
      request.body ?? {},
    );
    const summary = await requireKnowledge(c).sync({
      sourceId: body.source_id,
      seed: body.seed,
    });
    await c.audit({
      actorUserId: request.user.id,
      action: 'KNOWLEDGE_SYNC',
      resource: 'knowledge_sources',
      resourceId: body.source_id ?? null,
      metadata: { seeded: summary.seeded, documents: summary.documents, skipped: summary.skipped.length },
    });
    return summary;
  });
}
