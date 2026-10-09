/** Typed error handler + 404 handler: normalized JSON error envelopes. */
import type { FastifyInstance } from 'fastify';
import { ScopeViolationError, ValidationError, isPlatformError } from '@aegis/shared';
import { EmergencyStopError } from '@aegis/hardening';

export function registerErrorHandler(app: FastifyInstance): void {
  app.setNotFoundHandler((request, reply) => {
    reply.status(404).send({
      error: {
        code: 'ROUTE_NOT_FOUND',
        message: 'Route not found',
        request_id: request.id,
      },
    });
  });

  app.setErrorHandler((error, request, reply) => {
    const requestId = request.id;
    const log = request.server.ctx?.logger;

    // Part 8 §49/§94: scope violations raise a security event for the
    // metrics + incident layer. Best-effort: observability never blocks the
    // error response path.
    if (error instanceof ScopeViolationError && request.server.ctx?.hardening) {
      request.server.ctx.hardening.securityEvents
        .raise({
          category: 'SCOPE_DENIAL',
          actor: request.user ? 'USER' : 'PLATFORM',
          engagementId: (request.params as { id?: string } | undefined)?.id ?? null,
          description: `Scope violation: ${error.message}`,
          metadata: { code: error.code, request_id: requestId },
        })
        .catch(() => undefined);
    }

    // Part 8 §89: the emergency stop blocks target-bound actions with a
    // deterministic, non-internal error (never a 500).
    if (error instanceof EmergencyStopError) {
      reply.status(403).send({
        error: {
          code: 'EMERGENCY_STOP_ENGAGED',
          message: error.message,
          request_id: requestId,
        },
      });
      return;
    }

    if (isPlatformError(error)) {
      const errorBody: Record<string, unknown> = {
        code: error.code,
        message: error.message,
        category: error.category,
        request_id: requestId,
      };
      // Structured details are only exposed for client-facing errors;
      // server-side details (SQL, internals) stay in the log.
      if (error.statusCode < 500 && error.details !== undefined) {
        errorBody.details = error.details;
      }
      const body = { error: errorBody };
      if (error.statusCode >= 500) {
        log?.error('request.platform_error', {
          request_id: requestId,
          code: error.code,
          category: error.category,
          details: error.details,
        });
      }
      reply.status(error.statusCode).send(body);
      return;
    }

    // Fastify content-type/parse errors carry a numeric statusCode.
    const statusCode = typeof (error as { statusCode?: number }).statusCode === 'number'
      ? (error as { statusCode: number }).statusCode
      : undefined;

    if (statusCode === 400) {
      reply.status(400).send({
        error: {
          code: 'BODY_PARSE_FAILED',
          message: 'Request body could not be parsed as JSON',
          request_id: requestId,
        },
      });
      return;
    }
    if (statusCode === 413) {
      reply.status(413).send({
        error: {
          code: 'BODY_TOO_LARGE',
          message: 'Request body exceeds the configured size limit',
          request_id: requestId,
        },
      });
      return;
    }

    // Unknown error: log internally, never leak internals to the client.
    log?.error('request.unhandled_error', {
      request_id: requestId,
      error_name: error instanceof Error ? error.name : 'Unknown',
      error_message: error instanceof Error ? error.message : String(error),
      stack: error instanceof Error ? error.stack : undefined,
    });
    reply.status(500).send({
      error: {
        code: 'INTERNAL_ERROR',
        message: 'An internal error occurred',
        request_id: requestId,
      },
    });
  });

  // Unknown errors are logged by the handler above; nothing else to wire.
}

export { ValidationError };
