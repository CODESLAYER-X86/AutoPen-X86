/** Zod request body parsing — every route input is schema validated (spec §27). */
import type { z } from 'zod';
import { ValidationError } from '@aegis/shared';

export function parseBody<S extends z.ZodTypeAny>(schema: S, body: unknown): z.output<S> {
  if (body === undefined || body === null) {
    throw new ValidationError('Request body is required', 'BODY_MISSING');
  }
  const result = schema.safeParse(body);
  if (!result.success) {
    throw new ValidationError(
      'Request body failed schema validation',
      'BODY_INVALID',
      result.error.issues.map((issue) => ({
        path: issue.path.join('.') || '(root)',
        message: issue.message,
      })),
    );
  }
  return result.data;
}

export function parseQueryInt(value: string | undefined, fallback: number, min: number, max: number): number {
  if (value === undefined || value === '') return fallback;
  const parsed = Number(value);
  if (!Number.isInteger(parsed) || parsed < min || parsed > max) {
    throw new ValidationError(`Query parameter must be an integer between ${min} and ${max}`, 'QUERY_INVALID');
  }
  return parsed;
}
