/** Shared structural schemas used across contract definitions. */
import { z } from 'zod';
import { ID_PATTERN } from '@aegis/shared';

/** Prefixed platform identifier (e.g. ENG_...). */
export const IdSchema = z.string().regex(ID_PATTERN, 'Expected a prefixed platform identifier');

/** ISO-8601 timestamp string. */
export const IsoDateTimeSchema = z
  .string()
  .regex(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,6})?Z$/, 'Expected an ISO-8601 UTC timestamp');

/** Standard error envelope produced by the API for every failure. */
export const ApiErrorSchema = z.object({
  error: z.object({
    code: z.string(),
    message: z.string(),
    category: z.string().optional(),
    details: z.unknown().optional(),
    request_id: z.string().optional(),
  }),
});
export type ApiError = z.infer<typeof ApiErrorSchema>;

export function pageSchema<T extends z.ZodTypeAny>(item: T) {
  return z.object({ items: z.array(item), total: z.number().int().min(0) });
}
