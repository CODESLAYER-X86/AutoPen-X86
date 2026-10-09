/** HTTP interaction contracts (spec Part 3 §15-§23, §48, §55, §64-§72, §80). */
import { z } from 'zod';
import {
  AUTH_STATE_KINDS,
  HTTP_BODY_TYPES,
  HTTP_METHODS,
  HTTP_MUTATION_LOCATIONS,
  HTTP_MUTATION_OPERATIONS,
  HTTP_PROVENANCE_SOURCES,
  HTTP_REQUEST_SOURCES,
  WS_MESSAGE_DIRECTIONS,
} from '@aegis/shared';

// ---------------------------------------------------------------------------
// Normalized request / response representations (§16-§17).
// ---------------------------------------------------------------------------

export const HttpHeaderListSchema = z.array(
  z.object({
    name: z.string().min(1).max(128),
    value: z.string().max(8192),
  }),
);

export const QueryParamListSchema = z.array(
  z.object({
    name: z.string().min(1).max(256),
    value: z.string().max(8192),
  }),
);

export const HttpRequestBodySchema = z.object({
  body_type: z.enum(HTTP_BODY_TYPES),
  /** Raw bytes never inline: parsed representations + artifact references. */
  parsed: z.unknown().nullable(),
  artifact_ref: z.string().nullable(),
  sha256: z.string().nullable(),
  byte_length: z.number().int().min(0),
});

export const HttpRequestRecordSchema = z.object({
  id: z.string(),
  engagement_id: z.string(),
  task_id: z.string().nullable(),
  identity_id: z.string().nullable(),
  method: z.enum(HTTP_METHODS),
  url: z.string().min(1).max(2048),
  normalized_url: z.string().min(1).max(2048),
  headers: HttpHeaderListSchema,
  query: QueryParamListSchema,
  body: HttpRequestBodySchema.nullable(),
  source: z.enum(HTTP_REQUEST_SOURCES),
  provenance: z.object({
    source: z.enum(HTTP_PROVENANCE_SOURCES),
    parent_task_id: z.string().nullable(),
    hypothesis_id: z.string().nullable(),
    test_id: z.string().nullable(),
    reason: z.string().max(2000).optional(),
  }),
  parent_request_id: z.string().nullable(),
  browser_context_id: z.string().nullable(),
  browser_page_id: z.string().nullable(),
  correlation_id: z.string().nullable(),
  created_at: z.string(),
});
export type HttpRequestRecord = z.infer<typeof HttpRequestRecordSchema>;

export const HttpResponseRecordSchema = z.object({
  id: z.string(),
  request_id: z.string(),
  status: z.number().int().min(100).max(599),
  headers: HttpHeaderListSchema,
  content_type: z.string().nullable(),
  content_kind: z.string(),
  body_artifact_ref: z.string().nullable(),
  body_sha256: z.string().nullable(),
  content_length: z.number().int().min(0),
  /** Explicit truncation flag (§48: never silently truncate). */
  truncated: z.boolean(),
  timing_ms: z.number().int().min(0),
  redirect_to: z.string().nullable(),
  created_at: z.string(),
});
export type HttpResponseRecord = z.infer<typeof HttpResponseRecordSchema>;

// ---------------------------------------------------------------------------
// Tool inputs.
// ---------------------------------------------------------------------------

export const HttpBodyInputSchema = z.discriminatedUnion('body_type', [
  z.object({ body_type: z.literal('JSON'), data: z.unknown() }),
  z.object({ body_type: z.literal('FORM_URLENCODED'), fields: z.array(z.object({ name: z.string(), value: z.string() })) }),
  z.object({
    body_type: z.literal('MULTIPART'),
    fields: z.array(z.object({ name: z.string(), value: z.string() })),
    files: z.array(z.object({ name: z.string(), filename: z.string(), content_b64: z.string() })).default([]),
  }),
  z.object({ body_type: z.literal('TEXT'), text: z.string().max(1_048_576) }),
  z.object({ body_type: z.literal('XML'), text: z.string().max(1_048_576) }),
  z.object({ body_type: z.literal('BINARY'), content_b64: z.string(), content_type: z.string().optional() }),
  z.object({ body_type: z.literal('EMPTY') }),
]);

export type HttpBodyInput = z.infer<typeof HttpBodyInputSchema>;

export const HttpRequestInputSchema = z.object({
  method: z.enum(HTTP_METHODS).default('GET'),
  url: z.string().min(1).max(2048),
  headers: z.array(z.object({ name: z.string().min(1).max(128), value: z.string().max(8192) })).max(64).default([]),
  body: HttpBodyInputSchema.nullable().default(null),
  identity_id: z.string().nullable().default(null),
  reason: z.string().max(2000).optional(),
});
export type HttpRequestInput = z.infer<typeof HttpRequestInputSchema>;

export const HttpReplayInputSchema = z.object({
  request_id: z.string(),
  identity_id: z.string().nullable().default(null),
  reason: z.string().max(2000).optional(),
});
export type HttpReplayInput = z.infer<typeof HttpReplayInputSchema>;

export const HttpMutationSchema = z.object({
  location: z.enum(HTTP_MUTATION_LOCATIONS),
  name: z.string().min(1).max(256).optional(),
  operation: z.enum(HTTP_MUTATION_OPERATIONS),
  value: z.union([z.string(), z.number(), z.boolean(), z.null()]).optional(),
  /** JSON-path-ish dot notation for body_json mutations (§69). */
  path: z.string().max(512).optional(),
  /** For reorder: new position index; for path: new segments. */
  index: z.number().int().min(0).max(999).optional(),
  segments: z.array(z.string().max(256)).max(64).optional(),
});
export type HttpMutation = z.infer<typeof HttpMutationSchema>;

export const HttpMutateInputSchema = z.object({
  base_request_id: z.string(),
  mutations: z.array(HttpMutationSchema).min(1).max(32),
  /** Execute the mutated request immediately (identity applies at execution). */
  execute: z.boolean().default(true),
  identity_id: z.string().nullable().default(null),
  reason: z.string().max(2000).optional(),
});
export type HttpMutateInput = z.infer<typeof HttpMutateInputSchema>;

// ---------------------------------------------------------------------------
// Observation interface published to the observation pipeline (§58).
// ---------------------------------------------------------------------------

export const HttpObservationSchema = z.object({
  observation_type: z.literal('HTTP_RESPONSE'),
  request_id: z.string(),
  response_id: z.string(),
  summary: z.object({
    status: z.number(),
    content_type: z.string().nullable(),
    length: z.number(),
    method: z.string(),
    url: z.string(),
  }),
  artifact_refs: z.array(z.string()),
});
export type HttpObservation = z.infer<typeof HttpObservationSchema>;

// ---------------------------------------------------------------------------
// WebSockets (§36) and auth states (§25-§28).
// ---------------------------------------------------------------------------

export const WsMessageRecordSchema = z.object({
  id: z.string(),
  connection_id: z.string(),
  direction: z.enum(WS_MESSAGE_DIRECTIONS),
  is_binary: z.boolean(),
  payload_artifact_ref: z.string().nullable(),
  payload_preview: z.string().nullable(),
  byte_size: z.number().int().min(0),
  truncated: z.boolean(),
  created_at: z.string(),
});
export type WsMessageRecord = z.infer<typeof WsMessageRecordSchema>;

export const WsObservationInputSchema = z.object({
  connection_id: z.string().nullable().default(null),
  context_id: z.string().nullable().default(null),
  reason: z.string().max(2000).optional(),
});
export type WsObservationInput = z.infer<typeof WsObservationInputSchema>;

export const AuthStateDescriptorSchema = z.object({
  kind: z.enum(AUTH_STATE_KINDS),
  /**COOKIE: cookie names; CUSTOM_HEADER: header names. */
  names: z.array(z.string().min(1).max(128)).max(32),
  domains: z.array(z.string().min(1).max(253)).max(32).default([]),
});
export type AuthStateDescriptor = z.infer<typeof AuthStateDescriptorSchema>;

export const HarImportInputSchema = z.object({
  har: z.object({
    log: z.object({
      entries: z
        .array(
          z.object({
            request: z.object({
              method: z.string(),
              url: z.string(),
              headers: z.array(z.object({ name: z.string(), value: z.string() })).optional(),
              postData: z.object({ text: z.string().optional(), mimeType: z.string().optional() }).optional(),
            }),
            response: z
              .object({
                status: z.number().optional(),
                content: z.object({ text: z.string().optional(), mimeType: z.string().optional() }).optional(),
              })
              .optional(),
          }),
        )
        .min(1)
        .max(2000),
    }),
  }),
  reason: z.string().max(2000).optional(),
});
export type HarImportInput = z.infer<typeof HarImportInputSchema>;

// ---------------------------------------------------------------------------
// API response envelopes.
// ---------------------------------------------------------------------------

export const HttpRequestListResponseSchema = z.object({
  items: z.array(HttpRequestRecordSchema),
  total: z.number().int().min(0),
});
export type HttpRequestListResponse = z.infer<typeof HttpRequestListResponseSchema>;

export const HttpExchangeResponseSchema = z.object({
  request: HttpRequestRecordSchema,
  response: HttpResponseRecordSchema.nullable(),
});
export type HttpExchangeResponse = z.infer<typeof HttpExchangeResponseSchema>;
