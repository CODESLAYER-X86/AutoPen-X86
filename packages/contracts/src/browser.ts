/** Browser interaction contracts (spec Part 3 §3-§14, §31-§39, §43-§47, §65). */
import { z } from 'zod';
import { BROWSER_ACTIONS, SELECTOR_STRATEGIES } from '@aegis/shared';

// ---------------------------------------------------------------------------
// Structured actions (§8) with selector strategies (§9).
// ---------------------------------------------------------------------------

export const SelectorSchema = z.object({
  strategy: z.enum(SELECTOR_STRATEGIES),
  value: z.string().min(1).max(1024),
  /** role name for strategy=role (e.g. 'button'). */
  role: z.string().max(128).optional(),
  /** accessible name for strategy=role. */
  name: z.string().max(512).optional(),
});
export type Selector = z.infer<typeof SelectorSchema>;

export const BrowserActionRequestSchema = z.object({
  context_id: z.string(),
  page_id: z.string().nullable().default(null),
  action: z.enum(BROWSER_ACTIONS),
  url: z.string().max(2048).optional(),
  selector: SelectorSchema.optional(),
  value: z.string().max(8192).optional(),
  values: z.array(z.string().max(512)).max(32).optional(),
  key: z.string().max(64).optional(),
  timeout_ms: z.number().int().min(250).max(60_000).optional(),
  reason: z.string().max(2000).optional(),
});
export type BrowserActionRequest = z.infer<typeof BrowserActionRequestSchema>;

// ---------------------------------------------------------------------------
// DOM snapshots (§32) and diffs (§33).
// ---------------------------------------------------------------------------

export const DomElementSchema = z.object({
  tag: z.string().max(64),
  role: z.string().max(128).nullable(),
  text: z.string().max(2048).nullable(),
  attributes: z.record(z.string().max(256)),
  forms: z
    .array(
      z.object({
        action: z.string().max(2048).nullable(),
        method: z.string().max(16).nullable(),
        inputs: z
          .array(
            z.object({
              name: z.string().max(256).nullable(),
              type: z.string().max(64).nullable(),
              required: z.boolean(),
            }),
          )
          .max(256),
      }),
    )
    .max(64),
});
export type DomElement = z.infer<typeof DomElementSchema>;

export const DomSnapshotSchema = z.object({
  id: z.string(),
  context_id: z.string(),
  page_id: z.string(),
  url: z.string().max(2048),
  title: z.string().max(1024).nullable(),
  elements: z.array(DomElementSchema).max(5000),
  links: z.array(z.object({ href: z.string().max(2048), text: z.string().max(512).nullable() })).max(2000),
  buttons: z.array(z.object({ text: z.string().max(512).nullable(), aria: z.string().max(512).nullable() })).max(1000),
  iframes: z.array(z.object({ src: z.string().max(2048).nullable() })).max(256),
  scripts: z
    .array(z.object({ url: z.string().max(2048), content_type: z.string().nullable(), size: z.number().int(), hash: z.string().nullable() }))
    .max(1000),
  stylesheets: z.array(z.object({ href: z.string().max(2048) })).max(1000),
  images: z.array(z.object({ src: z.string().max(2048), alt: z.string().max(512).nullable() })).max(2000),
  created_at: z.string(),
});
export type DomSnapshot = z.infer<typeof DomSnapshotSchema>;

export const DomDiffSchema = z.object({
  before_snapshot_id: z.string(),
  after_snapshot_id: z.string(),
  added: z.array(z.string().max(2048)).max(2000),
  removed: z.array(z.string().max(2048)).max(2000),
  changed: z
    .array(z.object({ selector: z.string().max(2048), before: z.string().max(512).nullable(), after: z.string().max(512).nullable() }))
    .max(2000),
});
export type DomDiff = z.infer<typeof DomDiffSchema>;

// ---------------------------------------------------------------------------
// Cookies (§23), storage (§24), downloads (§37), screenshots (§38).
// ---------------------------------------------------------------------------

export const CookieDescriptorSchema = z.object({
  id: z.string(),
  engagement_id: z.string(),
  context_id: z.string().nullable(),
  identity_id: z.string().nullable(),
  /** Value is NEVER included — only an opaque reference. */
  name: z.string().max(256),
  domain: z.string().max(253),
  path: z.string().max(1024),
  secure: z.boolean(),
  http_only: z.boolean(),
  same_site: z.string().max(32).nullable(),
  expiration: z.string().nullable(),
  secret_reference: z.string(),
  created_at: z.string(),
});
export type CookieDescriptor = z.infer<typeof CookieDescriptorSchema>;

export const StorageEntrySchema = z.object({
  id: z.string(),
  engagement_id: z.string(),
  context_id: z.string(),
  identity_id: z.string().nullable(),
  origin: z.string().max(2048),
  area: z.enum(['LOCAL', 'SESSION']),
  key: z.string().max(512),
  value_redacted: z.string().max(2048),
  is_sensitive: z.boolean(),
  secret_reference: z.string().nullable(),
  created_at: z.string(),
});
export type StorageEntry = z.infer<typeof StorageEntrySchema>;

export const DownloadRecordSchema = z.object({
  id: z.string(),
  engagement_id: z.string(),
  context_id: z.string(),
  page_id: z.string().nullable(),
  url: z.string().max(2048),
  filename: z.string().max(512),
  content_type: z.string().nullable(),
  size: z.number().int().min(0),
  sha256: z.string(),
  evidence_id: z.string(),
  created_at: z.string(),
});
export type DownloadRecord = z.infer<typeof DownloadRecordSchema>;

// ---------------------------------------------------------------------------
// Tool execution contract (§44-§45) — the request/result envelopes.
// ---------------------------------------------------------------------------

export const ToolExecutionRequestSchema = z.object({
  tool_id: z.string(),
  task_id: z.string().nullable(),
  engagement_id: z.string(),
  identity_id: z.string().nullable(),
  input: z.unknown(),
  deadline_ms: z.number().int().min(250).max(600_000),
  correlation_id: z.string(),
  provenance: z
    .object({
      source: z.enum(['leader_task', 'worker_task', 'replay', 'verification', 'api']),
      hypothesis_id: z.string().nullable().default(null),
      test_id: z.string().nullable().default(null),
    })
    .default({ source: 'api', hypothesis_id: null, test_id: null }),
});
export type ToolExecutionRequest = z.infer<typeof ToolExecutionRequestSchema>;

export const ToolExecutionLogSchema = z.object({
  id: z.string(),
  engagement_id: z.string(),
  task_id: z.string().nullable(),
  identity_id: z.string().nullable(),
  tool_name: z.string(),
  tool_version: z.string(),
  configuration_version: z.string(),
  correlation_id: z.string(),
  status: z.enum(['SUCCEEDED', 'FAILED']),
  input_redacted: z.unknown(),
  output_summary: z.unknown(),
  error: z.unknown().nullable(),
  duration_ms: z.number().int().min(0),
  deadline_ms: z.number().int().min(0),
  created_at: z.string(),
});
export type ToolExecutionLog = z.infer<typeof ToolExecutionLogSchema>;

// ---------------------------------------------------------------------------
// Artifact retrieval (§65).
// ---------------------------------------------------------------------------

export const ArtifactReadInputSchema = z.object({
  artifact_ref: z.string().min(1).max(256),
  offset: z.number().int().min(0).default(0),
  limit_bytes: z.number().int().min(1).max(262_144).default(4096),
});
export type ArtifactReadInput = z.infer<typeof ArtifactReadInputSchema>;

export const ArtifactExtractInputSchema = z.object({
  artifact_ref: z.string().min(1).max(256),
  selector: z.string().min(1).max(512),
  format: z.enum(['JSON_PATH', 'REGEX', 'LINE_RANGE']).default('JSON_PATH'),
  limit_bytes: z.number().int().min(1).max(262_144).default(4096),
});
export type ArtifactExtractInput = z.infer<typeof ArtifactExtractInputSchema>;

export const ArtifactSearchInputSchema = z.object({
  artifact_ref: z.string().min(1).max(256),
  pattern: z.string().min(1).max(512),
  is_regex: z.boolean().default(false),
  max_matches: z.number().int().min(1).max(200).default(50),
});
export type ArtifactSearchInput = z.infer<typeof ArtifactSearchInputSchema>;

// ---------------------------------------------------------------------------
// Screenshot + snapshot tool outputs.
// ---------------------------------------------------------------------------

export const ScreenshotOutputSchema = z.object({
  context_id: z.string(),
  page_id: z.string().nullable(),
  evidence_id: z.string(),
  sha256: z.string(),
  byte_size: z.number().int().min(0),
  truncated: z.boolean(),
});
export type ScreenshotOutput = z.infer<typeof ScreenshotOutputSchema>;
