/**
 * Part 8 contracts — Production Hardening (spec Part 8 §4-§15, §44-§46, §51,
 * §59-§60, §75, §85-§99).
 *
 * Every production control is a structured, validated record: trust levels,
 * API credentials, scoped credential grants, scope versions, security events
 * and incidents, circuit breakers, the transactional outbox, retention
 * policies and the tamper-evident audit chain. The security layer is
 * deterministic — the model can never modify any of these records.
 */
import { z } from 'zod';
import {
  API_CREDENTIAL_STATUSES,
  CIRCUIT_BREAKER_CATEGORIES,
  CIRCUIT_BREAKER_STATES,
  CREDENTIAL_GRANT_STATUSES,
  INCIDENT_STATUSES,
  OUTBOX_DELIVERY_STATUSES,
  RETENTION_DATA_CLASSES,
  SCOPE_VERSION_STATUSES,
  SECURITY_EVENT_SEVERITIES,
  TLS_POLICY_MODES,
  TRUST_LEVELS,
} from '@aegis/shared';
import { IdSchema, IsoDateTimeSchema } from './common.js';

// ---------------------------------------------------------------------------
// Trust boundaries (§4)
// ---------------------------------------------------------------------------

export const TrustLevelSchema = z.enum(TRUST_LEVELS);
export type TrustLevel = z.infer<typeof TrustLevelSchema>;

/** Tag applied to data crossing a trust boundary before it reaches a prompt. */
export const TrustTagSchema = z
  .object({
    level: TrustLevelSchema,
    label: z.string().min(1).max(64),
  })
  .strict();
export type TrustTag = z.infer<typeof TrustTagSchema>;

export const TRUST_TAGS = {
  target_content: { level: 'UNTRUSTED' as const, label: 'UNTRUSTED_TARGET_DATA' },
  external_knowledge: { level: 'UNTRUSTED' as const, label: 'UNTRUSTED_EXTERNAL_KNOWLEDGE' },
  model_output: { level: 'SEMI_TRUSTED' as const, label: 'SEMI_TRUSTED_MODEL_OUTPUT' },
  worker_output: { level: 'SEMI_TRUSTED' as const, label: 'SEMI_TRUSTED_WORKER_OUTPUT' },
  policy: { level: 'TRUSTED' as const, label: 'TRUSTED_POLICY' },
  human_approval: { level: 'TRUSTED' as const, label: 'TRUSTED_HUMAN_APPROVAL' },
} as const;

// ---------------------------------------------------------------------------
// API credentials (§11)
// ---------------------------------------------------------------------------

export const ApiCredentialKindSchema = z.enum(['API_KEY', 'PERSONAL_ACCESS_TOKEN']);
export type ApiCredentialKind = z.infer<typeof ApiCredentialKindSchema>;

export const ApiCredentialScopesSchema = z.array(z.enum(['read', 'write', 'admin'])).min(1).max(3);
export type ApiCredentialScope = z.infer<typeof ApiCredentialScopesSchema>[number];

export const CreateApiCredentialRequestSchema = z
  .object({
    kind: ApiCredentialKindSchema,
    name: z.string().min(1).max(120),
    scopes: ApiCredentialScopesSchema,
    ttl_hours: z.number().int().min(1).max(8760),
  })
  .strict();
export type CreateApiCredentialRequest = z.infer<typeof CreateApiCredentialRequestSchema>;

export const ApiCredentialRecordSchema = z
  .object({
    id: IdSchema,
    user_id: IdSchema,
    kind: ApiCredentialKindSchema,
    name: z.string().min(1).max(120),
    scopes: ApiCredentialScopesSchema,
    status: z.enum(API_CREDENTIAL_STATUSES),
    created_at: IsoDateTimeSchema,
    expires_at: IsoDateTimeSchema,
    last_used_at: IsoDateTimeSchema.nullable(),
    revoked_at: IsoDateTimeSchema.nullable(),
  })
  .strict();
export type ApiCredentialRecord = z.infer<typeof ApiCredentialRecordSchema>;

/** One-time response: the plaintext secret is shown exactly once. */
export const ApiCredentialCreatedSchema = ApiCredentialRecordSchema.extend({
  token: z.string().min(20).max(256),
}).strict();
export type ApiCredentialCreated = z.infer<typeof ApiCredentialCreatedSchema>;

// ---------------------------------------------------------------------------
// Scoped credential grants (§14-§15)
// ---------------------------------------------------------------------------

export const CreateCredentialGrantRequestSchema = z
  .object({
    engagement_id: IdSchema,
    identity_id: IdSchema,
    secret_reference: z.string().min(1).max(256),
    target_id: IdSchema,
    purpose: z.enum(['AUTHENTICATION', 'VERIFICATION', 'REPRODUCTION']),
    ttl_minutes: z.number().int().min(1).max(1440),
  })
  .strict();
export type CreateCredentialGrantRequest = z.infer<typeof CreateCredentialGrantRequestSchema>;

export const CredentialGrantRecordSchema = z
  .object({
    id: IdSchema,
    engagement_id: IdSchema,
    identity_id: IdSchema,
    target_id: IdSchema,
    secret_reference: z.string().min(1).max(256),
    purpose: z.enum(['AUTHENTICATION', 'VERIFICATION', 'REPRODUCTION']),
    status: z.enum(CREDENTIAL_GRANT_STATUSES),
    created_at: IsoDateTimeSchema,
    expires_at: IsoDateTimeSchema,
    revoked_at: IsoDateTimeSchema.nullable(),
    consumed_at: IsoDateTimeSchema.nullable(),
  })
  .strict();
export type CredentialGrantRecord = z.infer<typeof CredentialGrantRecordSchema>;

/** What a worker may request — anything outside this shape is denied (§15). */
export const CredentialRequestContextSchema = z
  .object({
    engagement_id: IdSchema,
    identity_id: IdSchema,
    target_id: IdSchema,
    purpose: z.enum(['AUTHENTICATION', 'VERIFICATION', 'REPRODUCTION']),
  })
  .strict();
export type CredentialRequestContext = z.infer<typeof CredentialRequestContextSchema>;

// ---------------------------------------------------------------------------
// Scope versions (§91-§92)
// ---------------------------------------------------------------------------

export const ScopeDiffSchema = z
  .object({
    added_hosts: z.array(z.string()),
    removed_hosts: z.array(z.string()),
    added_paths: z.array(z.string()),
    removed_paths: z.array(z.string()),
    destructive_actions_allowed: z.boolean(),
  })
  .strict();
export type ScopeDiff = z.infer<typeof ScopeDiffSchema>;

export const ScopeVersionRecordSchema = z
  .object({
    id: IdSchema,
    engagement_id: IdSchema,
    version: z.number().int().min(1),
    status: z.enum(SCOPE_VERSION_STATUSES),
    scope: z.record(z.unknown()),
    diff: ScopeDiffSchema,
    created_by: IdSchema,
    created_at: IsoDateTimeSchema,
    activated_at: IsoDateTimeSchema.nullable(),
  })
  .strict();
export type ScopeVersionRecord = z.infer<typeof ScopeVersionRecordSchema>;

// ---------------------------------------------------------------------------
// Security events + incidents (§94-§96)
// ---------------------------------------------------------------------------

export const SecurityEventRecordSchema = z
  .object({
    id: IdSchema,
    incident_id: IdSchema.nullable(),
    severity: z.enum(SECURITY_EVENT_SEVERITIES),
    category: z.string().min(1).max(80),
    actor: z.enum(['AGENT', 'MODEL', 'WORKER', 'USER', 'PLATFORM']),
    engagement_id: IdSchema.nullable(),
    description: z.string().min(1).max(2000),
    metadata: z.record(z.unknown()),
    created_at: IsoDateTimeSchema,
  })
  .strict();
export type SecurityEventRecord = z.infer<typeof SecurityEventRecordSchema>;

export const RaiseSecurityEventRequestSchema = z
  .object({
    severity: z.enum(SECURITY_EVENT_SEVERITIES),
    category: z.string().min(1).max(80),
    actor: z.enum(['AGENT', 'MODEL', 'WORKER', 'USER', 'PLATFORM']),
    engagement_id: IdSchema.nullable(),
    description: z.string().min(1).max(2000),
    metadata: z.record(z.unknown()).optional(),
  })
  .strict();
export type RaiseSecurityEventRequest = z.infer<typeof RaiseSecurityEventRequestSchema>;

export const IncidentRecordSchema = z
  .object({
    id: IdSchema,
    status: z.enum(INCIDENT_STATUSES),
    severity: z.enum(SECURITY_EVENT_SEVERITIES),
    title: z.string().min(1).max(200),
    opened_at: IsoDateTimeSchema,
    resolved_at: IsoDateTimeSchema.nullable(),
    event_count: z.number().int().min(0),
  })
  .strict();
export type IncidentRecord = z.infer<typeof IncidentRecordSchema>;

// ---------------------------------------------------------------------------
// Circuit breakers (§97-§99)
// ---------------------------------------------------------------------------

export const CircuitBreakerRecordSchema = z
  .object({
    id: IdSchema,
    subject: z.enum(['AGENT', 'MODEL']),
    subject_id: z.string().min(1).max(200),
    engagement_id: IdSchema.nullable(),
    category: z.enum(CIRCUIT_BREAKER_CATEGORIES),
    state: z.enum(CIRCUIT_BREAKER_STATES),
    violation_count: z.number().int().min(0),
    threshold: z.number().int().min(1),
    tripped_at: IsoDateTimeSchema.nullable(),
    reset_at: IsoDateTimeSchema.nullable(),
    updated_at: IsoDateTimeSchema,
  })
  .strict();
export type CircuitBreakerRecord = z.infer<typeof CircuitBreakerRecordSchema>;

// ---------------------------------------------------------------------------
// Transactional outbox (§44-§45)
// ---------------------------------------------------------------------------

export const OutboxEventRecordSchema = z
  .object({
    id: IdSchema,
    event_type: z.string().min(1).max(80),
    engagement_id: IdSchema.nullable(),
    aggregate_id: z.string().min(1).max(200),
    causation_id: z.string().min(1).max(200).nullable(),
    correlation_id: z.string().min(1).max(200).nullable(),
    sequence: z.number().int().min(0),
    payload: z.record(z.unknown()),
    status: z.enum(OUTBOX_DELIVERY_STATUSES),
    attempts: z.number().int().min(0),
    created_at: IsoDateTimeSchema,
    delivered_at: IsoDateTimeSchema.nullable(),
  })
  .strict();
export type OutboxEventRecord = z.infer<typeof OutboxEventRecordSchema>;

// ---------------------------------------------------------------------------
// Retention + deletion (§59-§60)
// ---------------------------------------------------------------------------

export const RetentionPolicyRecordSchema = z
  .object({
    id: IdSchema,
    data_class: z.enum(RETENTION_DATA_CLASSES),
    retention_days: z.number().int().min(0).max(36500),
    hard_delete: z.boolean(),
    created_at: IsoDateTimeSchema,
    updated_at: IsoDateTimeSchema,
  })
  .strict();
export type RetentionPolicyRecord = z.infer<typeof RetentionPolicyRecordSchema>;

export const RetentionSweepResultSchema = z
  .object({
    data_class: z.enum(RETENTION_DATA_CLASSES),
    evaluated: z.number().int().min(0),
    deleted: z.number().int().min(0),
  })
  .strict();
export type RetentionSweepResult = z.infer<typeof RetentionSweepResultSchema>;

// ---------------------------------------------------------------------------
// TLS policy (§75)
// ---------------------------------------------------------------------------

export const EngagementTlsPolicySchema = z
  .object({
    engagement_id: IdSchema,
    mode: z.enum(TLS_POLICY_MODES),
    custom_ca_reference: z.string().min(1).max(256).nullable(),
  })
  .strict();
export type EngagementTlsPolicy = z.infer<typeof EngagementTlsPolicySchema>;

// ---------------------------------------------------------------------------
// Emergency stop (§89-§90, §93)
// ---------------------------------------------------------------------------

export const EmergencyStopStateSchema = z
  .object({
    status: z.enum(['CLEAR', 'ENGAGED', 'RELEASING']),
    engaged_at: IsoDateTimeSchema.nullable(),
    released_at: IsoDateTimeSchema.nullable(),
    engaged_by: IdSchema.nullable(),
    reason: z.string().max(500).nullable(),
    cancelled_tasks: z.number().int().min(0),
    revoked_grants: z.number().int().min(0),
  })
  .strict();
export type EmergencyStopState = z.infer<typeof EmergencyStopStateSchema>;

// ---------------------------------------------------------------------------
// Audit chain (§85-§86)
// ---------------------------------------------------------------------------

export const AuditChainVerificationSchema = z
  .object({
    verified: z.boolean(),
    records_checked: z.number().int().min(0),
    first_broken_record_id: IdSchema.nullable(),
    reason: z.string().max(500).nullable(),
  })
  .strict();
export type AuditChainVerification = z.infer<typeof AuditChainVerificationSchema>;

// ---------------------------------------------------------------------------
// Health + metrics (§51-§52, §49)
// ---------------------------------------------------------------------------

export const DependencyHealthSchema = z
  .object({
    name: z.string().min(1).max(60),
    healthy: z.boolean(),
    detail: z.string().max(200).nullable(),
    latency_ms: z.number().int().min(0).nullable(),
  })
  .strict();
export type DependencyHealth = z.infer<typeof DependencyHealthSchema>;

export const ReadinessReportSchema = z
  .object({
    ready: z.boolean(),
    checked_at: IsoDateTimeSchema,
    dependencies: z.array(DependencyHealthSchema),
    waiting_for_resource: z.boolean(),
  })
  .strict();
export type ReadinessReport = z.infer<typeof ReadinessReportSchema>;

export const SecurityMetricsSnapshotSchema = z
  .object({
    scope_denials: z.number().int().min(0),
    policy_denials: z.number().int().min(0),
    approval_requests: z.number().int().min(0),
    credential_accesses: z.number().int().min(0),
    prompt_injection_events: z.number().int().min(0),
    tool_validation_failures: z.number().int().min(0),
    emergency_stop_engaged: z.boolean(),
    open_circuit_breakers: z.number().int().min(0),
    open_incidents: z.number().int().min(0),
  })
  .strict();
export type SecurityMetricsSnapshot = z.infer<typeof SecurityMetricsSnapshotSchema>;
