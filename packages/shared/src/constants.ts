/** Domain enums shared across backend, frontend and contracts. */

export const ENGAGEMENT_MODES = ['PENTEST', 'CTF'] as const;
export type EngagementMode = (typeof ENGAGEMENT_MODES)[number];

export const ENGAGEMENT_STATUSES = [
  'DRAFT',
  'READY',
  'RUNNING',
  'PAUSED',
  'COMPLETED',
  'FAILED',
  'CANCELLED',
] as const;
export type EngagementStatus = (typeof ENGAGEMENT_STATUSES)[number];

export const TARGET_TYPES = [
  'URL',
  'DOMAIN',
  'HOST',
  'IP',
  'APPLICATION',
  'CTF_INSTANCE',
] as const;
export type TargetType = (typeof TARGET_TYPES)[number];

export const ASSET_TYPES = [
  'HOST',
  'DOMAIN',
  'SUBDOMAIN',
  'APPLICATION',
  'API',
  'WEBSOCKET',
  'SOURCE_REPOSITORY',
  'FILE',
] as const;
export type AssetType = (typeof ASSET_TYPES)[number];

export const IDENTITY_TYPES = ['ANONYMOUS', 'USER', 'ADMIN', 'SERVICE'] as const;
export type IdentityType = (typeof IDENTITY_TYPES)[number];

/** Session types for TARGET-side identities (cookies, tokens, ...). */
export const SESSION_TYPES = ['COOKIE', 'JWT', 'API_KEY', 'BASIC', 'OAUTH', 'CUSTOM'] as const;
export type SessionType = (typeof SESSION_TYPES)[number];

export const SESSION_STATUSES = ['ACTIVE', 'EXPIRED', 'REVOKED', 'INVALID'] as const;
export type SessionStatus = (typeof SESSION_STATUSES)[number];

export const TOOL_CAPABILITIES = [
  'READ_ONLY',
  'NETWORK',
  'BROWSER',
  'MUTATION',
  'AUTHENTICATED',
  'DESTRUCTIVE',
] as const;
export type ToolCapability = (typeof TOOL_CAPABILITIES)[number];

export const RISK_LEVELS = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'] as const;
export type RiskLevel = (typeof RISK_LEVELS)[number];

/** Model roles (spec §19): strategic leader vs tactical workers. */
export const MODEL_ROLES = ['strategic', 'tactical'] as const;
export type ModelRole = (typeof MODEL_ROLES)[number];

/** Internal event vocabulary (spec §14). Kept in shared so the database,
 *  contracts and services layers share one source of truth. */
export const EVENT_TYPES = [
  'ENGAGEMENT_CREATED',
  'ENGAGEMENT_UPDATED',
  'ENGAGEMENT_READY',
  'ENGAGEMENT_STARTED',
  'ENGAGEMENT_PAUSED',
  'ENGAGEMENT_RESUMED',
  'ENGAGEMENT_COMPLETED',
  'ENGAGEMENT_FAILED',
  'ENGAGEMENT_CANCELLED',
  'TARGET_ADDED',
  'TARGET_REJECTED',
  'SCOPE_UPDATED',
  'IDENTITY_CREATED',
  'OBSERVATION_CREATED',
  'HYPOTHESIS_CREATED',
  'HYPOTHESIS_UPDATED',
  'TASK_CREATED',
  'TASK_STARTED',
  'TASK_COMPLETED',
  'TASK_FAILED',
  'HTTP_REQUEST_SENT',
  'HTTP_RESPONSE_RECEIVED',
  'BROWSER_NAVIGATION',
  'BROWSER_ACTION',
  'BROWSER_REQUEST',
  'BROWSER_RESPONSE',
  'EVIDENCE_CREATED',
  'FINDING_CREATED',
  'FINDING_VERIFIED',
  'AGENT_DECISION',
  'AGENT_ERROR',
  'TOOL_INVOKED',
  'TOOL_COMPLETED',
] as const;
export type EventType = (typeof EVENT_TYPES)[number];

export const PLATFORM_VERSION = '0.1.0-part1';
export const PLATFORM_NAME = 'Aegis Platform';
