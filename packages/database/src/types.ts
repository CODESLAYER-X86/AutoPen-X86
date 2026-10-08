/** Domain record types returned by repositories (snake_case kept for API fidelity). */
import type {
  EngagementMode,
  EngagementStatus,
  IdentityType,
  SessionType,
  SessionStatus,
  TargetType,
  AssetType,
  EventType,
} from '@aegis/shared';
import type { Iso8601, JsonRecord } from '@aegis/shared';

export interface UserRecord {
  id: string;
  email: string;
  name: string;
  password_hash: string;
  role: string;
  last_login_at: Iso8601 | null;
  created_at: Iso8601;
  updated_at: Iso8601;
}

export interface ProjectRecord {
  id: string;
  owner_id: string;
  name: string;
  description: string;
  created_at: Iso8601;
  updated_at: Iso8601;
}

export interface EngagementRecord {
  id: string;
  project_id: string;
  name: string;
  mode: EngagementMode;
  status: EngagementStatus;
  description: string;
  started_at: Iso8601 | null;
  completed_at: Iso8601 | null;
  created_at: Iso8601;
  updated_at: Iso8601;
}

export interface TargetRecord {
  id: string;
  engagement_id: string;
  type: TargetType;
  value: string;
  label: string | null;
  metadata: JsonRecord;
  created_at: Iso8601;
  updated_at: Iso8601;
}

export interface ScopeRecord {
  id: string;
  engagement_id: string;
  allowed_hosts: string[];
  allowed_domains: string[];
  allowed_ports: number[];
  allowed_schemes: string[];
  excluded_hosts: string[];
  excluded_paths: string[];
  rate_limit: number | null;
  concurrency_limit: number | null;
  destructive_actions_allowed: boolean;
  created_at: Iso8601;
  updated_at: Iso8601;
}

export interface AssetRecord {
  id: string;
  engagement_id: string;
  type: AssetType;
  value: string;
  label: string | null;
  parent_id: string | null;
  metadata: JsonRecord;
  created_at: Iso8601;
  updated_at: Iso8601;
}

export interface IdentityRecord {
  id: string;
  engagement_id: string;
  name: string;
  role: string;
  type: IdentityType;
  metadata: JsonRecord;
  created_at: Iso8601;
  updated_at: Iso8601;
}

/** TARGET-side session (cookies/JWTs of the application under test). */
export interface SessionRecord {
  id: string;
  identity_id: string;
  type: SessionType;
  status: SessionStatus;
  metadata: JsonRecord;
  secret_reference: string;
  created_at: Iso8601;
  expires_at: Iso8601 | null;
  updated_at: Iso8601;
}

/** PLATFORM-side authentication session (UI/API login). */
export interface AuthSessionRecord {
  id: string;
  user_id: string;
  token_hash: string;
  created_at: Iso8601;
  expires_at: Iso8601;
  revoked_at: Iso8601 | null;
}

export interface EventRecord {
  id: string;
  type: EventType;
  engagement_id: string | null;
  task_id: string | null;
  trace_id: string | null;
  actor_id: string | null;
  payload: JsonRecord;
  occurred_at: Iso8601;
}

export interface AuditRecord {
  id: string;
  actor_user_id: string | null;
  action: string;
  resource: string;
  resource_id: string | null;
  engagement_id: string | null;
  metadata: JsonRecord;
  created_at: Iso8601;
}

export interface EvidenceRecord {
  id: string;
  engagement_id: string;
  type: string;
  source: string;
  content_reference: string;
  sha256: string;
  parent_id: string | null;
  task_id: string | null;
  metadata: JsonRecord;
  created_at: Iso8601;
}
