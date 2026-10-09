/**
 * Worker runtime types (spec Part 2 §11-§17).
 *
 * A worker is a disposable tactical specialist. It receives ONE compact task
 * packet — never the whole engagement — plus an explicit allow-list of tools
 * and hard constraints. All worker output is structured and schema-validated;
 * the orchestrator (never the worker) interprets results (§16).
 */
import type { ScopeRules } from '@aegis/security';

/** The canonical compact task packet (spec Part 2 §13). */
export interface WorkerTaskPacket {
  task_id: string;
  engagement_id: string;
  run_id: string;
  type: string;
  worker_type: string;
  objective: string;
  hypothesis: { id: string; statement: string; confidence: number } | null;
  identity_id: string | null;
  allowed_tools: string[];
  constraints: {
    max_tool_calls: number;
    max_duration_seconds: number;
    max_network_requests?: number;
  };
  /** Trusted, application-derived compact facts (§15). */
  context: Record<string, unknown>;
  /** Target-derived content — always rendered inside untrusted delimiters. */
  untrusted_context: Record<string, unknown>;
}

/** Deterministic execution context supplied by the scheduler (§69). */
export interface WorkerExecutionContext {
  engagementId: string;
  runId: string;
  /** Scheduler-assigned attempt number for this execution. */
  attemptNumber: number;
  requestId?: string;
  /** Scope rules for network-capable tools; null when no scope exists. */
  scope: ScopeRules | null;
  /** Effective permissions derived from engagement state + configuration. */
  permissions: {
    network: boolean;
    browser: boolean;
    destructive: boolean;
    /** Part 5 §84: live web knowledge access — opt-in, fail closed. */
    knowledgeWeb?: boolean;
  };
  /** The deterministic tool gateway — the ONLY path to tool execution. */
  toolGateway: {
    execute(
      name: string,
      input: unknown,
      ctx: {
        requestId?: string;
        engagementId?: string;
        identityId?: string;
        scope?: ScopeRules | null;
        permissions: { network: boolean; browser: boolean; destructive: boolean; knowledgeWeb?: boolean };
      },
    ): Promise<{
      ok: boolean;
      tool: string;
      durationMs: number;
      output?: unknown;
      error?: { code: string; message: string; category: string };
    }>;
  };
  logger?: {
    info(event: string, fields?: Record<string, unknown>): void;
    warn(event: string, fields?: Record<string, unknown>): void;
  };
}

export interface WorkerUsage {
  inputTokens: number;
  outputTokens: number;
  toolCalls: number;
  networkRequests: number;
  durationMs: number;
}

export interface WorkerResult {
  task_id: string;
  attempt_id: string | null;
  status:
    | 'COMPLETED'
    | 'PARTIAL'
    | 'BLOCKED'
    | 'FAILED'
    | 'NEEDS_CONTEXT'
    | 'NEEDS_TOOL'
    | 'NEEDS_IDENTITY';
  observations: Array<{
    type: string;
    description: string;
    confidence: number;
    evidence_refs?: string[];
    metadata?: Record<string, unknown>;
  }>;
  evidence_ids: string[];
  hypothesis_updates: Array<{
    hypothesis_id?: string;
    change: string;
    confidence?: number;
    statement?: string;
    type?: string;
    reason?: string;
  }>;
  needs?: {
    context?: string[];
    tools?: string[];
    identity?: string;
  };
  recommended_next_action?: {
    type: 'VERIFY' | 'CREATE_TASK' | 'WAIT' | 'NONE';
    reason: string;
  };
  usage: WorkerUsage;
  error?: { code: string; message: string };
}

export interface WorkerRuntime {
  runTask(packet: WorkerTaskPacket, ctx: WorkerExecutionContext): Promise<WorkerResult>;
}
