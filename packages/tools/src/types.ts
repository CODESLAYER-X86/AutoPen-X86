/**
 * Tool abstraction (spec §16, §17).
 *
 * A tool is a deterministic capability with strict metadata: zod input and
 * output schemas, a risk level, and an explicit capability set. The
 * ToolGateway (not the model, not the worker) decides whether an
 * invocation may run: worker permission + engagement permission + scope +
 * tool capability + resource limits.
 */
import type { z } from 'zod';
import type { Logger } from '@aegis/logging';
import type { RiskLevel, ToolCapability } from '@aegis/shared';
import type { ScopeRules } from '@aegis/security';

export interface ToolExecutionContext {
  requestId?: string;
  engagementId?: string;
  identityId?: string;
  /** Required for tools with the NETWORK capability. */
  scope?: ScopeRules | null;
  /** Effective permissions derived from engagement state and config. */
  permissions: {
    network: boolean;
    browser: boolean;
    destructive: boolean;
    /** Part 5 §84: live web knowledge access — opt-in, fail closed. */
    knowledgeWeb?: boolean;
  };
  logger?: Logger;
}

export interface ToolDefinition {
  /** Dotted, lowercase, unique, e.g. `parser.jwt`. */
  name: string;
  version: string;
  description: string;
  inputSchema: z.ZodType<unknown>;
  outputSchema: z.ZodType<unknown>;
  riskLevel: RiskLevel;
  capabilities: ToolCapability[];
  requiresScope: boolean;
  requiresIdentity?: boolean;
  /** false = registered interface, execution deliberately deferred. */
  implemented: boolean;
  /** Implementation part where this tool becomes real, if not implemented. */
  plannedPart?: string;
  /** Input fields holding URLs that must be scope-checked (NETWORK tools). */
  urlFields?: string[];
  timeoutMs?: number;
  execute(input: unknown, ctx: ToolExecutionContext): Promise<unknown>;
}

export interface ToolExecutionSuccess {
  ok: true;
  tool: string;
  durationMs: number;
  output: unknown;
}

export interface ToolExecutionFailure {
  ok: false;
  tool: string;
  durationMs: number;
  error: {
    code: string;
    message: string;
    category: string;
  };
}

export type ToolExecutionResult = ToolExecutionSuccess | ToolExecutionFailure;
