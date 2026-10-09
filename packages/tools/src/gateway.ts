/**
 * Tool gateway — the ONLY path from a model/worker decision to actual tool
 * execution (spec §17, §40).
 *
 * Pipeline (all checks are deterministic; no LLM involvement):
 *   1. Tool exists in the registry        (kills hallucinated tool names)
 *   2. Tool is implemented                (explicit 501 for deferred tools)
 *   3. Input validates against the schema (kills invalid arguments)
 *   4. Capability gates:
 *        NETWORK    -> permission + scope present + URL scope-check
 *        BROWSER    -> permission
 *        DESTRUCTIVE-> engagement permission
 *        AUTHENTICATED -> identity in context
 *        KNOWLEDGE_WEB_SEARCH / KNOWLEDGE_WEB_FETCH -> explicit knowledge
 *        web permission (Part 5 §84 — fail closed when not granted)
 *   5. Execute with timeout
 *   6. Output validates against the schema (defense in depth)
 *
 * A worker "deciding" to call a tool is never sufficient authorization.
 */
import {
  AuthorizationError,
  ScopeViolationError,
  TimeoutError,
  ToolError,
  ValidationError,
  isPlatformError,
} from '@aegis/shared';
import { ScopeChecker } from '@aegis/security';
import type { ToolDefinition, ToolExecutionContext, ToolExecutionResult } from './types.js';
import type { ToolRegistry } from './registry.js';

const DEFAULT_TIMEOUT_MS = 15_000;

export class ToolGateway {
  constructor(private readonly registry: ToolRegistry) {}

  async execute(
    name: string,
    input: unknown,
    ctx: ToolExecutionContext,
  ): Promise<ToolExecutionResult> {
    const startedAt = Date.now();

    try {
      const tool = this.registry.require(name);
      if (!tool.implemented) {
        throw new ToolError(
          `Tool '${name}' is registered but not implemented${tool.plannedPart ? ` (planned for ${tool.plannedPart})` : ''}`,
          'TOOL_NOT_IMPLEMENTED',
        );
      }

      const parsedInput = tool.inputSchema.safeParse(input);
      if (!parsedInput.success) {
        throw new ValidationError(
          `Tool '${name}' input failed schema validation`,
          'TOOL_INPUT_INVALID',
          parsedInput.error.issues.map((issue) => ({
            path: issue.path.join('.'),
            message: issue.message,
          })),
        );
      }

      this.checkCapabilities(tool, parsedInput.data, ctx);
      this.checkScopeUrls(tool, parsedInput.data, ctx);

      const output = await this.withTimeout(
        tool.execute(parsedInput.data, ctx),
        tool.timeoutMs ?? DEFAULT_TIMEOUT_MS,
        name,
      );

      const parsedOutput = tool.outputSchema.safeParse(output);
      if (!parsedOutput.success) {
        throw new ToolError(
          `Tool '${name}' produced output that failed its own schema`,
          'TOOL_OUTPUT_INVALID',
          parsedOutput.error.issues.map((issue) => ({
            path: issue.path.join('.'),
            message: issue.message,
          })),
        );
      }

      return {
        ok: true,
        tool: name,
        durationMs: Date.now() - startedAt,
        output: parsedOutput.data,
      };
    } catch (error) {
      return {
        ok: false,
        tool: name,
        durationMs: Date.now() - startedAt,
        error: {
          code: isPlatformError(error) ? error.code : 'TOOL_EXECUTION_FAILED',
          message: isPlatformError(error) ? error.message : 'Tool execution failed unexpectedly',
          category: isPlatformError(error) ? error.category : 'TOOL',
        },
      };
    }
  }

  private checkCapabilities(tool: ToolDefinition, input: unknown, ctx: ToolExecutionContext): void {
    const caps = tool.capabilities;

    if (caps.includes('NETWORK')) {
      if (!ctx.permissions.network) {
        throw new AuthorizationError(
          `Tool '${tool.name}' requires the NETWORK capability which is not enabled in this context`,
          'TOOL_NETWORK_FORBIDDEN',
        );
      }
      if (!ctx.scope) {
        throw new ScopeViolationError(
          `Tool '${tool.name}' requires network access but no engagement scope is configured`,
          'SCOPE_NOT_CONFIGURED',
        );
      }
    }

    if (caps.includes('BROWSER') && !ctx.permissions.browser) {
      throw new AuthorizationError(
        `Tool '${tool.name}' requires the BROWSER capability which is not enabled in this context`,
        'TOOL_BROWSER_FORBIDDEN',
      );
    }

    if (caps.includes('DESTRUCTIVE') && !ctx.permissions.destructive) {
      throw new AuthorizationError(
        `Tool '${tool.name}' requires the DESTRUCTIVE capability which is not permitted for this engagement`,
        'TOOL_DESTRUCTIVE_FORBIDDEN',
      );
    }

    if (caps.includes('AUTHENTICATED') && !ctx.identityId) {
      throw new AuthorizationError(
        `Tool '${tool.name}' requires an identity in the execution context`,
        'TOOL_IDENTITY_REQUIRED',
      );
    }

    // Part 5 §84: live web knowledge tools require an explicit, opt-in
    // permission. Contexts that never set knowledgeWeb fail closed.
    if (
      (caps.includes('KNOWLEDGE_WEB_SEARCH') || caps.includes('KNOWLEDGE_WEB_FETCH')) &&
      ctx.permissions.knowledgeWeb !== true
    ) {
      throw new AuthorizationError(
        `Tool '${tool.name}' requires live web knowledge access which is not enabled in this context`,
        'TOOL_KNOWLEDGE_WEB_FORBIDDEN',
      );
    }

    if (tool.requiresIdentity && !ctx.identityId) {
      throw new AuthorizationError(
        `Tool '${tool.name}' declares requires_identity but no identity is bound`,
        'TOOL_IDENTITY_REQUIRED',
      );
    }

    void input;
  }

  private checkScopeUrls(tool: ToolDefinition, input: unknown, ctx: ToolExecutionContext): void {
    if (!tool.capabilities.includes('NETWORK') || !ctx.scope || !tool.urlFields) return;
    const checker = new ScopeChecker(ctx.scope);
    const candidate = input as Record<string, unknown>;

    for (const field of tool.urlFields) {
      const value = candidate[field];
      const urls: string[] = [];
      if (typeof value === 'string') urls.push(value);
      else if (Array.isArray(value)) {
        for (const item of value) if (typeof item === 'string') urls.push(item);
      }
      for (const url of urls) {
        const result = checker.checkUrl(url);
        if (!result.allowed) {
          throw new ScopeViolationError(
            `Tool '${tool.name}' was invoked with a URL outside the engagement scope: ${result.reason}`,
            'SCOPE_VIOLATION',
            { field, code: result.code },
          );
        }
      }
    }
  }

  private withTimeout(promise: Promise<unknown>, ms: number, toolName: string): Promise<unknown> {
    return new Promise((resolve, reject) => {
      const timer = setTimeout(
        () => reject(new TimeoutError(`Tool '${toolName}' timed out after ${ms}ms`, 'TOOL_TIMEOUT')),
        ms,
      );
      timer.unref?.();
      promise.then(
        (value) => {
          clearTimeout(timer);
          resolve(value);
        },
        (error) => {
          clearTimeout(timer);
          reject(error);
        },
      );
    });
  }
}
