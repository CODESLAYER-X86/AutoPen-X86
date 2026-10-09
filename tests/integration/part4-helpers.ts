/**
 * Part 4 integration helpers: composes the reasoning engine over the real
 * interaction stack (Part 3 helpers) plus the deterministic reasoning
 * processor, seeded engagements and logged-in sessions against the lab app.
 */
import type { Pool } from 'pg';
import type { Repositories } from '@aegis/database';
import { SecurityReasoningEngine } from '@aegis/reasoning';
import { createPart4Tools } from '@aegis/toolbox';
import { ToolGateway, createDefaultToolRegistry } from '@aegis/tools';
import { buildInteractionStack, gatewayContext, type InteractionStack } from './part3-helpers.js';

export interface ReasoningStack {
  interaction: InteractionStack;
  repos: Repositories;
  pool: Pool;
  reasoning: SecurityReasoningEngine;
  stopReasoning: () => void;
  reasoningGateway: ToolGateway;
  close(): Promise<void>;
}

export async function buildReasoningStack(options: { pool: Pool }): Promise<ReasoningStack> {
  const interaction = await buildInteractionStack({ pool: options.pool });
  const reasoning = new SecurityReasoningEngine({
    repos: interaction.repos,
    eventBus: interaction.eventBus,
  });
  // Event-driven integration (§109): derived state updates as traffic lands.
  const stopReasoning = reasoning.processor.subscribe();

  // Worker-facing reasoning tools (§80, §118, §72) behind their own gateway
  // so tests can exercise the exact permission/scope path workers use.
  const reasoningRegistry = createDefaultToolRegistry();
  reasoningRegistry.registerAll(
    createPart4Tools({
      reasoning,
      repos: interaction.repos,
      eventBus: interaction.eventBus,
    }),
  );
  const reasoningGateway = new ToolGateway(reasoningRegistry);

  return {
    interaction,
    repos: interaction.repos,
    pool: interaction.pool,
    reasoning,
    stopReasoning,
    reasoningGateway,
    close: async () => {
      stopReasoning();
      await interaction.close();
    },
  };
}

export { seedEngagement, gatewayContext } from './part3-helpers.js';

/**
 * Log in to the lab app as a user through the REAL tool gateway (the same
 * http.request path workers use) and register the resulting session with
 * the session manager (§28) so later requests with identity_id get the
 * auth injected automatically. The exchange is recorded like any worker
 * traffic (feeding the reasoning processor).
 */
export async function loginSession(
  stack: ReasoningStack,
  engagementId: string,
  identityId: string,
  username: string,
  password: string,
): Promise<void> {
  // Login via the engine (the auth workflow + session registration are the
  // platform's durable record of the login; the auth-workflow row feeds the
  // reasoning backfill's authentication-boundary detection).
  const exchange = await stack.interaction.engine.send(
    {
      engagementId,
      method: 'POST',
      url: `${stack.interaction.lab.url}/login`,
      headers: [{ name: 'content-type', value: 'application/x-www-form-urlencoded' }],
      body: { body_type: 'FORM_URLENCODED', fields: [{ name: 'username', value: username }, { name: 'password', value: password }] },
      identityId: null,
    },
    stack.interaction.scope,
  );
  if (exchange.response.status !== 200) {
    throw new Error(`login failed for ${username}: HTTP ${exchange.response.status}`);
  }
  const setCookie = (exchange.response.headers as Array<{ name: string; value: string }>).find(
    (header) => header.name.toLowerCase() === 'set-cookie',
  );
  const token = /LABSESS=([^;]+)/.exec(setCookie?.value ?? '')?.[1] ?? '';
  if (!token) {
    throw new Error(`login failed for ${username}: no session cookie`);
  }

  // Register the session for the identity (§28) — production flow.
  await stack.interaction.sessionManager.registerAuthState({
    engagementId,
    identityId,
    material: {
      kind: 'COOKIE',
      cookies: [
        {
          name: 'LABSESS',
          value: token,
          domain: stack.interaction.lab.host,
          path: '/',
          secure: false,
          httpOnly: true,
          sameSite: 'Lax',
          expires: null,
        },
      ],
    },
    workflow: { steps: [{ action: 'login', detail: `form login as ${username}`, success: true }] },
  });
}

/** Execute a recorded GET request as an identity (auth auto-injected). */
export async function getAs(
  stack: ReasoningStack,
  engagementId: string,
  identityId: string | null,
  path: string,
): Promise<{ requestId: string; status: number; body: unknown }> {
  const result = await stack.interaction.gateway.execute(
    'http.request',
    {
      method: 'GET',
      url: `${stack.interaction.lab.url}${path}`,
      identity_id: identityId,
    },
    gatewayContext(stack.interaction, engagementId, { identityId }),
  );
  if (!result.ok) {
    throw new Error(`request failed for ${path}: ${result.error?.code ?? 'unknown'}`);
  }
  const output = result.output as { request_id: string; status: number; body_preview: string | null };
  return {
    requestId: output.request_id,
    status: output.status,
    body: output.body_preview ? JSON.parse(output.body_preview) : null,
  };
}

/** Execute a recorded POST request (empty JSON body) as an identity. */
export async function postAs(
  stack: ReasoningStack,
  engagementId: string,
  identityId: string | null,
  path: string,
): Promise<{ requestId: string; status: number; body: unknown }> {
  const result = await stack.interaction.gateway.execute(
    'http.request',
    {
      method: 'POST',
      url: `${stack.interaction.lab.url}${path}`,
      headers: [{ name: 'content-type', value: 'application/json' }],
      body: { body_type: 'JSON', data: {} },
      identity_id: identityId,
    },
    gatewayContext(stack.interaction, engagementId, { identityId }),
  );
  if (!result.ok) {
    throw new Error(`request failed for ${path}: ${result.error?.code ?? 'unknown'}`);
  }
  const output = result.output as { request_id: string; status: number; body_preview: string | null };
  return {
    requestId: output.request_id,
    status: output.status,
    body: output.body_preview ? JSON.parse(output.body_preview) : null,
  };
}

/** Drain pending async event processing (§109 subscribe path). */
export async function settle(ms = 250): Promise<void> {
  await new Promise((resolve) => setTimeout(resolve, ms));
}
