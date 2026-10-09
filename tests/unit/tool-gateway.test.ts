import { describe, expect, it } from 'vitest';
import { z } from 'zod';
import { ValidationError, type ToolCapability } from '@aegis/shared';
import { jwtDecodeTool, ToolGateway, ToolRegistry, createDefaultToolRegistry } from '@aegis/tools';
import type { ToolDefinition, ToolExecutionContext } from '@aegis/tools';

function baseContext(overrides: Partial<ToolExecutionContext> = {}): ToolExecutionContext {
  return {
    permissions: { network: false, browser: false, destructive: false },
    ...overrides,
  };
}


/** Local fake NETWORK tool (was: http.request stub — real since Part 3). */
function fakeNetworkTool(): ToolDefinition {
  return {
    name: 'test.network.op',
    version: '1.0.0',
    description: 'Deterministic fake network tool for gateway tests',
    inputSchema: z.object({ url: z.string() }),
    outputSchema: z.object({ status: z.number() }),
    riskLevel: 'MEDIUM',
    capabilities: ['NETWORK', 'READ_ONLY'],
    requiresScope: true,
    urlFields: ['url'],
    implemented: true,
    async execute(): Promise<unknown> {
      return { status: 200 };
    },
  };
}

describe('tool registry metadata validation (spec §33)', () => {
  it('rejects invalid tool names', () => {
    const registry = new ToolRegistry();
    expect(() =>
      registry.register({ ...jwtDecodeTool, name: 'Not Dotted' }),
    ).toThrowError(ValidationError);
    expect(() => registry.register({ ...jwtDecodeTool, name: 'shell' })).toThrowError(ValidationError);
  });

  it('rejects non-semver versions', () => {
    const registry = new ToolRegistry();
    expect(() => registry.register({ ...jwtDecodeTool, version: '1' })).toThrowError(ValidationError);
  });

  it('rejects unknown capabilities and duplicates', () => {
    const registry = new ToolRegistry();
    expect(() =>
      registry.register({ ...jwtDecodeTool, capabilities: ['NETWORK', 'TELEPATHY' as unknown as ToolCapability] }),
    ).toThrowError(ValidationError);
    registry.register(jwtDecodeTool);
    expect(() => registry.register(jwtDecodeTool)).toThrowError(ValidationError);
  });

  it('rejects implemented tools without an execute function', () => {
    const registry = new ToolRegistry();
    expect(() =>
      registry.register({ ...jwtDecodeTool, execute: undefined as unknown as () => Promise<unknown> }),
    ).toThrowError(ValidationError);
  });

  it('lists descriptors with implemented flags', () => {
    const registry = createDefaultToolRegistry();
    const descriptors = registry.list();
    expect(descriptors.length).toBeGreaterThan(5);
    expect(descriptors.filter((tool) => tool.implemented)).toHaveLength(1); // parser.jwt
    // Part 3: interaction tools are implemented by @aegis/toolbox and
    // registered by the composition root, not the base registry.
    expect(descriptors.find((tool) => tool.name === 'http.request')).toBeUndefined();
    expect(descriptors.find((tool) => tool.name === 'browser.navigate')).toBeUndefined();
  });

  it('requires() throws a typed error for hallucinated names', () => {
    const registry = createDefaultToolRegistry();
    expect(() => registry.require('shell.exec')).toThrowError(ValidationError);
    expect(() => registry.require('http.request.but.faked')).toThrowError(ValidationError);
  });
});

describe('tool gateway (spec §17: model output cannot execute directly)', () => {
  it('rejects unknown tools — hallucinated names die at the gate', async () => {
    const gateway = new ToolGateway(createDefaultToolRegistry());
    const result = await gateway.execute('rm.rf.everything', {}, baseContext());
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error.code).toBe('TOOL_NOT_FOUND');
  });

  it('rejects execution of registered-but-unimplemented tools with 501 semantics', async () => {
    const gateway = new ToolGateway(createDefaultToolRegistry());
    const result = await gateway.execute('knowledge.search', { query: 'x' }, baseContext());
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error.code).toBe('TOOL_NOT_IMPLEMENTED');
      expect(result.error.message).toMatch(/Part/);
    }
  });

  it('rejects schema-invalid input arguments', async () => {
    const gateway = new ToolGateway(createDefaultToolRegistry());
    const result = await gateway.execute('parser.jwt', { token: 12345 }, baseContext());
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error.code).toBe('TOOL_INPUT_INVALID');
  });

  it('executes the deterministic jwt parser successfully', async () => {
    const gateway = new ToolGateway(createDefaultToolRegistry());
    const token = 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0GEsJi0';
    const result = await gateway.execute('parser.jwt', { token }, baseContext());
    expect(result.ok).toBe(true);
    if (result.ok) {
      const output = result.output as {
        header: Record<string, unknown>;
        payload: Record<string, unknown>;
        signature_present: boolean;
      };
      expect(output.header.alg).toBe('HS256');
      expect(output.payload.sub).toBe('1234567890');
      expect(output.signature_present).toBe(true);
    }
  });

  it('flags unsecured alg=none tokens', async () => {
    const gateway = new ToolGateway(createDefaultToolRegistry());
    const token = 'eyJhbGciOiJub25lIn0.eyJzdWIiOiIxMjM0NTY3ODkwIn0.';
    const result = await gateway.execute('parser.jwt', { token }, baseContext());
    expect(result.ok).toBe(true);
    if (result.ok) {
      const output = result.output as { warnings: string[]; signature_present: boolean };
      expect(output.warnings.join(' ')).toMatch(/alg=none/i);
      expect(output.signature_present).toBe(false);
    }
  });

  it('rejects structurally invalid JWTs', async () => {
    const gateway = new ToolGateway(createDefaultToolRegistry());
    const result = await gateway.execute('parser.jwt', { token: 'not.a.jwt.at.all.AT.ALL' }, baseContext());
    expect(result.ok).toBe(false);
  });

  it('rejects NETWORK tools when the network permission is absent', async () => {
    const registry = new ToolRegistry();
    registry.register(fakeNetworkTool());
    const gateway = new ToolGateway(registry);
    const result = await gateway.execute('test.network.op', { url: 'http://localhost:8080/' }, baseContext());
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error.code).toBe('TOOL_NETWORK_FORBIDDEN');
  });

  it('rejects NETWORK tools when no scope is configured', async () => {
    const registry = new ToolRegistry();
    registry.register(fakeNetworkTool());
    const gateway = new ToolGateway(registry);
    const result = await gateway.execute(
      'test.network.op',
      { url: 'http://localhost:8080/' },
      baseContext({ permissions: { network: true, browser: false, destructive: false } }),
    );
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error.code).toBe('SCOPE_NOT_CONFIGURED');
  });

  it('rejects NETWORK tool calls whose URL is outside scope', async () => {
    const registry = new ToolRegistry();
    registry.register(fakeNetworkTool());
    const gateway = new ToolGateway(registry);
    const result = await gateway.execute(
      'test.network.op',
      { url: 'http://evil.attacker.com/admin' },
      baseContext({
        permissions: { network: true, browser: false, destructive: false },
        scope: {
          allowed_hosts: ['localhost'],
          allowed_domains: [],
          allowed_ports: [8080],
          allowed_schemes: ['http'],
          excluded_hosts: [],
          excluded_paths: [],
          rate_limit: null,
          concurrency_limit: null,
          destructive_actions_allowed: false,
        },
      }),
    );
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error.code).toBe('SCOPE_VIOLATION');
  });

  it('rejects DESTRUCTIVE tools unless the engagement permits them', async () => {
    const registry = new ToolRegistry();
    registry.register({
      ...fakeNetworkTool(),
      name: 'test.destructive.op',
      capabilities: ['MUTATION', 'DESTRUCTIVE'],
      urlFields: undefined,
      inputSchema: z.object({}).passthrough(),
    });
    const gateway = new ToolGateway(registry);
    const denied = await gateway.execute('test.destructive.op', {}, baseContext());
    expect(denied.ok).toBe(false);
    if (!denied.ok) expect(denied.error.code).toBe('TOOL_DESTRUCTIVE_FORBIDDEN');

    const allowed = await gateway.execute(
      'test.destructive.op',
      {},
      baseContext({ permissions: { network: false, browser: false, destructive: true } }),
    );
    expect(allowed.ok).toBe(true);
  });

  it('validates tool OUTPUT against the declared schema (defense in depth)', async () => {
    const registry = new ToolRegistry();
    registry.register({
      ...jwtDecodeTool,
      name: 'parser.jwt.bad',
      async execute(): Promise<unknown> {
        return { not: 'the declared shape' };
      },
    });
    const gateway = new ToolGateway(registry);
    const result = await gateway.execute(
      'parser.jwt.bad',
      { token: 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0GEsJi0' },
      baseContext(),
    );
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error.code).toBe('TOOL_OUTPUT_INVALID');
  });
});
