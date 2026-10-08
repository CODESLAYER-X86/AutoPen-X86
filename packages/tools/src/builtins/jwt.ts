/**
 * parser.jwt — a genuinely deterministic, implemented tool (Part 1).
 *
 * DECODE ONLY: header + payload are base64url-decoded and structurally
 * validated. Signature verification is explicitly NOT performed (that is
 * the job of a future verification module with the right key material).
 * The tool flags `alg: none` and expiry for the caller.
 */
import { z } from 'zod';
import { ValidationError } from '@aegis/shared';
import type { ToolDefinition } from '../types.js';

const InputSchema = z
  .object({
    token: z.string().min(10).max(8192),
  })
  .strict();

const OutputSchema = z.object({
  header: z.record(z.unknown()),
  payload: z.record(z.unknown()),
  signature_present: z.boolean(),
  expired: z.boolean(),
  warnings: z.array(z.string()),
});

function decodeSegment(segment: string, label: string): Record<string, unknown> {
  if (segment === '') {
    throw new ValidationError(`JWT ${label} segment is empty`, 'JWT_MALFORMED');
  }
  let json: string;
  try {
    json = Buffer.from(segment, 'base64url').toString('utf8');
  } catch {
    throw new ValidationError(`JWT ${label} segment is not valid base64url`, 'JWT_MALFORMED');
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(json);
  } catch {
    throw new ValidationError(`JWT ${label} segment is not valid JSON`, 'JWT_MALFORMED');
  }
  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
    throw new ValidationError(`JWT ${label} segment must be a JSON object`, 'JWT_MALFORMED');
  }
  return parsed as Record<string, unknown>;
}

export const jwtDecodeTool: ToolDefinition = {
  name: 'parser.jwt',
  version: '1.0.0',
  description:
    'Decodes a JWT (JWS compact serialization) header and payload without signature verification. ' +
    'Reports alg, expiry and structural warnings. Deterministic parsing only.',
  riskLevel: 'LOW',
  capabilities: ['READ_ONLY'],
  requiresScope: false,
  implemented: true,
  timeoutMs: 5_000,
  inputSchema: InputSchema,
  outputSchema: OutputSchema,
  async execute(input: unknown): Promise<unknown> {
    const { token } = InputSchema.parse(input);
    const parts = token.trim().split('.');
    if (parts.length < 2 || parts.length > 3) {
      throw new ValidationError(
        'Token does not have the JWS compact serialization form (header.payload[.signature])',
        'JWT_MALFORMED',
      );
    }

    const header = decodeSegment(parts[0]!, 'header');
    const payload = decodeSegment(parts[1]!, 'payload');

    if (typeof header.alg !== 'string' || header.alg.length === 0) {
      throw new ValidationError('JWT header is missing the "alg" field', 'JWT_MALFORMED');
    }

    const warnings: string[] = [];
    if (header.alg === 'none') {
      warnings.push('Unsecured JWT: alg=none (no signature)');
    }
    if (parts.length === 3 && parts[2] !== '' && header.alg === 'none') {
      warnings.push('alg=none but a signature segment is present (suspicious)');
    }

    const exp = payload.exp;
    const expired =
      typeof exp === 'number' && Number.isFinite(exp) ? exp * 1000 < Date.now() : false;
    if (typeof exp !== 'number') {
      warnings.push('Payload has no numeric "exp" claim');
    }

    return {
      header,
      payload,
      signature_present: parts.length === 3 && parts[2] !== '',
      expired,
      warnings,
    };
  },
};
