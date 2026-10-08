/**
 * Typed API client. Every response is validated against the shared zod
 * contracts — a contract drift between backend and frontend fails loudly
 * instead of rendering garbage.
 */
import type { z } from 'zod';

const TOKEN_KEY = 'aegis_token';

export class ApiError extends Error {
  readonly code: string;
  readonly status: number;
  readonly details?: unknown;

  constructor(code: string, message: string, status: number, details?: unknown) {
    super(message);
    this.name = 'ApiError';
    this.code = code;
    this.status = status;
    this.details = details;
  }
}

export function getToken(): string | null {
  try {
    return localStorage.getItem(TOKEN_KEY);
  } catch {
    return null;
  }
}

export function setToken(token: string | null): void {
  try {
    if (token === null) localStorage.removeItem(TOKEN_KEY);
    else localStorage.setItem(TOKEN_KEY, token);
  } catch {
    /* storage unavailable */
  }
}

export async function apiRequest<S extends z.ZodTypeAny>(
  method: 'GET' | 'POST' | 'PATCH' | 'DELETE',
  path: string,
  schema: S,
  body?: unknown,
): Promise<z.output<S>> {
  const headers: Record<string, string> = {};
  if (body !== undefined) headers['content-type'] = 'application/json';
  const token = getToken();
  if (token) headers.authorization = `Bearer ${token}`;

  let response: Response;
  try {
    response = await fetch(path, {
      method,
      headers,
      body: body === undefined ? undefined : JSON.stringify(body),
    });
  } catch {
    throw new ApiError('NETWORK_ERROR', 'Could not reach the API server', 0);
  }

  if (response.status === 204) {
    return undefined as z.output<S>;
  }

  let json: unknown;
  try {
    json = await response.json();
  } catch {
    throw new ApiError(
      'BAD_RESPONSE',
      `Unexpected non-JSON response (HTTP ${response.status})`,
      response.status,
    );
  }

  if (!response.ok) {
    const errorBody = (json as { error?: { code?: string; message?: string; details?: unknown } })
      .error;
    throw new ApiError(
      errorBody?.code ?? 'UNKNOWN_ERROR',
      errorBody?.message ?? `Request failed (HTTP ${response.status})`,
      response.status,
      errorBody?.details,
    );
  }

  const parsed = schema.safeParse(json);
  if (!parsed.success) {
    throw new ApiError(
      'CONTRACT_MISMATCH',
      'API response failed schema validation (frontend/backend contract drift)',
      response.status,
      parsed.error.issues.map((issue) => `${issue.path.join('.') || '(root)'}: ${issue.message}`),
    );
  }
  return parsed.data;
}
