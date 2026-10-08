/**
 * Target HTTP client interface (spec §3 — HTTP Worker).
 *
 * Part 1 defines the contract only. The implementation (Part 3) will route
 * every request through the ToolGateway + scope checker and record
 * request/response evidence. This factory returns an object that fails
 * fast with an explicit NotImplementedError instead of pretending.
 */
import { NotImplementedError } from '@aegis/shared';

export interface TargetHttpRequest {
  method: string;
  url: string;
  headers?: Record<string, string>;
  body?: Uint8Array | string | null;
  identity_id?: string | null;
}

export interface TargetHttpResponse {
  status: number;
  headers: Record<string, string[]>;
  body: Uint8Array;
  duration_ms: number;
}

export interface TargetHttpClient {
  send(request: TargetHttpRequest): Promise<TargetHttpResponse>;
}

export function createNotImplementedTargetHttpClient(): TargetHttpClient {
  return {
    async send(): Promise<TargetHttpResponse> {
      throw new NotImplementedError(
        'The HTTP worker is not implemented in Part 1; it is the subject of Part 3',
        'HTTP_WORKER_NOT_IMPLEMENTED',
      );
    },
  };
}
