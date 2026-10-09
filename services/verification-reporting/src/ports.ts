/**
 * Structural ports for the verification-reporting service.
 *
 * The service is execution-agnostic: concrete infrastructure (HTTP engine,
 * reasoning engine, knowledge) is injected through these seams so the
 * deterministic verification/reporting/evaluation layers stay independently
 * testable (mirrors the Part 6 ReasoningPort/LauncherPort pattern).
 */
import type { VerificationOutcome } from './verification/reasoning-port.js';

export type { VerificationOutcome };

/** Controlled HTTP execution port (same infra as worker tools, §8). */
export interface ControlledHttpPort {
  /** Sends an arbitrary scope-validated request and records the exchange. */
  send(input: {
    engagementId: string;
    method: string;
    url: string;
    headers?: Array<{ name: string; value: string }>;
    body?: string | null;
    identityId: string | null;
    reason: string | null;
  }): Promise<{
    status: number | null;
    requestId: string | null;
    responseId: string | null;
    evidenceId: string | null;
    error: string | null;
  }>;

  /** Replays a recorded request with fresh identity material; scope-validated. */
  replay(input: {
    engagementId: string;
    requestId: string;
    identityId: string | null;
    reason: string | null;
  }): Promise<{
    status: number | null;
    responseId: string | null;
    evidenceId: string | null;
    bodyPreview: string | null;
  }>;
}

/**
 * Part 4 reasoning bridge: ingestion (recorded traffic -> attack-surface
 * intelligence) + the skeptical hypothesis verification (§71-§76).
 */
export interface ReasoningVerificationPort {
  ingest(engagementId: string, limit?: number): Promise<{ ingested: number }>;
  verify(input: {
    engagementId: string;
    hypothesisId: string;
  }): Promise<{
    verificationId: string;
    outcome: VerificationOutcome;
  }>;
}

export interface EngineDeps {
  repos: import('@aegis/database').Repositories;
  eventBus: import('@aegis/events').EventBus;
  logger?: import('@aegis/logging').Logger;
  config: import('@aegis/config').AppConfig;
  http: ControlledHttpPort;
  reasoning: ReasoningVerificationPort;
  /** Object store reference for rendered report artifacts. */
  objectStore: {
    put(key: string, content: Buffer | string): Promise<void>;
    get(key: string): Promise<Buffer | null>;
  };
}
