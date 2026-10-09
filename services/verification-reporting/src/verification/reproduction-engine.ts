/**
 * Reproduction engine (spec Part 7 §12-§13, §9 Reproduction).
 *
 * TEST -> REPEAT -> COMPARE. Reproduction re-executes the suspect request
 * through the SAME controlled tool infrastructure (scope-validated HTTP
 * engine + traffic recorder + identity session manager), then compares the
 * response semantically against the originally recorded one.
 *
 * Reproduction procedures are stored as CONTROLLED STEP REFERENCES (browser
 * action / HTTP request / identity switch / observation), never as arbitrary
 * executable scripts (§12).
 */
import type { Repositories } from '@aegis/database';
import type { FindingRecord } from '@aegis/database';
import { generateId } from '@aegis/shared';
import type { ControlledHttpPort } from '../ports.js';

export interface ReproductionStepOutcome {
  step: { kind: string; reference: string; description: string };
  executed: boolean;
  status: number | null;
  response_id: string | null;
  evidence_id: string | null;
  error: string | null;
}

export interface ReproductionOutcome {
  planId: string;
  steps: ReproductionStepOutcome[];
  reproduced: boolean;
  /** Semantically similar to the original observation (status + body class). */
  consistent: boolean;
  evidenceIds: string[];
  note: string;
}

export class ReproductionEngine {
  constructor(
    private readonly repos: Repositories,
    private readonly http: ControlledHttpPort,
  ) {}

  /** §12: build a controlled reproduction plan for a finding. */
  async buildPlan(finding: FindingRecord): Promise<{
    id: string;
    prerequisites: string[];
    steps: Array<{ kind: string; reference: string; description: string }>;
    expectedSignals: Array<{ signal: string; source: string }>;
  }> {
    const steps: Array<{ kind: string; reference: string; description: string }> = [];
    const requestRecords = await this.loadSuspectRequests(finding);
    for (const request of requestRecords) {
      steps.push({
        kind: 'HTTP_REQUEST',
        reference: request.id,
        description: `Replay recorded ${request.method} ${request.normalized_url ?? request.url} (identity ${request.identity_id ?? 'anonymous'})`,
      });
    }
    if (steps.length === 0) {
      steps.push({
        kind: 'OBSERVATION',
        reference: finding.id,
        description: 'No recorded request references; reproduce from linked observations when available',
      });
    }
    return {
      id: generateId('RPN'),
      prerequisites: [
        `finding ${finding.id} in a verifiable state`,
        'target reachable under the engagement scope',
        ...(requestRecords.some((r) => r.identity_id)
          ? ['identity session material resolvable (no auto re-auth, §12)']
          : []),
      ],
      steps,
      expectedSignals: [
        { signal: finding.observed_behavior ?? finding.title, source: 'original observation' },
        { signal: 'status code class matches the original response', source: 'response comparison' },
      ],
    };
  }

  /** §9 Reproduction: repeat + compare. */
  async reproduce(finding: FindingRecord): Promise<ReproductionOutcome> {
    const plan = await this.buildPlan(finding);
    const outcomes: ReproductionStepOutcome[] = [];
    const evidenceIds: string[] = [];

    for (const step of plan.steps) {
      if (step.kind !== 'HTTP_REQUEST') {
        outcomes.push({ step, executed: false, status: null, response_id: null, evidence_id: null, error: 'no replayable request reference' });
        continue;
      }
      try {
        const request = (await this.repos.httpRequests.findById(step.reference)) as
          | { id: string; identity_id?: string | null }
          | null;
        if (!request) {
          outcomes.push({ step, executed: false, status: null, response_id: null, evidence_id: null, error: 'request record not found' });
          continue;
        }
        const sent = await this.http.replay({
          engagementId: finding.engagement_id,
          requestId: request.id,
          identityId: request.identity_id ?? null,
          reason: `verification reproduction for finding ${finding.id} (§12)`,
        });
        outcomes.push({
          step,
          executed: true,
          status: sent.status,
          response_id: sent.responseId,
          evidence_id: sent.evidenceId,
          error: null,
        });
        if (sent.evidenceId) evidenceIds.push(sent.evidenceId);
      } catch (error) {
        outcomes.push({
          step,
          executed: false,
          status: null,
          response_id: null,
          evidence_id: null,
          error: error instanceof Error ? error.message : String(error),
        });
      }
    }

    const executed = outcomes.filter((o) => o.executed);
    const original = await this.loadOriginalStatus(finding);
    const consistent =
      executed.length > 0 &&
      executed.every((o) => original === null || statusClass(o.status) === statusClass(original));

    return {
      planId: plan.id,
      steps: outcomes,
      reproduced: executed.length > 0,
      consistent,
      evidenceIds,
      note:
        executed.length === 0
          ? 'No reproduction steps could be executed (no replayable request records)'
          : `Reproduced ${executed.length}/${plan.steps.length} step(s); responses ${consistent ? 'consistent with' : 'DIFFERENT from'} the original observation (§13).`,
    };
  }

  private async loadSuspectRequests(finding: FindingRecord): Promise<Array<{
    id: string;
    method: string;
    url: string;
    normalized_url: string | null;
    identity_id: string | null;
  }>> {
    // Requests referenced by the finding's evidence (via metadata linkage).
    const requests: Array<{ id: string; method: string; url: string; normalized_url: string | null; identity_id: string | null }> = [];
    const seen = new Set<string>();
    for (const evidenceId of finding.evidence_ids) {
      const record = await this.repos.evidence.findById(evidenceId).catch(() => null);
      const requestId = (record?.metadata as Record<string, unknown> | undefined)?.request_id;
      if (typeof requestId === 'string' && !seen.has(requestId)) {
        const row = (await this.repos.httpRequests.findById(requestId).catch(() => null)) as
          | Record<string, unknown>
          | null;
        if (row) {
          seen.add(requestId);
          requests.push({
            id: String(row.id),
            method: String(row.method),
            url: String(row.url),
            normalized_url: (row.normalized_url as string | undefined) ?? null,
            identity_id: (row.identity_id as string | undefined) ?? null,
          });
        }
      }
    }
    return requests;
  }

  private async loadOriginalStatus(finding: FindingRecord): Promise<number | null> {
    for (const evidenceId of [...finding.evidence_ids].reverse()) {
      const record = await this.repos.evidence.findById(evidenceId).catch(() => null);
      const status = (record?.metadata as Record<string, unknown> | undefined)?.status;
      if (typeof status === 'number') return status;
    }
    return null;
  }
}

function statusClass(status: number | null): string {
  if (status === null) return 'unknown';
  if (status < 300) return 'success';
  if (status < 400) return 'redirect';
  if (status < 500) return 'client-error';
  return 'server-error';
}
