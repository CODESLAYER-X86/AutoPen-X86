/**
 * Flag-condition analyzer (spec Part 6 §31).
 *
 * Distinguishes "interesting behavior" from "challenge solved". A challenge
 * may only become SOLVED when evidence exists that the SUCCESS CONDITION
 * was satisfied: flag pattern observed, challenge-specific success
 * response, explicit success state, validated flag artifact, or
 * server-confirmed completion.
 *
 * Scanning is deterministic over bounded observation text, response
 * previews, DOM snapshot text and storage values. Detected values become
 * flag evidence (§31) — never a bare model claim.
 */
import type { Repositories } from '@aegis/database';
import { generateId, type FlagEvidenceKind } from '@aegis/shared';
import type { PlatformEvent } from '@aegis/contracts';
import type { EventBus } from '@aegis/events';

export interface FlagDetection {
  value: string;
  evidenceIds: string[];
  kinds: FlagEvidenceKind[];
  where: string;
}

export class FlagConditionAnalyzer {
  private readonly patterns: RegExp[];

  constructor(
    private readonly deps: { repos: Repositories; eventBus: EventBus },
    flagPatternsCsv: string,
  ) {
    // Default patterns: flag{...}, CTF{...}, aegis{...} — configurable (§31).
    const sources = flagPatternsCsv
      .split(',')
      .map((pattern) => pattern.trim())
      .filter((pattern) => pattern.length > 0);
    this.patterns = sources.map((source) => {
      try {
        return new RegExp(source, 'i');
      } catch {
        return /flag\{[^\s]{4,128}\}/i;
      }
    });
  }

  /** Patterns compiled from config + the challenge's declared format (§31). */
  withDeclaredFormat(declared: string | null): RegExp[] {
    if (!declared || declared.trim().length === 0) return this.patterns;
    let declaredPattern: RegExp;
    const body = declared.includes('(') ? declared : declared.replace(/[.*+?^${}()|[\]\\]/g, (match) => {
      // Treat bare "flag{...}" style declarations as a pattern body.
      void match;
      return '';
    });
    try {
      declaredPattern = declared.includes('(') ? new RegExp(declared, 'i') : new RegExp(`${declared}`, 'i');
    } catch {
      return this.patterns;
    }
    void body;
    return [declaredPattern, ...this.patterns];
  }

  /**
   * Scan recorded evidence for flag patterns (§31). Bounded to recent
   * observations, response previews, DOM snapshots and storage entries.
   */
  async scan(engagementId: string, declaredFormat: string | null): Promise<FlagDetection[]> {
    const patterns = this.withDeclaredFormat(declaredFormat);
    const detections: FlagDetection[] = [];
    const seen = new Set<string>();

    const observations = await safe(() => this.deps.repos.observations.listByEngagement(engagementId, 60));
    for (const observation of observations) {
      const text = `${observation.description} ${JSON.stringify(observation.metadata ?? {})}`;
      const found = this.match(text, patterns);
      for (const value of found) {
        if (seen.has(value)) continue;
        seen.add(value);
        detections.push({
          value,
          evidenceIds: observation.evidence_ids ?? [],
          kinds: ['FLAG_PATTERN_OBSERVED'],
          where: `observation ${observation.id}`,
        });
      }
    }

    const responses = await safe(() => this.deps.repos.httpResponses.listByEngagement(engagementId, 60));
    for (const response of responses) {
      const preview = typeof response.body_preview === 'string' ? response.body_preview : '';
      if (!preview) continue;
      const found = this.match(preview, patterns);
      for (const value of found) {
        if (seen.has(value)) continue;
        seen.add(value);
        detections.push({
          value,
          evidenceIds: [],
          kinds: ['SUCCESS_RESPONSE'],
          where: `http response ${String(response.request_id ?? '')}`,
        });
      }
    }

    const snapshots = await safe(() => this.deps.repos.domSnapshots.listByEngagement(engagementId, 30));
    for (const snapshot of snapshots) {
      const text = JSON.stringify(snapshot.snapshot ?? {});
      const found = this.match(text, patterns);
      for (const value of found) {
        if (seen.has(value)) continue;
        seen.add(value);
        detections.push({
          value,
          evidenceIds: typeof snapshot.evidence_id === 'string' ? [snapshot.evidence_id] : [],
          kinds: ['EXPLICIT_SUCCESS_STATE'],
          where: `dom snapshot ${String(snapshot.id ?? '')}`,
        });
      }
    }

    const storage = await safe(() => this.deps.repos.storageEntries.listByEngagement(engagementId));
    for (const entry of storage) {
      const text = `${String((entry as Record<string, unknown>).key ?? '')}=${String((entry as Record<string, unknown>).value_redacted ?? '')}`;
      const found = this.match(text, patterns);
      for (const value of found) {
        if (seen.has(value)) continue;
        seen.add(value);
        detections.push({
          value,
          evidenceIds: [],
          kinds: ['VALIDATED_FLAG_ARTIFACT'],
          where: `storage entry ${String((entry as Record<string, unknown>).id ?? '')}`,
        });
      }
    }

    return detections.slice(0, 10);
  }

  /**
   * Record a flag detection: flag condition -> DETECTED, ctf context ->
   * SOLVED, CHALLENGE_SOLVED event (§31). Only called with concrete
   * pattern-observed evidence.
   */
  async recordDetection(engagementId: string, detection: FlagDetection): Promise<void> {
    const conditions = await this.deps.repos.flagConditions.listByEngagement(engagementId);
    const condition =
      conditions.find((c) => c.status === 'HYPOTHESIZED' || c.status === 'SUPPORTED') ?? null;
    if (condition) {
      await this.deps.repos.flagConditions.markDetected(
        condition.id,
        detection.value,
        detection.evidenceIds,
        detection.kinds,
      );
    } else {
      await this.deps.repos.flagConditions.create({
        engagementId,
        description: `Flag pattern observed in ${detection.where} (§31: success condition evidence)`,
        pattern: null,
      });
      const created = await this.deps.repos.flagConditions.listByEngagement(engagementId);
      const latest = created[0];
      if (latest && latest.status === 'HYPOTHESIZED') {
        await this.deps.repos.flagConditions.markDetected(
          latest.id,
          detection.value,
          detection.evidenceIds,
          detection.kinds,
        );
      }
    }
    await this.deps.repos.ctfContexts.markSolved(engagementId, detection.value, detection.evidenceIds[0] ?? null, 'SOLVED');
    const event: PlatformEvent = {
      type: 'CHALLENGE_SOLVED',
      engagement_id: engagementId,
      trace_id: generateId('TRC'),
      actor_id: null,
      payload: {
        flag_pattern: 'detected',
        evidence_kinds: detection.kinds,
        where: detection.where,
      },
      occurred_at: new Date().toISOString(),
      dedup_key: `challenge-solved:${engagementId}`,
    };
    await this.deps.eventBus.publish(event).catch(() => undefined);
  }

  private match(text: string, patterns: RegExp[]): string[] {
    const found: string[] = [];
    for (const pattern of patterns) {
      const matches = text.match(new RegExp(pattern.source, 'gi'));
      if (matches) {
        for (const match of matches.slice(0, 4)) {
          if (match.length <= 256) found.push(match);
        }
      }
    }
    return found;
  }
}

/** Failure-isolated helper (§113-style degradation for the scan loop). */
async function safe<T>(fn: () => Promise<T[]>): Promise<T[]> {
  try {
    return await fn();
  } catch {
    return [];
  }
}
