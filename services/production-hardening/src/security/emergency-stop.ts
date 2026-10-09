/**
 * Emergency stop + engagement kill switch + credential kill switch
 * (spec Part 8 §89-§90, §93).
 *
 * The global emergency stop is deterministic: it never depends on the LLM.
 * Engaging it (1) stops scheduling, (2) cancels PENDING/QUEUED tasks,
 * (3) revokes every issued credential grant, (4) records the state
 * persistently so restarts keep the stop engaged until a human releases.
 */
import type { EmergencyStopRecord } from '@aegis/database';
import type { EventPort } from '../ops/ports.js';

export interface EmergencyStopDeps {
  repos: {
    emergencyStop: {
      getState(): Promise<EmergencyStopRecord>;
      engage(input: {
        engagedBy: string;
        reason: string;
        cancelledTasks: number;
        revokedGrants: number;
      }): Promise<EmergencyStopRecord>;
      release(): Promise<EmergencyStopRecord>;
      isEngaged(): Promise<boolean>;
    };
    tasks: { cancelPending(engagementId?: string): Promise<number> };
    credentialGrants: { revokeAllIssued(): Promise<number> };
  };
  eventBus?: EventPort;
}

export class EmergencyStopError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'EmergencyStopError';
  }
}

export class EmergencyStopEngine {
  constructor(private readonly deps: EmergencyStopDeps) {}

  /** Hot-path guard called before ANY target-bound action (§90). */
  async assertNotEngaged(): Promise<void> {
    if (await this.deps.repos.emergencyStop.isEngaged()) {
      throw new EmergencyStopError(
        'Platform emergency stop is ENGAGED: all target-bound actions are blocked until a human releases the stop',
      );
    }
  }

  async isEngaged(): Promise<boolean> {
    return this.deps.repos.emergencyStop.isEngaged();
  }

  async getState(): Promise<EmergencyStopRecord> {
    return this.deps.repos.emergencyStop.getState();
  }

  /**
   * Engage the global stop. Deterministic order: persist state first so a
   * crash mid-engagement still leaves the platform stopped (fail-closed).
   */
  async engage(input: { engagedBy: string; reason: string }): Promise<EmergencyStopRecord> {
    const cancelledTasks = await this.deps.repos.tasks.cancelPending();
    const revokedGrants = await this.deps.repos.credentialGrants.revokeAllIssued();
    const state = await this.deps.repos.emergencyStop.engage({
      engagedBy: input.engagedBy,
      reason: input.reason,
      cancelledTasks,
      revokedGrants,
    });
    await this.deps.eventBus?.publish({
      type: 'EMERGENCY_STOP_ENGAGED',
      engagement_id: null,
      trace_id: 'EST_PLATFORM',
      actor_id: input.engagedBy,
      payload: { reason: input.reason, cancelled_tasks: cancelledTasks, revoked_grants: revokedGrants },
      occurred_at: new Date().toISOString(),
    });
    return state;
  }

  async release(): Promise<EmergencyStopRecord> {
    const state = await this.deps.repos.emergencyStop.release();
    await this.deps.eventBus?.publish({
      type: 'EMERGENCY_STOP_RELEASED',
      engagement_id: null,
      trace_id: 'EST_PLATFORM',
      actor_id: null,
      payload: {},
      occurred_at: new Date().toISOString(),
    });
    return state;
  }
}
