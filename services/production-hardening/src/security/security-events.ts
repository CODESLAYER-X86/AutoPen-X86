/**
 * Security events + incident timeline engine (spec Part 8 §94-§96).
 *
 * Deterministic generation: platform control points (scope gateway,
 * tool gateway, credential resolution, prompt-injection detector) raise
 * security events; HIGH/CRITICAL bursts automatically open incidents.
 * The incident timeline (events -> actors -> affected resources -> actions)
 * is reconstructable from these records alone.
 */
import type {
  CircuitBreakerRecord,
  EmergencyStopRecord,
  IncidentRecord,
  SecurityEventRecord,
} from '@aegis/database';
import type { EventPort } from '../ops/ports.js';

export interface HardeningDeps {
  repos: {
    securityEvents: {
      create(input: {
        severity: SecurityEventRecord['severity'];
        category: string;
        actor: SecurityEventRecord['actor'];
        engagementId?: string | null;
        description: string;
        metadata?: Record<string, unknown>;
      }): Promise<SecurityEventRecord>;
      listUnlinkedSince(sinceMinutes: number, limit: number): Promise<SecurityEventRecord[]>;
      attachToIncident(ids: string[], incidentId: string): Promise<number>;
      list(input: { severity?: string; engagementId?: string; limit: number }): Promise<SecurityEventRecord[]>;
      countByCategorySince(category: string, sinceMinutes: number): Promise<number>;
    };
    incidents: {
      open(input: {
        severity: IncidentRecord['severity'];
        title: string;
        eventIds: string[];
      }): Promise<IncidentRecord>;
      listOpen(): Promise<IncidentRecord[]>;
      updateStatus(id: string, status: string): Promise<IncidentRecord | null>;
      findById(id: string): Promise<IncidentRecord | null>;
    };
    circuitBreakers: {
      recordViolation(input: {
        subject: 'AGENT' | 'MODEL';
        subjectId: string;
        engagementId?: string | null;
        category: string;
        threshold: number;
      }): Promise<CircuitBreakerRecord>;
      listOpen(): Promise<CircuitBreakerRecord[]>;
      reset(id: string): Promise<CircuitBreakerRecord | null>;
    };
    emergencyStop: {
      getState(): Promise<EmergencyStopRecord>;
      isEngaged(): Promise<boolean>;
    };
  };
  eventBus?: EventPort;
}

/** §95 severity defaults per category — platform control points rely on these. */
export const CATEGORY_SEVERITY_DEFAULTS: Record<string, SecurityEventRecord['severity']> = {
  PROMPT_INJECTION_DETECTED: 'LOW',
  REPEATED_MALFORMED_MODEL_OUTPUT: 'MEDIUM',
  OUT_OF_SCOPE_TOOL_EXECUTION: 'HIGH',
  SCOPE_DENIAL: 'LOW',
  CREDENTIAL_EXPOSURE_SUSPECTED: 'CRITICAL',
  CROSS_TENANT_ACCESS_ATTEMPT: 'CRITICAL',
  WORKER_COMPROMISE_SUSPECTED: 'CRITICAL',
  EMERGENCY_STOP: 'HIGH',
  CIRCUIT_BREAKER_TRIPPED: 'MEDIUM',
  UNEXPECTED_EGRESS: 'HIGH',
  TOOL_VALIDATION_FAILURE: 'LOW',
  AUTHENTICATION_ANOMALY: 'MEDIUM',
};

/** §96: HIGH/CRITICAL events inside this window auto-open an incident. */
const INCIDENT_WINDOW_MINUTES = 30;

export class SecurityEventsEngine {
  constructor(private readonly deps: HardeningDeps) {}

  /**
   * Raise a security event. Severity is chosen by the caller but never
   * below the category floor (a control point cannot downgrade a
   * CRITICAL category to INFO).
   */
  async raise(input: {
    category: string;
    actor: SecurityEventRecord['actor'];
    engagementId?: string | null;
    description: string;
    severity?: SecurityEventRecord['severity'];
    metadata?: Record<string, unknown>;
  }): Promise<SecurityEventRecord> {
    const floor = CATEGORY_SEVERITY_DEFAULTS[input.category] ?? 'LOW';
    const severity = minSeverity(input.severity ?? floor, floor);
    const record = await this.deps.repos.securityEvents.create({
      severity,
      category: input.category,
      actor: input.actor,
      engagementId: input.engagementId ?? null,
      description: input.description,
      metadata: input.metadata,
    });
    await this.deps.eventBus?.publish({
      type: 'SECURITY_EVENT_RAISED',
      engagement_id: input.engagementId ?? null,
      trace_id: record.id,
      actor_id: null,
      payload: { severity, category: input.category },
      occurred_at: new Date().toISOString(),
    });
    // §96: auto-correlate HIGH/CRITICAL events into an incident.
    if (severity === 'HIGH' || severity === 'CRITICAL') {
      await this.maybeOpenIncident();
    }
    return record;
  }

  /** Open an incident for unlinked HIGH/CRITICAL events in the window. */
  async maybeOpenIncident(): Promise<IncidentRecord | null> {
    const unlinked = await this.deps.repos.securityEvents.listUnlinkedSince(
      INCIDENT_WINDOW_MINUTES,
      100,
    );
    if (unlinked.length === 0) return null;
    const worst = unlinked.reduce(
      (acc, event) => (severityRank(event.severity) > severityRank(acc) ? event.severity : acc),
      'LOW' as SecurityEventRecord['severity'],
    );
    const severity = (worst === 'INFO' ? 'LOW' : worst) as IncidentRecord['severity'];
    return this.deps.repos.incidents.open({
      severity,
      title: `Auto-correlated ${unlinked.length} ${severity} security event(s) in the last ${INCIDENT_WINDOW_MINUTES} minutes`,
      eventIds: unlinked.map((event) => event.id),
    });
  }

  list(input: { severity?: string; engagementId?: string; limit?: number }): Promise<SecurityEventRecord[]> {
    return this.deps.repos.securityEvents.list({
      severity: input.severity,
      engagementId: input.engagementId,
      limit: input.limit ?? 100,
    });
  }

  listOpenIncidents(): Promise<IncidentRecord[]> {
    return this.deps.repos.incidents.listOpen();
  }

  updateIncidentStatus(id: string, status: string): Promise<IncidentRecord | null> {
    return this.deps.repos.incidents.updateStatus(id, status);
  }

  async securityMetricsSnapshot(): Promise<{
    scope_denials: number;
    policy_denials: number;
    approval_requests: number;
    credential_accesses: number;
    prompt_injection_events: number;
    tool_validation_failures: number;
    emergency_stop_engaged: boolean;
    open_circuit_breakers: number;
    open_incidents: number;
  }> {
    const sinceMinutes = 1440; // 24h window
    const [scopeDenials, policyDenials, approvals, credentialAccesses, injections, toolFailures, estop, breakers, incidents] =
      await Promise.all([
        this.deps.repos.securityEvents.countByCategorySince('SCOPE_DENIAL', sinceMinutes),
        this.deps.repos.securityEvents.countByCategorySince('POLICY_DENIAL', sinceMinutes),
        this.deps.repos.securityEvents.countByCategorySince('APPROVAL_REQUESTED', sinceMinutes),
        this.deps.repos.securityEvents.countByCategorySince('CREDENTIAL_ACCESS', sinceMinutes),
        this.deps.repos.securityEvents.countByCategorySince('PROMPT_INJECTION_DETECTED', sinceMinutes),
        this.deps.repos.securityEvents.countByCategorySince('TOOL_VALIDATION_FAILURE', sinceMinutes),
        this.deps.repos.emergencyStop.isEngaged(),
        this.deps.repos.circuitBreakers.listOpen(),
        this.deps.repos.incidents.listOpen(),
      ]);
    return {
      scope_denials: scopeDenials,
      policy_denials: policyDenials,
      approval_requests: approvals,
      credential_accesses: credentialAccesses,
      prompt_injection_events: injections,
      tool_validation_failures: toolFailures,
      emergency_stop_engaged: estop,
      open_circuit_breakers: breakers.length,
      open_incidents: incidents.length,
    };
  }
}

const SEVERITY_ORDER: SecurityEventRecord['severity'][] = ['INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];

function severityRank(severity: SecurityEventRecord['severity']): number {
  return SEVERITY_ORDER.indexOf(severity);
}

function minSeverity(
  a: SecurityEventRecord['severity'],
  b: SecurityEventRecord['severity'],
): SecurityEventRecord['severity'] {
  return severityRank(a) >= severityRank(b) ? a : b;
}
