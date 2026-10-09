/** Shared structural types for the reasoning modules. */
export interface AttackSurfaceProjection {
  endpointCount: number;
  identityCount: number;
  objectCount: number;
  workflowCount: number;
  parameterCount: number;
}

export interface AnomalyFinding {
  kind: string;
  subject: string;
  observed: string;
  expected: string;
  severity: 'LOW' | 'MEDIUM' | 'HIGH';
  evidenceRef: string | null;
}
