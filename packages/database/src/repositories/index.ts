import type { Pool } from 'pg';
import { AgentDecisionsRepository } from './agent-decisions.js';
import { AgentMessagesRepository } from './agent-messages.js';
import { AgentRunsRepository } from './agent-runs.js';
import { AssetsRepository } from './assets.js';
import { AuditRepository } from './audit.js';
import { AuthSessionsRepository } from './auth-sessions.js';
import { DeadEndsRepository } from './dead-ends.js';
import { EngagementsRepository } from './engagements.js';
import { EngagementBudgetsRepository } from './budgets.js';
import { EventsRepository } from './events.js';
import { EvidenceRepository } from './evidence.js';
import { FindingsRepository } from './findings.js';
import { HypothesesRepository } from './hypotheses.js';
import { IdentitiesRepository, SessionsRepository } from './identities.js';
import { ModelCallsRepository } from './model-calls.js';
import { ObservationsRepository } from './observations.js';
import { ProjectsRepository } from './projects.js';
import { ScopeRepository } from './scope.js';
import { StrategiesRepository } from './strategies.js';
import { TargetsRepository } from './targets.js';
import { TaskAttemptsRepository } from './task-attempts.js';
import { TasksRepository } from './tasks.js';
import { TestsRepository } from './tests.js';
import { UsersRepository } from './users.js';
import { HttpRequestsRepository, HttpResponsesRepository } from './http-traffic.js';
import {
  AuthWorkflowsRepository,
  BrowserContextsRepository,
  BrowserEventsRepository,
  BrowserPagesRepository,
  CookiesRepository,
  DomSnapshotsRepository,
  DownloadsRepository,
  StorageEntriesRepository,
  ToolExecutionsRepository,
  WebSocketsRepository,
} from './interaction.js';
import {
  AttackEdgesRepository,
  AttackNodesRepository,
  ReasoningFailuresRepository,
} from './reasoning-graph.js';
import {
  DataFlowsRepository,
  DifferentialResultsRepository,
  VerificationsRepository,
  WorkflowStatesRepository,
  WorkflowTransitionsRepository,
  WorkflowsRepository,
} from './reasoning-flows.js';
import {
  AuthorizationMatrixRepository,
  EndpointsRepository,
  ObjectCandidatesRepository,
  ParametersRepository,
  SecuritySignalsRepository,
} from './reasoning-surface.js';

export interface Repositories {
  users: UsersRepository;
  projects: ProjectsRepository;
  engagements: EngagementsRepository;
  targets: TargetsRepository;
  scope: ScopeRepository;
  assets: AssetsRepository;
  identities: IdentitiesRepository;
  sessions: SessionsRepository;
  authSessions: AuthSessionsRepository;
  events: EventsRepository;
  audit: AuditRepository;
  evidence: EvidenceRepository;
  // Part 2 — Agent Operating System repositories.
  agentRuns: AgentRunsRepository;
  agentDecisions: AgentDecisionsRepository;
  hypotheses: HypothesesRepository;
  observations: ObservationsRepository;
  tasks: TasksRepository;
  taskAttempts: TaskAttemptsRepository;
  tests: TestsRepository;
  deadEnds: DeadEndsRepository;
  strategies: StrategiesRepository;
  findings: FindingsRepository;
  agentMessages: AgentMessagesRepository;
  modelCalls: ModelCallsRepository;
  budgets: EngagementBudgetsRepository;
  // Part 3 — interaction layer repositories.
  httpRequests: HttpRequestsRepository;
  httpResponses: HttpResponsesRepository;
  browserContexts: BrowserContextsRepository;
  browserPages: BrowserPagesRepository;
  browserEvents: BrowserEventsRepository;
  cookies: CookiesRepository;
  storageEntries: StorageEntriesRepository;
  domSnapshots: DomSnapshotsRepository;
  downloads: DownloadsRepository;
  websockets: WebSocketsRepository;
  toolExecutions: ToolExecutionsRepository;
  authWorkflows: AuthWorkflowsRepository;
  // Part 4 — security reasoning engine repositories.
  endpoints: EndpointsRepository;
  parameters: ParametersRepository;
  authzMatrix: AuthorizationMatrixRepository;
  securitySignals: SecuritySignalsRepository;
  objectCandidates: ObjectCandidatesRepository;
  workflows: WorkflowsRepository;
  workflowStates: WorkflowStatesRepository;
  workflowTransitions: WorkflowTransitionsRepository;
  dataFlows: DataFlowsRepository;
  differentialResults: DifferentialResultsRepository;
  verifications: VerificationsRepository;
  attackNodes: AttackNodesRepository;
  attackEdges: AttackEdgesRepository;
  reasoningFailures: ReasoningFailuresRepository;
}

export function createRepositories(pool: Pool): Repositories {
  return {
    users: new UsersRepository(pool),
    projects: new ProjectsRepository(pool),
    engagements: new EngagementsRepository(pool),
    targets: new TargetsRepository(pool),
    scope: new ScopeRepository(pool),
    assets: new AssetsRepository(pool),
    identities: new IdentitiesRepository(pool),
    sessions: new SessionsRepository(pool),
    authSessions: new AuthSessionsRepository(pool),
    events: new EventsRepository(pool),
    audit: new AuditRepository(pool),
    evidence: new EvidenceRepository(pool),
    agentRuns: new AgentRunsRepository(pool),
    agentDecisions: new AgentDecisionsRepository(pool),
    hypotheses: new HypothesesRepository(pool),
    observations: new ObservationsRepository(pool),
    tasks: new TasksRepository(pool),
    taskAttempts: new TaskAttemptsRepository(pool),
    tests: new TestsRepository(pool),
    deadEnds: new DeadEndsRepository(pool),
    strategies: new StrategiesRepository(pool),
    findings: new FindingsRepository(pool),
    agentMessages: new AgentMessagesRepository(pool),
    modelCalls: new ModelCallsRepository(pool),
    budgets: new EngagementBudgetsRepository(pool),
    httpRequests: new HttpRequestsRepository(pool),
    httpResponses: new HttpResponsesRepository(pool),
    browserContexts: new BrowserContextsRepository(pool),
    browserPages: new BrowserPagesRepository(pool),
    browserEvents: new BrowserEventsRepository(pool),
    cookies: new CookiesRepository(pool),
    storageEntries: new StorageEntriesRepository(pool),
    domSnapshots: new DomSnapshotsRepository(pool),
    downloads: new DownloadsRepository(pool),
    websockets: new WebSocketsRepository(pool),
    toolExecutions: new ToolExecutionsRepository(pool),
    authWorkflows: new AuthWorkflowsRepository(pool),
    endpoints: new EndpointsRepository(pool),
    parameters: new ParametersRepository(pool),
    authzMatrix: new AuthorizationMatrixRepository(pool),
    securitySignals: new SecuritySignalsRepository(pool),
    objectCandidates: new ObjectCandidatesRepository(pool),
    workflows: new WorkflowsRepository(pool),
    workflowStates: new WorkflowStatesRepository(pool),
    workflowTransitions: new WorkflowTransitionsRepository(pool),
    dataFlows: new DataFlowsRepository(pool),
    differentialResults: new DifferentialResultsRepository(pool),
    verifications: new VerificationsRepository(pool),
    attackNodes: new AttackNodesRepository(pool),
    attackEdges: new AttackEdgesRepository(pool),
    reasoningFailures: new ReasoningFailuresRepository(pool),
  };
}

export * from './util.js';
export {
  AgentDecisionsRepository,
  AgentMessagesRepository,
  AgentRunsRepository,
  AssetsRepository,
  AuditRepository,
  AuthSessionsRepository,
  DeadEndsRepository,
  EngagementBudgetsRepository,
  EngagementsRepository,
  EventsRepository,
  EvidenceRepository,
  FindingsRepository,
  HypothesesRepository,
  IdentitiesRepository,
  ModelCallsRepository,
  ObservationsRepository,
  ProjectsRepository,
  ScopeRepository,
  SessionsRepository,
  StrategiesRepository,
  TargetsRepository,
  TaskAttemptsRepository,
  TasksRepository,
  TestsRepository,
  UsersRepository,
};
export {
  AuthWorkflowsRepository,
  BrowserContextsRepository,
  BrowserEventsRepository,
  BrowserPagesRepository,
  CookiesRepository,
  DomSnapshotsRepository,
  DownloadsRepository,
  HttpRequestsRepository,
  HttpResponsesRepository,
  StorageEntriesRepository,
  ToolExecutionsRepository,
  WebSocketsRepository,
};
export {
  AttackEdgesRepository,
  AttackNodesRepository,
  AuthorizationMatrixRepository,
  DataFlowsRepository,
  DifferentialResultsRepository,
  EndpointsRepository,
  ObjectCandidatesRepository,
  ParametersRepository,
  ReasoningFailuresRepository,
  SecuritySignalsRepository,
  VerificationsRepository,
  WorkflowStatesRepository,
  WorkflowTransitionsRepository,
  WorkflowsRepository,
};
