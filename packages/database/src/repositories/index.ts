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
