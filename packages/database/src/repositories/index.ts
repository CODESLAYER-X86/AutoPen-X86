import type { Pool } from 'pg';
import { AssetsRepository } from './assets.js';
import { AuditRepository } from './audit.js';
import { AuthSessionsRepository } from './auth-sessions.js';
import { EngagementsRepository } from './engagements.js';
import { EventsRepository } from './events.js';
import { EvidenceRepository } from './evidence.js';
import { IdentitiesRepository, SessionsRepository } from './identities.js';
import { ProjectsRepository } from './projects.js';
import { ScopeRepository } from './scope.js';
import { TargetsRepository } from './targets.js';
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
  };
}

export * from './util.js';
export {
  AssetsRepository,
  AuditRepository,
  AuthSessionsRepository,
  EngagementsRepository,
  EventsRepository,
  EvidenceRepository,
  IdentitiesRepository,
  SessionsRepository,
  ProjectsRepository,
  ScopeRepository,
  TargetsRepository,
  UsersRepository,
};
