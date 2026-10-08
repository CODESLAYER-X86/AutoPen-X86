/**
 * Ownership guards. Cross-tenant access returns 404 (not 403) to avoid
 * leaking the existence of other users' resources (documented in the
 * threat model).
 */
import { NotFoundError } from '@aegis/shared';
import type { AppContext } from '../context.js';
import type { EngagementRecord, ProjectRecord } from '@aegis/database';

export async function requireOwnedProject(
  ctx: AppContext,
  userId: string,
  projectId: string,
): Promise<ProjectRecord> {
  const project = await ctx.repos.projects.findById(projectId);
  if (!project || project.owner_id !== userId) {
    throw new NotFoundError('PROJECT');
  }
  return project;
}

export async function requireOwnedEngagement(
  ctx: AppContext,
  userId: string,
  engagementId: string,
): Promise<EngagementRecord> {
  const engagement = await ctx.repos.engagements.findById(engagementId);
  if (!engagement) {
    throw new NotFoundError('ENGAGEMENT');
  }
  await requireOwnedProject(ctx, userId, engagement.project_id);
  return engagement;
}
