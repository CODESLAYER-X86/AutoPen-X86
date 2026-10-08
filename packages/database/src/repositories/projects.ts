import type { Pool } from 'pg';
import { generateId } from '@aegis/shared';
import type { ProjectRecord } from '../types.js';
import { iso, requireIso, type RepoBase } from './util.js';

export interface CreateProjectInput {
  ownerId: string;
  name: string;
  description: string;
}

export class ProjectsRepository implements RepoBase {
  constructor(readonly pool: Pool) {}

  async create(input: CreateProjectInput): Promise<ProjectRecord> {
    const id = generateId('PRJ');
    const result = await this.pool.query(
      `INSERT INTO projects (id, owner_id, name, description)
       VALUES ($1, $2, $3, $4)
       RETURNING id, owner_id, name, description, created_at, updated_at`,
      [id, input.ownerId, input.name, input.description],
    );
    return mapProject(result.rows[0]!);
  }

  async findById(id: string): Promise<ProjectRecord | null> {
    const result = await this.pool.query(
      `SELECT id, owner_id, name, description, created_at, updated_at
       FROM projects WHERE id = $1`,
      [id],
    );
    return result.rows[0] ? mapProject(result.rows[0]) : null;
  }

  async listByOwner(ownerId: string, limit = 100, offset = 0): Promise<ProjectRecord[]> {
    const result = await this.pool.query(
      `SELECT id, owner_id, name, description, created_at, updated_at
       FROM projects WHERE owner_id = $1
       ORDER BY created_at DESC LIMIT $2 OFFSET $3`,
      [ownerId, limit, offset],
    );
    return result.rows.map(mapProject);
  }

  async countByOwner(ownerId: string): Promise<number> {
    const result = await this.pool.query('SELECT count(*)::int AS n FROM projects WHERE owner_id = $1', [
      ownerId,
    ]);
    return result.rows[0]!.n as number;
  }

  async update(
    id: string,
    patch: { name?: string; description?: string },
  ): Promise<ProjectRecord | null> {
    const result = await this.pool.query(
      `UPDATE projects SET
         name = COALESCE($2, name),
         description = COALESCE($3, description),
         updated_at = now()
       WHERE id = $1
       RETURNING id, owner_id, name, description, created_at, updated_at`,
      [id, patch.name ?? null, patch.description ?? null],
    );
    return result.rows[0] ? mapProject(result.rows[0]) : null;
  }
}

type ProjectRow = {
  id: string;
  owner_id: string;
  name: string;
  description: string;
  created_at: Date;
  updated_at: Date;
};

export function mapProject(row: ProjectRow): ProjectRecord {
  return {
    id: row.id,
    owner_id: row.owner_id,
    name: row.name,
    description: row.description,
    created_at: requireIso(row.created_at),
    updated_at: requireIso(row.updated_at),
  };
}

export { iso };
