import type { Pool } from 'pg';
import { generateId } from '@aegis/shared';
import type { UserRecord } from '../types.js';
import { iso, requireIso, type RepoBase } from './util.js';

interface InsertUser {
  email: string;
  name: string;
  passwordHash: string;
}

export class UsersRepository implements RepoBase {
  constructor(readonly pool: Pool) {}

  async create(input: InsertUser): Promise<UserRecord> {
    const id = generateId('USR');
    const result = await this.pool.query(
      `INSERT INTO users (id, email, name, password_hash)
       VALUES ($1, $2, $3, $4)
       RETURNING id, email, name, password_hash, role, last_login_at, created_at, updated_at`,
      [id, input.email, input.name, input.passwordHash],
    );
    return mapUser(result.rows[0]!);
  }

  async findByEmail(email: string): Promise<UserRecord | null> {
    const result = await this.pool.query(
      `SELECT id, email, name, password_hash, role, last_login_at, created_at, updated_at
       FROM users WHERE email = $1`,
      [email],
    );
    return result.rows[0] ? mapUser(result.rows[0]) : null;
  }

  async findById(id: string): Promise<UserRecord | null> {
    const result = await this.pool.query(
      `SELECT id, email, name, password_hash, role, last_login_at, created_at, updated_at
       FROM users WHERE id = $1`,
      [id],
    );
    return result.rows[0] ? mapUser(result.rows[0]) : null;
  }

  async touchLastLogin(id: string): Promise<void> {
    await this.pool.query(
      'UPDATE users SET last_login_at = now(), updated_at = now() WHERE id = $1',
      [id],
    );
  }
}

type UserRow = {
  id: string;
  email: string;
  name: string;
  password_hash: string;
  role: string;
  last_login_at: Date | null;
  created_at: Date;
  updated_at: Date;
};

function mapUser(row: UserRow): UserRecord {
  return {
    id: row.id,
    email: row.email,
    name: row.name,
    password_hash: row.password_hash,
    role: row.role,
    last_login_at: iso(row.last_login_at),
    created_at: requireIso(row.created_at),
    updated_at: requireIso(row.updated_at),
  };
}
