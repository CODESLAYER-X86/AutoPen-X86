/** PostgreSQL pool management. */
import { Pool, type PoolClient } from 'pg';
import { DatabaseError } from '@aegis/shared';

export interface CreatePoolOptions {
  max?: number;
  idleTimeoutMillis?: number;
  connectionTimeoutMillis?: number;
}

export function createPool(connectionString: string, options: CreatePoolOptions = {}): Pool {
  return new Pool({
    connectionString,
    max: options.max ?? 10,
    idleTimeoutMillis: options.idleTimeoutMillis ?? 30_000,
    connectionTimeoutMillis: options.connectionTimeoutMillis ?? 10_000,
  });
}

export async function withTransaction<T>(
  pool: Pool,
  fn: (client: PoolClient) => Promise<T>,
): Promise<T> {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const result = await fn(client);
    await client.query('COMMIT');
    return result;
  } catch (error) {
    try {
      await client.query('ROLLBACK');
    } catch {
      // connection already broken; nothing to roll back
    }
    throw error;
  } finally {
    client.release();
  }
}

/** Maps a pg error to a typed DatabaseError (unique violations etc.). */
export function toDatabaseError(error: unknown, context: string): DatabaseError {
  const pgErr = error as { code?: string; constraint?: string; detail?: string };
  if (pgErr && typeof pgErr.code === 'string') {
    if (pgErr.code === '23505') {
      return new DatabaseError(`${context}: duplicate key`, 'DUPLICATE', { constraint: pgErr.constraint });
    }
    if (pgErr.code === '23503') {
      return new DatabaseError(`${context}: foreign key violation`, 'FK_VIOLATION', {
        constraint: pgErr.constraint,
      });
    }
    if (pgErr.code === '23514') {
      return new DatabaseError(`${context}: check constraint violation`, 'CHECK_VIOLATION', {
        constraint: pgErr.constraint,
      });
    }
    if (pgErr.code === 'ECONNREFUSED' || pgErr.code === '57P01') {
      return new DatabaseError(`${context}: database unavailable`, 'DATABASE_UNAVAILABLE');
    }
  }
  return new DatabaseError(`${context}: unexpected database error`, 'DATABASE_ERROR', undefined, error);
}
