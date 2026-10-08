/**
 * Worker runtime interface (spec §3 — Worker Runtime).
 *
 * Part 1 defines the contract only. Part 2 implements the tactical worker
 * execution: compact task packets -> tactical model -> structured result.
 */
import { NotImplementedError } from '@aegis/shared';

/** Compact task packet — the worker never receives the whole engagement DB. */
export interface TaskPacket {
  task_id: string;
  engagement_id: string;
  type: string;
  instruction: string;
  evidence_refs: string[];
  context: Record<string, unknown>;
}

export interface WorkerResult {
  task_id: string;
  status: 'COMPLETED' | 'FAILED';
  observations: Record<string, unknown>[];
  tool_invocations: Record<string, unknown>[];
  error?: string;
}

export interface WorkerRuntime {
  runTask(packet: TaskPacket): Promise<WorkerResult>;
}

export function createNotImplementedWorkerRuntime(): WorkerRuntime {
  return {
    async runTask(): Promise<WorkerResult> {
      throw new NotImplementedError(
        'The worker runtime is not implemented in Part 1; it is the subject of Part 2 (Agent OS)',
        'WORKER_RUNTIME_NOT_IMPLEMENTED',
      );
    },
  };
}
