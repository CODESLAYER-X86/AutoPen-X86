/**
 * Dependency planner (spec Part 6 §36-§37).
 *
 * Makes dependencies EXPLICIT: identity differential tests wait for session
 * capture; workflow continuation waits for prior steps; analysis waits for
 * the observations it consumes. Parallelism applies to independent branches.
 */
import type { TaskRecord } from '@aegis/database';

export interface DependencyPlan {
  taskId: string;
  dependsOn: string[];
  condition?: 'COMPLETED' | 'SUCCESS' | 'OBSERVATION_EXISTS' | 'IDENTITY_AVAILABLE' | 'ENDPOINT_DISCOVERED' | 'HYPOTHESIS_ACTIVE';
}

/**
 * Compute dependencies for engine-compiled tasks:
 *  - identity-dependent tasks wait for the session-init task of the SAME
 *    identity (§36: discover -> capture -> differential);
 *  - analysis tasks wait for the discovery tasks that produce their input;
 *  - verification tasks wait for the test task of the same hypothesis.
 */
export function planDependencies(tasks: TaskRecord[]): Map<string, DependencyPlan> {
  const plans = new Map<string, DependencyPlan>();
  const sessionTasksByIdentity = new Map<string, TaskRecord>();
  const testTasksByHypothesis = new Map<string, TaskRecord>();
  const discoveryTasks = tasks.filter((t) => t.type === 'RECON' || t.type === 'BROWSER_INVESTIGATION');

  for (const task of tasks) {
    const identityId = typeof task.inputs.identity_id === 'string' ? task.inputs.identity_id : null;
    if (task.type === 'AUTHENTICATION_ANALYSIS' && identityId) {
      sessionTasksByIdentity.set(identityId, task);
    }
    if (task.hypothesis_id && task.inputs.mode === 'TEST_CANDIDATE') {
      testTasksByHypothesis.set(task.hypothesis_id, task);
    }
  }

  for (const task of tasks) {
    const dependsOn: string[] = [];
    let condition: DependencyPlan['condition'];

    const identityId = typeof task.inputs.identity_id === 'string' ? task.inputs.identity_id : null;
    if (identityId && task.inputs.mode === 'TEST_CANDIDATE') {
      const sessionTask = sessionTasksByIdentity.get(identityId);
      if (sessionTask && sessionTask.id !== task.id) {
        dependsOn.push(sessionTask.id);
        condition = 'IDENTITY_AVAILABLE';
      }
    }
    if (task.hypothesis_id && task.type === 'VERIFICATION') {
      const testTask = testTasksByHypothesis.get(task.hypothesis_id);
      if (testTask && testTask.id !== task.id) {
        dependsOn.push(testTask.id);
        condition = 'COMPLETED';
      }
    }
    if (task.type === 'GENERAL_ANALYSIS' && task.inputs.split_of) {
      const parent = tasks.find((t) => t.id === task.inputs.split_of);
      if (parent) dependsOn.push(parent.id);
    }

    if (dependsOn.length > 0 || discoveryTasks.includes(task) === false) {
      plans.set(task.id, { taskId: task.id, dependsOn: dependsOn.slice(0, 10), condition });
    }
  }
  return plans;
}

/**
 * Two engine-compiled tasks are INDEPENDENT when they target different
 * hypotheses and different identities (§36 parallelism).
 */
export function independent(a: TaskRecord, b: TaskRecord): boolean {
  if (a.hypothesis_id && a.hypothesis_id === b.hypothesis_id) return false;
  const identityA = typeof a.inputs.identity_id === 'string' ? a.inputs.identity_id : '';
  const identityB = typeof b.inputs.identity_id === 'string' ? b.inputs.identity_id : '';
  if (identityA && identityA === identityB) return false;
  return !b.depends_on.includes(a.id) && !a.depends_on.includes(b.id);
}
