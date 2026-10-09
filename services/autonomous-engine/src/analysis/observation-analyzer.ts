/**
 * Observation analyzer (spec Part 6 §24-§25, §44).
 *
 * Post-task deterministic analysis pipeline (no model calls):
 *   1. passive asset discovery over newly recorded traffic (§10)
 *   2. technology fingerprints (§9)
 *   3. anomaly detection against baselines (§24)
 *   4. auto differential for test-candidate tasks (§18-§19)
 *   5. flag-condition scan in CTF mode (§31)
 *
 * Deterministic extraction COMPRESSES the evidence before any model call
 * (§44): workers receive compact diffs and interesting fields, never raw
 * multi-kilobyte bodies.
 */
import type { Repositories, TaskRecord } from '@aegis/database';
import { AssetDiscovery } from '../reconnaissance/asset-discovery.js';
import { TechnologyFingerprinter } from '../reconnaissance/technology-fingerprint.js';
import { AnomalyAnalyzer } from '../reasoning/anomaly-analyzer.js';
import { DifferentialEngine } from './differential-engine.js';
import type { EventBus } from '@aegis/events';

export interface ObservationAnalysisResult {
  passiveObservations: number;
  technologies: number;
  anomalies: number;
  differentials: Array<{ taskId: string; verdict: string; signal: string }>;
}

export interface ObservationAnalyzerDeps {
  repos: Repositories;
  eventBus: EventBus;
  reasoning: import('../engine/ports.js').ReasoningPort;
}

export class ObservationAnalyzer {
  private readonly assets: AssetDiscovery;
  private readonly fingerprinter: TechnologyFingerprinter;
  private readonly anomalies: AnomalyAnalyzer;
  private readonly differentials: DifferentialEngine;

  constructor(private readonly deps: ObservationAnalyzerDeps) {
    this.assets = new AssetDiscovery({ repos: deps.repos, eventBus: deps.eventBus });
    this.fingerprinter = new TechnologyFingerprinter(deps.repos);
    this.anomalies = new AnomalyAnalyzer(deps.repos);
    this.differentials = new DifferentialEngine({ repos: deps.repos, eventBus: deps.eventBus, reasoning: deps.reasoning });
  }

  /**
   * Analyze after a task completes (§24 observation -> anomaly -> hypothesis
   * candidate). Failures are isolated per stage — analysis never breaks the
   * loop (§113-style degradation).
   */
  async analyzeTaskCompletion(engagementId: string, task: TaskRecord): Promise<ObservationAnalysisResult> {
    const result: ObservationAnalysisResult = {
      passiveObservations: 0,
      technologies: 0,
      anomalies: 0,
      differentials: [],
    };

    try {
      const passive = await this.assets.discover(engagementId, 30);
      result.passiveObservations = passive.observations;
    } catch {
      // isolated per stage
    }

    if (task.type === 'RECON' || task.type === 'BROWSER_INVESTIGATION') {
      try {
        const technologies = await this.fingerprinter.fingerprint(engagementId, 30);
        result.technologies = technologies.length;
      } catch {
        // isolated
      }
    }

    try {
      const analysis = await this.anomalies.analyze(engagementId, 30);
      result.anomalies = analysis.anomalies.length;
    } catch {
      // isolated
    }

    try {
      const differential = await this.differentials.analyzeTask(engagementId, task);
      if (differential) {
        result.differentials.push({ taskId: differential.taskId ?? task.id, verdict: differential.verdict, signal: differential.signal });
      }
    } catch {
      // isolated
    }

    return result;
  }
}
