/**
 * CTF engine (spec Part 6 §4, §29-§31, §63).
 *
 * CTF mode changes the optimization objective: maximize the probability of
 * solving the challenge while minimizing wasted exploration. The engine
 * ingests the challenge description, analyzes clues, generates candidate
 * interpretations (riddle engine), retrieves knowledge (challenge memory),
 * branches hypotheses, flag-conditions the outcome, and follows EVIDENCE —
 * never brute-forcing every storage value (§63).
 *
 * A CTF finding only becomes SOLVED when evidence exists that the success
 * condition was satisfied (§31) — a discovered vulnerability alone never
 * marks the challenge solved.
 */
import type { Repositories, EngagementRecord } from '@aegis/database';
import type { PlatformEvent, CtfInterpretation } from '@aegis/contracts';
import type { EventBus } from '@aegis/events';
import { generateId, type HypothesisType } from '@aegis/shared';
import { HypothesisEngine } from '@aegis/agent';
import { BranchManager } from '../reasoning/branch-manager.js';
import { extractClues, ClueAnalyzer } from './clue-analyzer.js';
import { interpretClue, rankBranches, type RiddleInterpretation } from './riddle-engine.js';
import { ChallengeMemory } from './challenge-memory.js';
import { FlagConditionAnalyzer } from './flag-condition-analyzer.js';
import type { KnowledgePort } from '../engine/ports.js';

export interface CtfAnalysisResult {
  clues: number;
  interpretations: number;
  hypothesesCreated: number;
  branchesCreated: number;
  similarCases: number;
}

export interface CtfEngineDeps {
  repos: Repositories;
  eventBus: EventBus;
  knowledge?: KnowledgePort;
  hypothesisEngine: HypothesisEngine;
  branchManager: BranchManager;
  flagPatterns: string;
  /** CTF hypotheses budget per analysis cycle. */
  maxHypotheses: number;
}

const CTF_HYPOTHESIS_TYPE: HypothesisType = 'CTF_CLUE';

export class CtfEngine {
  private readonly clueAnalyzer: ClueAnalyzer;
  private readonly memory: ChallengeMemory | null;
  private readonly flags: FlagConditionAnalyzer;

  constructor(private readonly deps: CtfEngineDeps) {
    this.clueAnalyzer = new ClueAnalyzer(deps.repos);
    this.memory = deps.knowledge ? new ChallengeMemory(deps.knowledge) : null;
    this.flags = new FlagConditionAnalyzer({ repos: deps.repos, eventBus: deps.eventBus }, deps.flagPatterns);
  }

  /**
   * Initialize the challenge: upsert the CTF context (title/description/
   * hints from the engagement description or operator input), extract
   * clues, interpret them, retrieve similar cases and create hypothesis
   * branches (§63 cycle: clue -> interpretations -> knowledge ->
   * hypotheses).
   */
  async initialize(engagement: EngagementRecord, input: { title?: string; description?: string; hints?: string[]; flagFormat?: string | null }): Promise<CtfAnalysisResult> {
    const context = await this.deps.repos.ctfContexts.upsert({
      engagementId: engagement.id,
      title: input.title ?? engagement.name,
      description: input.description ?? engagement.description,
      hints: input.hints ?? [],
      flagFormat: input.flagFormat ?? null,
    });

    const event: PlatformEvent = {
      type: 'CTF_CONTEXT_CREATED',
      engagement_id: engagement.id,
      trace_id: generateId('TRC'),
      actor_id: null,
      payload: { title: context.title, hints: context.hints.length },
      occurred_at: new Date().toISOString(),
      dedup_key: `ctf-context:${engagement.id}`,
    };
    await this.deps.eventBus.publish(event).catch(() => undefined);

    return this.analyze(engagement.id);
  }

  /**
   * Analyze clues -> interpretations -> hypotheses + branches + flag
   * conditions (§29, §30). Idempotent: existing clues are not re-recorded.
   */
  async analyze(engagementId: string): Promise<CtfAnalysisResult> {
    const result: CtfAnalysisResult = {
      clues: 0,
      interpretations: 0,
      hypothesesCreated: 0,
      branchesCreated: 0,
      similarCases: 0,
    };

    const context = await this.deps.repos.ctfContexts.findByEngagement(engagementId);
    if (!context) return result;

    // 1. Clue extraction (§29).
    const clues = extractClues({
      title: context.title,
      description: context.description,
      hints: context.hints,
    });
    result.clues = await this.clueAnalyzer.recordClues(engagementId, clues);

    // 2. Riddle interpretation per NEW clue (§29) + knowledge retrieval.
    const recorded = await this.deps.repos.ctfClues.listByEngagement(engagementId);
    let hypothesisBudget = this.deps.maxHypotheses;

    for (const clue of recorded) {
      if (clue.status === 'INTERPRETED' || clue.status === 'CONSUMED' || clue.status === 'DEAD_END') continue;
      let riddleInterpretations: RiddleInterpretation[] = interpretClue(clue.text_content);

      let interpretations: CtfInterpretation[] = riddleInterpretations.map((i) => ({
        concept: i.concept,
        confidence: i.confidence,
        rationale: i.rationale,
      }));
      if (this.memory && interpretations.length > 0) {
        interpretations = await this.memory.corroborateInterpretations(interpretations);
        // Keep branch ranking data in sync with the corroborated confidences.
        const byConcept = new Map(interpretations.map((i) => [i.concept, i]));
        riddleInterpretations = riddleInterpretations.map(
          (i) => (byConcept.get(i.concept) ? { ...i, confidence: byConcept.get(i.concept)!.confidence } : i),
        );
      }

      await this.deps.repos.ctfClues.recordInterpretations(clue.id, interpretations, 'INTERPRETED');
      result.interpretations += interpretations.length;

      // 3. Hypotheses + branches per interpretation (§30 branching).
      for (const interpretation of rankBranches(riddleInterpretations)) {
        if (hypothesisBudget <= 0) break;
        try {
          const hypothesis = await this.deps.hypothesisEngine.createHypothesis({
            engagementId,
            type: CTF_HYPOTHESIS_TYPE,
            statement: `CTF clue interpretation (${clue.source}): the challenge secret relates to ${interpretation.concept}. Confidence from deterministic riddle analysis: ${interpretation.confidence.toFixed(2)}.`,
            confidence: interpretation.confidence,
            priority: interpretation.confidence,
            source: `ctf-clue:${clue.id}`,
          });
          const branch = await this.deps.branchManager.createBranch(engagementId, {
            origin: 'CTF_CLUE',
            originRef: clue.id,
            focus: `Clue interpretation: ${interpretation.concept}`,
            hypothesisIds: [hypothesis.id],
            metadata: { concept: interpretation.concept, confidence: interpretation.confidence },
          });
          await this.deps.repos.ctfClues.attachBranch(clue.id, branch.id);
          hypothesisBudget -= 1;
          result.hypothesesCreated += 1;
          result.branchesCreated += 1;
        } catch {
          // Branch budget exceeded — remaining interpretations stay recorded.
          break;
        }
      }

      const analysisEvent: PlatformEvent = {
        type: 'CTF_CLUE_ANALYZED',
        engagement_id: engagementId,
        trace_id: generateId('TRC'),
        actor_id: null,
        payload: {
          clue_id: clue.id,
          interpretations: interpretations.map((i) => ({ concept: i.concept, confidence: i.confidence })),
        },
        occurred_at: new Date().toISOString(),
        dedup_key: `ctf-clue-analyzed:${clue.id}`,
      };
      await this.deps.eventBus.publish(analysisEvent).catch(() => undefined);
    }

    // 4. Similar cases (§63 knowledge retrieval for the whole challenge).
    if (this.memory) {
      const similar = await this.memory.similarChallenges(`${context.title} ${context.description}`);
      result.similarCases = similar.cases.length;
      await this.deps.repos.ctfContexts.updateAnalysis(engagementId, {
        similar_cases: similar.cases.slice(0, 5),
        notes: similar.notes,
        analyzed_at: new Date().toISOString(),
      });
    }

    // 5. Flag-condition hypothesis (§31): the success condition statement.
    const conditions = await this.deps.repos.flagConditions.listByEngagement(engagementId);
    if (conditions.length === 0) {
      await this.deps.repos.flagConditions.create({
        engagementId,
        description: `Challenge success condition: a value matching the declared flag format (${context.flag_format ?? 'flag{...}'}) is observed in challenge evidence (§31).`,
        pattern: context.flag_format,
      });
      const event: PlatformEvent = {
        type: 'FLAG_CONDITION_HYPOTHESIZED',
        engagement_id: engagementId,
        trace_id: generateId('TRC'),
        actor_id: null,
        payload: { pattern: context.flag_format ?? 'flag{...}' },
        occurred_at: new Date().toISOString(),
        dedup_key: `flag-condition:${engagementId}`,
      };
      await this.deps.eventBus.publish(event).catch(() => undefined);
    }
    return result;
  }

  /**
   * Scan for the flag after new evidence arrives (§31). Returns true when
   * the challenge became SOLVED.
   */
  async scanForFlag(engagementId: string): Promise<boolean> {
    const context = await this.deps.repos.ctfContexts.findByEngagement(engagementId);
    if (!context || context.status === 'SOLVED') return false;
    const detections = await this.flags.scan(engagementId, context.flag_format);
    for (const detection of detections) {
      await this.flags.recordDetection(engagementId, detection);
      return true;
    }
    return false;
  }

  /** Human-added clue (§48: user can feed observations into CTF reasoning). */
  async addClue(
    engagementId: string,
    text: string,
    source: 'USER' | 'OBSERVATION' | 'TITLE' | 'DESCRIPTION' | 'HINT' | 'ARTIFACT' = 'USER',
  ): Promise<void> {
    await this.deps.repos.ctfClues.create({ engagementId, source, text });
  }
}
