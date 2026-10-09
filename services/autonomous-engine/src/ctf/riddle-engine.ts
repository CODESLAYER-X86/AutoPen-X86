/**
 * CTF riddle engine (spec Part 6 §29-§30).
 *
 * Pipeline: CLUE -> LINGUISTIC ANALYSIS -> SEMANTIC INTERPRETATIONS ->
 * TECHNICAL CONCEPTS -> KNOWLEDGE RETRIEVAL -> CANDIDATE TECHNIQUES ->
 * HYPOTHESES.
 *
 * Interpretation is DETERMINISTIC lexicon matching (§29): a bounded concept
 * map from riddle language to technical concepts. Riddle interpretation is
 * NEVER treated as fact — each interpretation becomes a branch with
 * confidence + test cost + information gain (§30 branching); cheap
 * high-information branches are tested first.
 */
export interface RiddleInterpretation {
  concept: string;
  confidence: number;
  rationale: string;
  testCost: 'CHEAP' | 'MODERATE' | 'EXPENSIVE';
  informationGain: number;
}

interface ConceptEntry {
  concept: string;
  patterns: RegExp[];
  confidence: number;
  testCost: RiddleInterpretation['testCost'];
  informationGain: number;
}

/**
 * Bounded deterministic concept lexicon (§29 example: "The key is not where
 * you think" -> client-side storage 0.61 / alternate parameter location
 * 0.48). Concept names align with the knowledge taxonomy so retrieval
 * works without translation.
 */
const CONCEPT_LEXICON: ConceptEntry[] = [
  {
    concept: 'client-side storage',
    patterns: [/client[- ]side/i, /local\s*storage/i, /session\s*storage/i, /browser\s*(?:remember|forget)/i, /where you think/i],
    confidence: 0.61,
    testCost: 'CHEAP',
    informationGain: 0.7,
  },
  {
    concept: 'cookies',
    patterns: [/cookie/i, /crumb/i, /biscuit/i, /remembers? what the browser/i, /sweet/i],
    confidence: 0.58,
    testCost: 'CHEAP',
    informationGain: 0.6,
  },
  {
    concept: 'hidden endpoint',
    patterns: [/hidden/i, /secret (?:path|endpoint|page|route)/i, /not\s+(?:linked|listed|indexed)/i, /undocumented/i, /nobody (?:knows|visits)/i],
    confidence: 0.55,
    testCost: 'MODERATE',
    informationGain: 0.75,
  },
  {
    concept: 'encoding',
    patterns: [/encod/i, /base64/i, /cipher/i, /rotat/i, /decode/i, /obfusc/i, /readable form/i, /plain sight/i],
    confidence: 0.52,
    testCost: 'CHEAP',
    informationGain: 0.6,
  },
  {
    concept: 'authentication behavior',
    patterns: [/login/i, /password/i, /authenticat/i, /session/i, /who you are/i, /prove (?:yourself|who)/i],
    confidence: 0.5,
    testCost: 'MODERATE',
    informationGain: 0.55,
  },
  {
    concept: 'business logic',
    patterns: [/business/i, /order|checkout|price|discount|cart/i, /money|pay/i, /logic flaw/i, /short\s*cut|shortcut/i],
    confidence: 0.48,
    testCost: 'MODERATE',
    informationGain: 0.65,
  },
  {
    concept: 'state machine',
    patterns: [/state/i, /stage|step|phase/i, /order of operations/i, /sequence/i, /jump(?:ed)? ahead/i, /skip/i, /backwards/i],
    confidence: 0.5,
    testCost: 'MODERATE',
    informationGain: 0.6,
  },
  {
    concept: 'source code clues',
    patterns: [/source/i, /code(?:base)?/i, /comment/i, /javascript|js file/i, /read the code/i, /inspect/i],
    confidence: 0.55,
    testCost: 'CHEAP',
    informationGain: 0.65,
  },
  {
    concept: 'unusual parameters',
    patterns: [/parameter|param/i, /argument/i, /query string/i, /variable/i, /input/i, /flag.*field/i],
    confidence: 0.45,
    testCost: 'CHEAP',
    informationGain: 0.55,
  },
  {
    concept: 'protocol quirks',
    patterns: [/header/i, /HTTP/i, /method/i, /verb/i, /protocol/i, /request/i, /cache/i, /redirect/i],
    confidence: 0.42,
    testCost: 'MODERATE',
    informationGain: 0.5,
  },
  {
    concept: 'file handling',
    patterns: [/file/i, /upload/i, /download/i, /directory|folder/i, /path traversal/i, /\.txt|\.pdf|\.zip/i],
    confidence: 0.45,
    testCost: 'CHEAP',
    informationGain: 0.5,
  },
  {
    concept: 'websockets',
    patterns: [/websocket|ws\b/i, /socket/i, /real[- ]time/i, /live/i, /push/i],
    confidence: 0.5,
    testCost: 'MODERATE',
    informationGain: 0.55,
  },
];

/** Deterministic linguistic analysis of one clue (§29). */
export function interpretClue(text: string): RiddleInterpretation[] {
  const interpretations: RiddleInterpretation[] = [];
  for (const entry of CONCEPT_LEXICON) {
    const matched = entry.patterns.some((pattern) => pattern.test(text));
    if (matched) {
      interpretations.push({
        concept: entry.concept,
        confidence: entry.confidence,
        rationale: `Lexicon match on clue text (${entry.concept}; deterministic §29 interpretation, never fact)`,
        testCost: entry.testCost,
        informationGain: entry.informationGain,
      });
    }
  }
  // Sort: cheap high-information branches first (§30).
  return interpretations
    .sort((a, b) => {
      const costRank = (c: RiddleInterpretation['testCost']) => ({ CHEAP: 0, MODERATE: 1, EXPENSIVE: 2 })[c];
      return costRank(a.testCost) - costRank(b.testCost) || b.informationGain - a.informationGain;
    })
    .slice(0, 6);
}

/** Branch ordering (§30): test cheap/high-information branches first. */
export function rankBranches(interpretations: RiddleInterpretation[]): RiddleInterpretation[] {
  return [...interpretations].sort(
    (a, b) => b.confidence * b.informationGain - a.confidence * a.informationGain,
  );
}

/** Branch cost rank helper (§30): CHEAP first. */
export function extractBranchCost(cost: 'CHEAP' | 'MODERATE' | 'EXPENSIVE'): number {
  return { CHEAP: 0, MODERATE: 1, EXPENSIVE: 2 }[cost];
}
