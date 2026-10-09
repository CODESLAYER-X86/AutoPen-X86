/**
 * CTF clue analyzer (spec Part 6 §4, §29).
 *
 * Extracts clues from the challenge title, description, hints and provided
 * artifacts. Clues are UNTRUSTED challenge data — they flow into the
 * riddle engine and are only ever rendered inside untrusted delimiters.
 */
import type { Repositories } from '@aegis/database';
import type { CtfClueSource } from '@aegis/shared';

export interface ExtractedClue {
  source: CtfClueSource;
  text: string;
}

/** Split descriptions into candidate clue sentences (riddle-shaped first). */
export function extractClues(input: {
  title: string;
  description: string;
  hints: string[];
}): ExtractedClue[] {
  const clues: ExtractedClue[] = [];

  if (input.title.trim().length > 0) {
    clues.push({ source: 'TITLE', text: input.title.trim().slice(0, 500) });
  }

  const sentences = input.description
    .split(/(?<=[.!?])\s+|\n+/)
    .map((s) => s.trim())
    .filter((s) => s.length > 8);
  for (const sentence of sentences.slice(0, 20)) {
    clues.push({ source: 'DESCRIPTION', text: sentence.slice(0, 800) });
  }

  for (const hint of input.hints.slice(0, 16)) {
    const trimmed = hint.trim();
    if (trimmed.length > 0) {
      clues.push({ source: 'HINT', text: trimmed.slice(0, 800) });
    }
  }
  return clues.slice(0, 32);
}

export class ClueAnalyzer {
  constructor(private readonly repos: Repositories) {}

  /** Persist extracted clues (idempotent per engagement by text hash). */
  async recordClues(engagementId: string, clues: ExtractedClue[]): Promise<number> {
    const existing = await this.repos.ctfClues.listByEngagement(engagementId);
    const existingTexts = new Set(existing.map((c) => c.text_content));
    let created = 0;
    for (const clue of clues) {
      if (existingTexts.has(clue.text)) continue;
      await this.repos.ctfClues.create({ engagementId, source: clue.source, text: clue.text });
      created += 1;
    }
    return created;
  }
}
