/** Lexical similarity helpers for case memory (deterministic, no models). */

function tokenize(text: string): string[] {
  return text
    .toLowerCase()
    .replace(/[^a-z0-9\s]/g, ' ')
    .split(/\s+/)
    .filter((token) => token.length > 3);
}

function jaccard(a: Set<string>, b: Set<string>): number {
  if (a.size === 0 || b.size === 0) return 0;
  let intersection = 0;
  for (const item of a) if (b.has(item)) intersection += 1;
  return intersection / (a.size + b.size - intersection);
}

/** Jaccard similarity over significant words of two texts. */
export function jaccardText(a: string, b: string): number {
  return jaccard(new Set(tokenize(a)), new Set(tokenize(b)));
}
