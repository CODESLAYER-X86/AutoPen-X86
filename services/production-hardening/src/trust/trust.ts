/**
 * Trust boundary helpers (spec Part 8 §4).
 *
 * The trust level of data is represented in code: every value that crosses
 * a trust boundary carries an explicit tag before it is placed in any
 * prompt, log or store. Untrusted content can never claim a higher trust
 * level because tagging happens at the deterministic ingestion point, never
 * inside the data itself.
 */
import { TRUST_TAGS, type TrustLevel } from '@aegis/contracts';

export interface TaggedContent {
  level: TrustLevel;
  label: string;
  content: string;
}

/** Wrap untrusted target content before it reaches model context (§35). */
export function tagTargetContent(content: string): TaggedContent {
  return { ...TRUST_TAGS.target_content, content };
}

/** Wrap external knowledge before it reaches model context (§36). */
export function tagExternalKnowledge(content: string): TaggedContent {
  return { ...TRUST_TAGS.external_knowledge, content };
}

/** Wrap model output before it is consumed downstream (§37). */
export function tagModelOutput(content: string): TaggedContent {
  return { ...TRUST_TAGS.model_output, content };
}

/**
 * Render tagged content into the deterministic prompt envelope. The wrapper
 * is opened/closed by the platform, never by the payload: content that
 * itself contains a closing tag is inert because parsers treat the whole
 * envelope body as data (defense against tag-splicing prompt injection).
 */
export function renderTagged(tagged: TaggedContent): string {
  return `<${tagged.label}>\n${tagged.content}\n</${tagged.label}>`;
}

/** Strip every trust envelope from a string (used on model output). */
export function stripTrustEnvelopes(value: string): string {
  return value
    .replace(/<UNTRUSTED_[A-Z_]+>\n?/g, '')
    .replace(/<\/UNTRUSTED_[A-Z_]+>\n?/g, '')
    .replace(/<SEMI_TRUSTED_[A-Z_]+>\n?/g, '')
    .replace(/<\/SEMI_TRUSTED_[A-Z_]+>\n?/g, '');
}
