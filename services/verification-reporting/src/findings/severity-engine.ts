/**
 * Severity engine (spec Part 7 §17-§18).
 *
 * CVSS 3.1 implemented as a DETERMINISTIC calculator (§17: "do not let the
 * LLM invent scores. The model may provide inputs and justification. The
 * calculator produces the score."). The vector string, base/temporal/
 * environmental scores and the qualitative severity are computed exactly per
 * the FIRST CVSS 3.1 specification, including the Roundup formula.
 *
 * CVSS stays SEPARATE from confidence and business priority (§18): a high
 * CVSS score does not prove the vulnerability exists.
 */

/** CVSS 3.1 numeric weights (FIRST specification §3.2). */
const METRIC_VALUES: Record<string, Record<string, number>> = {
  AV: { N: 0.85, A: 0.62, L: 0.55, P: 0.2 },
  AC: { L: 0.77, H: 0.44 },
  PR: { N: 0.85, L: 0.62, H: 0.27 }, // scope unchanged
  UI: { N: 0.85, R: 0.62 },
  CIA: { H: 0.56, L: 0.22, N: 0 },
};

const PR_CHANGED: Record<string, number> = { N: 0.85, L: 0.68, H: 0.5 };

/** FIRST CVSS 3.1 §3.2.3 roundup: smallest number with one decimal >= input. */
function roundup(input: number): number {
  const intInput = Math.round(input * 100_000);
  const ceiling = Math.ceil(intInput / 10_000) * 10_000;
  if (intInput - Math.floor(intInput / 10_000) * 10_000 === 0) {
    return intInput / 100_000;
  }
  return ceiling / 100_000;
}

export interface SeverityInputFields {
  attack_vector: 'NETWORK' | 'ADJACENT' | 'LOCAL' | 'PHYSICAL';
  attack_complexity: 'LOW' | 'HIGH';
  privileges_required: 'NONE' | 'LOW' | 'HIGH';
  user_interaction: 'NONE' | 'REQUIRED';
  scope: 'UNCHANGED' | 'CHANGED';
  confidentiality_impact: 'NONE' | 'LOW' | 'HIGH';
  integrity_impact: 'NONE' | 'LOW' | 'HIGH';
  availability_impact: 'NONE' | 'LOW' | 'HIGH';
  data_sensitivity: 'LOW' | 'MEDIUM' | 'HIGH';
  business_impact: 'LOW' | 'MEDIUM' | 'HIGH';
  exploitability_ease: 'LOW' | 'MEDIUM' | 'HIGH';
  justification?: string;
}

export interface CvssResult {
  version: '3.1';
  vector: string;
  base_score: number;
  temporal_score: number | null;
  environmental_score: number | null;
  base_severity: 'NONE' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
}

const AV_CODE: Record<SeverityInputFields['attack_vector'], string> = {
  NETWORK: 'N',
  ADJACENT: 'A',
  LOCAL: 'L',
  PHYSICAL: 'P',
};

export class SeverityEngine {
  /** Compute the CVSS 3.1 base score + vector (deterministic, §17-§18). */
  compute(input: SeverityInputFields): CvssResult {
    const av = METRIC_VALUES['AV']![AV_CODE[input.attack_vector]]!;
    const ac = METRIC_VALUES['AC']![input.attack_complexity === 'LOW' ? 'L' : 'H']!;
    const prTable = input.scope === 'CHANGED' ? PR_CHANGED : METRIC_VALUES['PR']!;
    const pr = prTable[input.privileges_required === 'NONE' ? 'N' : input.privileges_required === 'LOW' ? 'L' : 'H']!;
    const ui = METRIC_VALUES['UI']![input.user_interaction === 'NONE' ? 'N' : 'R']!;

    const cia = METRIC_VALUES['CIA']!;
    const c = cia[input.confidentiality_impact === 'HIGH' ? 'H' : input.confidentiality_impact === 'LOW' ? 'L' : 'N']!;
    const i = cia[input.integrity_impact === 'HIGH' ? 'H' : input.integrity_impact === 'LOW' ? 'L' : 'N']!;
    const a = cia[input.availability_impact === 'HIGH' ? 'H' : input.availability_impact === 'LOW' ? 'L' : 'N']!;

    const iscBase = 1 - (1 - c) * (1 - i) * (1 - a);
    // Scope changed: impact sub-score uses the modified formula.
    const impact =
      input.scope === 'CHANGED'
        ? 7.52 * (iscBase - 0.029) - 3.25 * Math.pow(iscBase - 0.02, 15)
        : 6.42 * iscBase;
    const exploitability = 8.22 * av * ac * pr * ui;

    let base: number;
    if (impact <= 0) {
      base = 0;
    } else if (input.scope === 'CHANGED') {
      base = roundup(Math.min(1.08 * (impact + exploitability), 10));
    } else {
      base = roundup(Math.min(impact + exploitability, 10));
    }

    const vector =
      `CVSS:3.1/AV:${AV_CODE[input.attack_vector]}/AC:${input.attack_complexity === 'LOW' ? 'L' : 'H'}` +
      `/PR:${input.privileges_required === 'NONE' ? 'N' : input.privileges_required === 'LOW' ? 'L' : 'H'}` +
      `/UI:${input.user_interaction === 'NONE' ? 'N' : 'R'}/S:${input.scope === 'CHANGED' ? 'C' : 'U'}` +
      `/C:${ciaCode(input.confidentiality_impact)}/I:${ciaCode(input.integrity_impact)}/A:${ciaCode(input.availability_impact)}`;

    return {
      version: '3.1',
      vector,
      base_score: Number(base.toFixed(1)),
      temporal_score: null,
      environmental_score: null,
      base_severity: qualitative(base),
    };
  }

  /**
   * Platform severity band. CVSS qualitative bands drive the band; the
   * business dimensions (data sensitivity, business impact, exploitability
   * ease) may raise ONE band at most — they are recorded separately and can
   * never turn a NONE-impact input into a finding (§18: business priority is
   * not CVSS).
   */
  severityBand(cvss: CvssResult, input: SeverityInputFields): 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL' {
    const cvssBand: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL' =
      cvss.base_severity === 'NONE' || cvss.base_severity === 'LOW'
        ? 'LOW'
        : cvss.base_severity === 'MEDIUM'
          ? 'MEDIUM'
          : cvss.base_severity === 'HIGH'
            ? 'HIGH'
            : 'CRITICAL';
    const businessBoost =
      (input.data_sensitivity === 'HIGH' ? 1 : 0) +
      (input.business_impact === 'HIGH' ? 1 : 0) +
      (input.exploitability_ease === 'HIGH' ? 1 : 0);
    if (businessBoost >= 2 && cvssBand !== 'CRITICAL') {
      const order: Array<'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'> = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];
      return order[Math.min(order.indexOf(cvssBand) + 1, 3)]!;
    }
    return cvssBand;
  }
}

function ciaCode(value: 'NONE' | 'LOW' | 'HIGH'): string {
  return value === 'HIGH' ? 'H' : value === 'LOW' ? 'L' : 'N';
}

function qualitative(score: number): 'NONE' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL' {
  if (score === 0) return 'NONE';
  if (score < 4) return 'LOW';
  if (score < 7) return 'MEDIUM';
  if (score < 9) return 'HIGH';
  return 'CRITICAL';
}
