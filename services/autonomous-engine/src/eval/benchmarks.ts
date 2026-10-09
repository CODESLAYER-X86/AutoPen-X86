/**
 * Benchmark definitions (spec Part 6 §79-§80, §84).
 *
 * Deterministic local fixtures with KNOWN ground truth: expected findings,
 * expected dead ends, expected workflows. Every benchmark runs offline
 * against the fixture lab applications; metrics measure whether the
 * autonomous loop SOLVES with fewer meaningful experiments rather than
 * simply more requests (§84).
 */
import type { BenchmarkDefinition } from '@aegis/contracts';

export const BENCHMARKS: BenchmarkDefinition[] = [
  {
    name: 'lab-pentest-authorization',
    description:
      'Multi-user lab application with a broken-ownership notes API (IDOR), an enforced orders API (negative control) and a flawed workflow confirm step. The engine must verify the IDOR finding, respect the enforced control as a dead end, and avoid the volatile/debug endpoints as noise.',
    mode: 'PENTEST',
    expected_findings: [
      '/api/notes/{id} broken object ownership (IDOR) — cross-identity object data returned',
      'workflow confirm step missing paid-state prerequisite (business logic)',
    ],
    expected_dead_ends: ['/api/orders/{id} object ownership correctly enforced (403/404 for foreign objects)'],
    measures: [
      'time_to_first_finding',
      'time_to_verified_finding',
      'false_positive_rate',
      'duplicate_test_rate',
      'requests_per_finding',
      'coverage',
    ],
  },
  {
    name: 'lab-ctf-client-side',
    description:
      'Riddle-based CTF challenge: the clue points at client-side state; the flag is stored in localStorage and reflected in an API response. Solving requires clue interpretation -> storage inspection -> flag detection, NOT brute force.',
    mode: 'CTF',
    expected_findings: ['flag{client_side_memory_victory} detected from client-side state evidence'],
    expected_dead_ends: ['brute-force scanning of every storage key without following the clue'],
    measures: ['ctf_solve_rate', 'time_to_solve', 'tests_before_solve', 'false_leads', 'model_tokens'],
  },
  {
    name: 'lab-ctf-hidden-endpoint',
    description:
      'Source-code challenge: a comment in the application JavaScript references an undocumented endpoint that returns the flag. Requires source analysis, not scanning.',
    mode: 'CTF',
    expected_findings: ['flag{source_code_archaeology} discovered via the undocumented endpoint'],
    expected_dead_ends: ['known-path brute force without source analysis'],
    measures: ['ctf_solve_rate', 'clue_interpretation_quality', 'time_to_solve'],
  },
  {
    name: 'lab-ctf-state-machine',
    description:
      'State-machine challenge: the success state is reachable only by triggering an out-of-order transition the server fails to guard. Requires workflow reasoning, not payload injection.',
    mode: 'CTF',
    expected_findings: ['flag{order_of_operations} obtained via out-of-order state transition'],
    expected_dead_ends: ['direct flag fetch without completing the transition sequence'],
    measures: ['ctf_solve_rate', 'branch_efficiency', 'tests_before_solve'],
  },
  {
    name: 'lab-ctf-encoded',
    description:
      'Encoding challenge: a base64-encoded value in a cookie hides the flag. Requires recognizing encoding, not exploiting a vulnerability.',
    mode: 'CTF',
    expected_findings: ['flag{decode_the_obvious} recovered from the encoded cookie value'],
    expected_dead_ends: ['treating the encoded value as a session token to attack'],
    measures: ['ctf_solve_rate', 'retrieval_quality', 'time_to_solve'],
  },
];
