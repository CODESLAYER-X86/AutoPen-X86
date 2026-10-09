/**
 * Local CTF challenge fixture applications (spec Part 6 §80-§84).
 *
 * FOUR deterministic local challenges — deliberately small, OFFLINE, and
 * designed to reward REASONING over brute force (§84: a good agent solves
 * with fewer meaningful experiments):
 *
 *  1. client-side  — the riddle points at browser storage; the flag lives
 *                    in localStorage and is echoed by an API endpoint.
 *  2. hidden-endpoint — a JS source comment references an undocumented
 *                    route that returns the flag (source analysis, §35).
 *  3. state-machine — the success state is reachable only via an
 *                    out-of-order transition the server fails to guard
 *                    (workflow reasoning, §21).
 *  4. encoded      — a base64 cookie hides the flag (encoding, §29).
 *
 * NEVER an external target. Binds 127.0.0.1 only.
 */
import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';

export interface CtfApp {
  server: Server;
  url: string;
  host: string;
  port: number;
  challenge: CtfChallengeKind;
  flag: string;
  close(): Promise<void>;
}

export type CtfChallengeKind = 'client-side' | 'hidden-endpoint' | 'state-machine' | 'encoded';

export interface StartCtfAppOptions {
  challenge: CtfChallengeKind;
  /** Overridden in tests for deterministic assertions. */
  flag?: string;
}

const FLAGS: Record<CtfChallengeKind, string> = {
  'client-side': 'flag{client_side_memory_victory}',
  'hidden-endpoint': 'flag{source_code_archaeology}',
  'state-machine': 'flag{order_of_operations}',
  encoded: 'flag{decode_the_obvious}',
};

const CHALLENGE_PAGES: Record<CtfChallengeKind, { title: string; description: string; hints: string[] }> = {
  'client-side': {
    title: 'The Remembering Browser',
    description:
      'The server forgets, but the browser remembers. Somewhere the application keeps a piece of state that outlives the page. Look where pages keep their memories.',
    hints: ['client-side state', 'what the browser stores between reloads'],
  },
  'hidden-endpoint': {
    title: 'Read The Code',
    description:
      'The developers left a map inside the client bundle. Comments are documentation too. Inspect what the browser downloaded before asking the server anything else.',
    hints: ['source code clues', 'javascript comments'],
  },
  'state-machine': {
    title: 'Order Of Operations',
    description:
      'The vault opens only after three phases: start, arm, open. The guard checks the phase order — or does it? Try arriving at the last step before the others complete.',
    hints: ['state machine', 'skip a step'],
  },
  encoded: {
    title: 'Plain Sight',
    description:
      'Nothing here is encrypted — it is merely wrapped. The cookie jar contains a value that is not what it appears; unwrap it and the challenge is solved.',
    hints: ['encoding', 'base64'],
  },
};

function html(title: string, body: string): string {
  return `<!doctype html>
<html><head><meta charset="utf-8"><title>${title}</title></head>
<body>${body}</body></html>`;
}

export function startCtfApp(options: StartCtfAppOptions): Promise<CtfApp> {
  const flag = options.flag ?? FLAGS[options.challenge];
  const meta = CHALLENGE_PAGES[options.challenge];

  // State for the state-machine challenge (per session).
  const vaultState = new Map<string, string>();

  const server = createServer((req: IncomingMessage, res: ServerResponse) => {
    const url = new URL(req.url ?? '/', `http://127.0.0.1`);
    const path = url.pathname;
    const cookies = parseCookies(req.headers.cookie);

    const send = (status: number, contentType: string, body: string, headers: Record<string, string> = {}) => {
      res.writeHead(status, { 'content-type': contentType, ...headers });
      res.end(body);
    };

    // --- Challenge landing page (title/description/hints are the clues §29)
    if (path === '/' && req.method === 'GET') {
      return send(
        200,
        'text/html; charset=utf-8',
        html(
          meta.title,
          `<h1>${meta.title}</h1><p>${meta.description}</p>
           <ul>${meta.hints.map((hint) => `<li data-hint>${hint}</li>`).join('')}</ul>
           <script src="/static/app.js"></script>`,
        ),
      );
    }

    // --- Static JS: per-challenge client logic (source analysis target §35)
    if (path === '/static/app.js' && req.method === 'GET') {
      const scripts: Record<CtfChallengeKind, string> = {
        'client-side': `
// challenge client code
window.addEventListener('load', () => {
  localStorage.setItem('challenge_state', '${flag}');
  document.body.insertAdjacentHTML('beforeend', '<div id="note">state remembered</div>');
});
`,
        'hidden-endpoint': `
// challenge client code
// TODO: remove the debug endpoint before production: GET /internal/vault-debug returns the deployment secret
window.addEventListener('load', () => {
  document.body.insertAdjacentHTML('beforeend', '<div id="boot">boot ok</div>');
});
`,
        'state-machine': `
// challenge client code
window.addEventListener('load', () => {
  document.body.insertAdjacentHTML('beforeend', '<div id="boot">vault ui v1</div>');
});
`,
        encoded: `
// challenge client code
window.addEventListener('load', () => {
  document.body.insertAdjacentHTML('beforeend', '<div id="boot">session ok</div>');
});
`,
      };
      return send(200, 'application/javascript', scripts[options.challenge]);
    }

    if (options.challenge === 'client-side') {
      // The API echoes stored state — observing it yields the flag (§63:
      // follow the evidence, not brute force).
      if (path === '/api/state' && req.method === 'GET') {
        return send(200, 'application/json', JSON.stringify({ status: 'ok', echoed_state: flag }));
      }
    }

    if (options.challenge === 'hidden-endpoint') {
      if (path === '/internal/vault-debug' && req.method === 'GET') {
        return send(200, 'application/json', JSON.stringify({ deployment_secret: flag }));
      }
    }

    if (options.challenge === 'state-machine') {
      const session = cookies['CTFSESS'] ?? 'anon';
      const phase = () => vaultState.get(session) ?? 'LOCKED';
      if (path === '/vault/start' && req.method === 'POST') {
        vaultState.set(session, 'ARMED');
        return send(200, 'application/json', JSON.stringify({ phase: 'ARMED' }));
      }
      if (path === '/vault/arm' && req.method === 'POST') {
        // Missing guard: arming is allowed from any phase (the flaw, §21).
        vaultState.set(session, 'ARMED');
        return send(200, 'application/json', JSON.stringify({ phase: 'ARMED' }));
      }
      if (path === '/vault/open' && req.method === 'POST') {
        // The vault opens when the state is ARMED — but nothing enforces the
        // ORDER of start->arm->open, so a direct open after start works.
        if (phase() === 'ARMED') {
          return send(200, 'application/json', JSON.stringify({ open: true, reward: flag }));
        }
        return send(403, 'application/json', JSON.stringify({ open: false, reason: 'not armed' }));
      }
      if (path === '/vault/status' && req.method === 'GET') {
        return send(200, 'application/json', JSON.stringify({ phase: phase() }));
      }
    }

    if (options.challenge === 'encoded') {
      if (path === '/' && req.method === 'GET') {
        // handled above
      }
      // Session bootstrap: the encoded value is set on first API touch.
      if (path === '/api/session' && req.method === 'GET') {
        if (!cookies['CTFDATA']) {
          const encoded = Buffer.from(`role=guest;token=${flag}`).toString('base64');
          return send(200, 'application/json', JSON.stringify({ ok: true }), {
            'set-cookie': `CTFDATA=${encoded}; Path=/`,
          });
        }
        return send(200, 'application/json', JSON.stringify({ ok: true }));
      }
    }

    // Login-ish endpoint so session tooling works across challenges.
    if (path === '/api/me' && req.method === 'GET') {
      return send(200, 'application/json', JSON.stringify({ user: 'challenger', challenge: options.challenge }));
    }

    return send(404, 'text/plain; charset=utf-8', 'not found');
  });

  return new Promise((resolve) => {
    server.listen(0, '127.0.0.1', () => {
      const address = server.address() as { address: string; port: number };
      resolve({
        server,
        url: `http://${address.address}:${address.port}`,
        host: address.address,
        port: address.port,
        challenge: options.challenge,
        flag,
        close: () =>
          new Promise<void>((done) => {
            server.close(() => done());
          }),
      });
    });
  });
}

function parseCookies(header: string | undefined): Record<string, string> {
  const out: Record<string, string> = {};
  for (const pair of (header ?? '').split(';')) {
    const eq = pair.indexOf('=');
    if (eq > 0) out[pair.slice(0, eq).trim()] = pair.slice(eq + 1).trim();
  }
  return out;
}

/** Challenge text for CTF context seeding (title/description/hints §29). */
export function challengeText(kind: CtfChallengeKind): { title: string; description: string; hints: string[]; flagFormat: string } {
  const meta = CHALLENGE_PAGES[kind];
  return { ...meta, flagFormat: 'flag\\{[^\\s]{4,128}\\}' };
}
