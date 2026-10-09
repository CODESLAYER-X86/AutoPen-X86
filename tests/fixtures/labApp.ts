/**
 * Local lab test application (spec Part 3 §83) — a deliberately vulnerable
 * LOCAL fixture for integration/security tests. NEVER an external target.
 *
 * Provides:
 *   - login form (HTML) + POST /login (cookie + localStorage workflow)
 *   - multiple users with distinct roles (userA, userB, admin)
 *   - session cookies, localStorage tokens (auth state)
 *   - API endpoints with per-identity authorization differences
 *   - redirects (within app, and to an out-of-scope host)
 *   - WebSocket echo (ws + wss-less) with oversized-message endpoint
 *   - downloads (binary)
 *   - dynamic DOM (JS updates)
 *   - multipart upload endpoint
 *   - oversized response endpoint (limit testing)
 */
import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import { WebSocketServer, type WebSocket } from 'ws';

export interface LabApp {
  server: Server;
  wss: WebSocketServer;
  url: string;
  host: string;
  port: number;
  close(): Promise<void>;
}

interface LabUser {
  username: string;
  password: string;
  role: string;
}

const USERS: Record<string, LabUser> = {
  usera: { username: 'usera', password: 'password-a', role: 'user' },
  userb: { username: 'userb', password: 'password-b', role: 'user' },
  admin: { username: 'admin', password: 'admin-secret', role: 'admin' },
};

const SESSIONS = new Map<string, { user: string; role: string }>();

/** Part 4 Fixture B: per-user workflow state (server-side). */
const WORKFLOW_STATE = new Map<string, string>();

function parseCookies(header: string | undefined): Record<string, string> {
  const out: Record<string, string> = {};
  for (const pair of (header ?? '').split(';')) {
    const eq = pair.indexOf('=');
    if (eq > 0) out[pair.slice(0, eq).trim()] = pair.slice(eq + 1).trim();
  }
  return out;
}

function readBody(req: IncomingMessage, limit = 5 * 1024 * 1024): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let total = 0;
    req.on('data', (chunk: Buffer) => {
      total += chunk.byteLength;
      if (total > limit) {
        reject(new Error('body too large'));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

function parseMultipart(body: Buffer, contentType: string): { fields: Record<string, string>; files: Array<{ name: string; filename: string; bytes: number }> } {
  const match = /boundary=(.+)$/.exec(contentType);
  if (!match) return { fields: {}, files: [] };
  const boundary = `--${match[1]!}`;
  const parts = body.toString('binary').split(boundary).filter((p) => p.includes('Content-Disposition'));
  const fields: Record<string, string> = {};
  const files: Array<{ name: string; filename: string; bytes: number }> = [];
  for (const part of parts) {
    const disposition = /Content-Disposition: form-data; name="([^"]+)"(?:; filename="([^"]+)")?/.exec(part);
    if (!disposition) continue;
    const [, name, filename] = disposition;
    const content = part.split('\r\n\r\n').slice(1).join('\r\n\r\n').replace(/\r\n$/, '');
    if (filename) {
      files.push({ name: name!, filename: filename!, bytes: Buffer.byteLength(content, 'binary') });
    } else {
      fields[name!] = content;
    }
  }
  return { fields, files };
}

function sessionCookieValue(req: IncomingMessage): string | null {
  return parseCookies(req.headers.cookie).LABSESS ?? null;
}

function currentUser(req: IncomingMessage): { user: string; role: string } | null {
  const token = sessionCookieValue(req);
  if (!token) return null;
  return SESSIONS.get(token) ?? null;
}

const LOGIN_PAGE = `<!doctype html>
<html>
<head><title>Lab App — Login</title>
<script>
  // Dynamic DOM: JS builds a timestamped status element (§83 dynamic DOM).
  window.addEventListener('DOMContentLoaded', () => {
    const el = document.createElement('div');
    el.id = 'js-status';
    el.setAttribute('data-testid', 'js-status');
    el.textContent = 'js-ready ' + new Date().toISOString();
    document.body.appendChild(el);
    try { localStorage.setItem('app', JSON.stringify({ client: 'lab', ts: Date.now() })); } catch (e) {}
    try { sessionStorage.setItem('visit', '1'); } catch (e) {}
  });
</script>
</head>
<body>
  <h1>Lab Application</h1>
  <form id="login-form" action="/login" method="post">
    <label for="username">Username</label>
    <input id="username" name="username" placeholder="username" autocomplete="off">
    <label for="password">Password</label>
    <input id="password" name="password" type="password" placeholder="password">
    <button type="submit" role="button" name="login">Login</button>
  </form>
  <nav><a href="/dashboard">Dashboard</a> <a href="/api/status">Status</a> <a href="/download/report.bin">Download</a></nav>
  <iframe src="/frame" title="embedded"></iframe>
</body>
</html>`;

const DASHBOARD_PAGE = (user: string, role: string) => `<!doctype html>
<html>
<head><title>Lab App — Dashboard</title></head>
<body>
  <h1>Dashboard</h1>
  <p id="who" data-testid="who">${user} (${role})</p>
  <script src="/static/app.js"></script>
</body>
</html>`;

const APP_JS = `console.log('lab app js loaded');
window.labReady = true;`;

export function startLabApp(): Promise<LabApp> {
  const server = createServer((req, res) => {
    void handle(req, res).catch((error) => {
      res.writeHead(500, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ error: 'internal', detail: String(error) }));
    });
  });

  const wss = new WebSocketServer({ noServer: true });
  wss.on('connection', (ws: WebSocket) => {
    ws.on('message', (data) => {
      // Echo back with a prefix (direction verifiable).
      const payload = typeof data === 'string' ? data : Buffer.from(data as ArrayBuffer).toString('utf8');
      if (payload === 'SEND_OVERSIZED') {
        const big = 'x'.repeat(2 * 1024 * 1024); // 2 MiB — over default limits
        ws.send(big);
        return;
      }
      ws.send(`echo:${payload}`);
    });
  });

  server.on('upgrade', (request, socket, head) => {
    if (request.url?.startsWith('/ws')) {
      wss.handleUpgrade(request, socket, head, (ws) => {
        wss.emit('connection', ws, request);
      });
    } else {
      socket.destroy();
    }
  });

  async function handle(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const url = (req.url ?? '/').split('?')[0]!;
    const method = (req.method ?? 'GET').toUpperCase();

    // --- Login workflow (§83) ---------------------------------------------
    if (url === '/' || url === '/login' && method === 'GET') {
      res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
      res.end(LOGIN_PAGE);
      return;
    }
    if (url === '/login' && method === 'POST') {
      const body = (await readBody(req)).toString('utf8');
      const params = new URLSearchParams(body);
      const username = params.get('username') ?? '';
      const password = params.get('password') ?? '';
      const user = USERS[username];
      if (!user || user.password !== password) {
        res.writeHead(401, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ success: false, error: 'invalid credentials' }));
        return;
      }
      const token = `sess-${username}-${Math.random().toString(36).slice(2, 10)}`;
      SESSIONS.set(token, { user: user.username, role: user.role });
      res.writeHead(200, {
        'content-type': 'application/json',
        'set-cookie': `LABSESS=${token}; HttpOnly; Path=/; SameSite=Lax`,
      });
      res.end(
        JSON.stringify({
          success: true,
          role: user.role,
          storage_hint: { token: `local-${token}`, role: user.role },
        }),
      );
      return;
    }
    if (url === '/logout' && method === 'POST') {
      const token = sessionCookieValue(req);
      if (token) SESSIONS.delete(token);
      res.writeHead(200, {
        'content-type': 'application/json',
        'set-cookie': 'LABSESS=; Path=/; Max-Age=0',
      });
      res.end(JSON.stringify({ success: true }));
      return;
    }

    // --- Public API ---------------------------------------------------------
    if (url === '/api/status') {
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ ok: true, version: '1.0.0-lab', authenticated: currentUser(req) !== null }));
      return;
    }
    if (url === '/api/echo' && method === 'POST') {
      const raw = await readBody(req);
      const contentType = String(req.headers['content-type'] ?? '');
      if (contentType.includes('application/json')) {
        try {
          const parsed = JSON.parse(raw.toString('utf8')) as Record<string, unknown>;
          res.writeHead(200, { 'content-type': 'application/json' });
          res.end(JSON.stringify({ received: parsed, content_type: 'application/json' }));
          return;
        } catch {
          res.writeHead(400, { 'content-type': 'application/json' });
          res.end(JSON.stringify({ error: 'invalid json' }));
          return;
        }
      }
      if (contentType.includes('multipart/form-data')) {
        const parsed = parseMultipart(raw, contentType);
        res.writeHead(200, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ received: parsed.fields, files: parsed.files, content_type: 'multipart/form-data' }));
        return;
      }
      if (contentType.includes('application/x-www-form-urlencoded')) {
        const fields = Object.fromEntries(new URLSearchParams(raw.toString('utf8')));
        res.writeHead(200, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ received: fields, content_type: 'application/x-www-form-urlencoded' }));
        return;
      }
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ received_bytes: raw.byteLength, content_type: contentType || 'unknown' }));
      return;
    }

    // --- Redirects (§83, for scope/redirect tests) ----------------------------
    if (url === '/redirect/login') {
      res.writeHead(302, { location: '/login' });
      res.end();
      return;
    }
    if (url === '/redirect/dashboard') {
      res.writeHead(302, { location: '/dashboard' });
      res.end();
      return;
    }
    if (url === '/redirect/external') {
      // Out-of-scope host — the engine MUST refuse to follow (§51).
      res.writeHead(302, { location: 'http://out-of-scope.example.com/payload' });
      res.end();
      return;
    }
    if (url === '/redirect/loop') {
      res.writeHead(302, { location: '/redirect/loop' });
      res.end();
      return;
    }

    // --- Authenticated pages + APIs (authorization differences) -----------
    const user = currentUser(req);
    if (url === '/dashboard' || url === '/frame') {
      if (!user) {
        res.writeHead(302, { location: '/login' });
        res.end();
        return;
      }
      res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
      res.end(DASHBOARD_PAGE(user.user, user.role));
      return;
    }
    if (url === '/api/me') {
      if (!user) {
        res.writeHead(401, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ error: 'authentication required' }));
        return;
      }
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ user: user.user, role: user.role }));
      return;
    }
    if (url === '/api/admin/users') {
      if (!user || user.role !== 'admin') {
        res.writeHead(403, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ error: 'admin role required' }));
        return;
      }
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(
        JSON.stringify({
          users: Object.values(USERS).map((u) => ({ username: u.username, role: u.role })),
        }),
      );
      return;
    }
    if (url === '/api/orders') {
      if (!user) {
        res.writeHead(401, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ error: 'authentication required' }));
        return;
      }
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(
        JSON.stringify({
          orders: [
            { id: 1, owner: 'usera', total: 100 },
            { id: 2, owner: 'userb', total: 200 },
          ],
          viewer: user.user,
        }),
      );
      return;
    }

    // --- Part 4 fixtures (spec §127) ---------------------------------------

    // Fixture A: object-level endpoint with PROPER ownership enforcement
    // (negative control for authorization reasoning). Order 1 -> usera,
    // order 2 -> userb; admin sees everything; others get 403.
    if (url.startsWith('/api/orders/') && /^\/api\/orders\/\d+$/.test(url) && method === 'GET') {
      const orderId = Number(url.split('/').pop());
      if (!user) {
        res.writeHead(401, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ error: 'authentication required' }));
        return;
      }
      const order = orderId === 1 ? { id: 1, owner: 'usera', total: 100 } : orderId === 2 ? { id: 2, owner: 'userb', total: 200 } : null;
      if (!order) {
        res.writeHead(404, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ error: 'not found' }));
        return;
      }
      if (user.role !== 'admin' && order.owner !== user.user) {
        res.writeHead(403, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ error: 'forbidden' }));
        return;
      }
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify(order));
      return;
    }

    // Fixture A: object-level endpoint with BROKEN ownership enforcement
    // (the deliberate authorization flaw for the reasoning pipeline: any
    // authenticated identity can read any note, including private data).
    if (url.startsWith('/api/notes/') && /^\/api\/notes\/\d+$/.test(url) && method === 'GET') {
      const noteId = Number(url.split('/').pop());
      if (!user) {
        res.writeHead(401, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ error: 'authentication required' }));
        return;
      }
      // Ownership NOT checked (intentional lab flaw): note 7 is usera's
      // private note with identity-bound content.
      const note =
        noteId === 7
          ? { id: 7, owner: 'usera', title: 'usera private note', content: 'usera-secret-note-content' }
          : noteId === 8
            ? { id: 8, owner: 'userb', title: 'userb private note', content: 'userb-secret-note-content' }
            : null;
      if (!note) {
        res.writeHead(404, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ error: 'not found' }));
        return;
      }
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify(note));
      return;
    }

    // Fixture B: workflow application (registration -> verification ->
    // payment-like state -> confirmation). Server-side state per session.
    if (url === '/api/workflow/register' && method === 'POST') {
      if (!user) {
        res.writeHead(401, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ error: 'authentication required' }));
        return;
      }
      const state = WORKFLOW_STATE.get(user.user) ?? 'REGISTERED';
      WORKFLOW_STATE.set(user.user, state === 'NONE' ? 'REGISTERED' : state);
      res.writeHead(201, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ state: 'REGISTERED', username: user.user }));
      return;
    }
    if (url === '/api/workflow/verify' && method === 'POST') {
      if (!user) {
        res.writeHead(401, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ error: 'authentication required' }));
        return;
      }
      const state = WORKFLOW_STATE.get(user.user) ?? 'REGISTERED';
      if (state !== 'REGISTERED') {
        res.writeHead(409, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ error: 'invalid state transition', from: state, to: 'VERIFIED' }));
        return;
      }
      WORKFLOW_STATE.set(user.user, 'VERIFIED');
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ state: 'VERIFIED' }));
      return;
    }
    if (url === '/api/workflow/pay' && method === 'POST') {
      if (!user) {
        res.writeHead(401, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ error: 'authentication required' }));
        return;
      }
      const state = WORKFLOW_STATE.get(user.user) ?? 'REGISTERED';
      if (state !== 'VERIFIED') {
        res.writeHead(409, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ error: 'invalid state transition', from: state, to: 'PAID' }));
        return;
      }
      WORKFLOW_STATE.set(user.user, 'PAID');
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ state: 'PAID' }));
      return;
    }
    if (url === '/api/workflow/confirm' && method === 'POST') {
      if (!user) {
        res.writeHead(401, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ error: 'authentication required' }));
        return;
      }
      // Business-logic flaw (deliberate lab flaw for §36/§122): confirmation
      // does NOT check that the workflow is in the PAID state.
      WORKFLOW_STATE.set(user.user, 'CONFIRMED');
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ state: 'CONFIRMED', note: 'confirmed without checking payment state' }));
      return;
    }
    if (url === '/api/workflow/status' && method === 'GET') {
      if (!user) {
        res.writeHead(401, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ error: 'authentication required' }));
        return;
      }
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ state: WORKFLOW_STATE.get(user.user) ?? 'REGISTERED' }));
      return;
    }

    // Fixture C: dynamic API — pagination, volatile timestamps, and a
    // schema-varying variant (differential testing surface).
    if (url === '/api/items' && method === 'GET') {
      const page = Number(new URL(req.url ?? '/', `http://${req.headers.host}`).searchParams.get('page') ?? '1');
      const items = [
        { id: page * 2 - 1, name: `item-${page * 2 - 1}`, generated_at: new Date().toISOString() },
        { id: page * 2, name: `item-${page * 2}`, generated_at: new Date().toISOString() },
      ];
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ page, total_pages: 3, items }));
      return;
    }
    if (url === '/api/items/vary' && method === 'GET') {
      // Response schema varies by ?mode= (schema-diff surface, §26).
      const mode = new URL(req.url ?? '/', `http://${req.headers.host}`).searchParams.get('mode') ?? 'a';
      const body =
        mode === 'a'
          ? { id: 1, name: 'alpha', generated_at: new Date().toISOString() }
          : { id: 1, name: 'alpha', generated_at: new Date().toISOString(), debug_trace: 'internal /app/handlers/items.py', stack: 'at handler (/app/main.py)' };
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify(body));
      return;
    }

    // --- Static assets --------------------------------------------------------
    if (url === '/static/app.js') {
      res.writeHead(200, { 'content-type': 'application/javascript' });
      res.end(APP_JS);
      return;
    }

    // --- Download (binary, §37) ------------------------------------------------
    if (url === '/download/report.bin') {
      const payload = Buffer.alloc(4096, 7);
      res.writeHead(200, {
        'content-type': 'application/octet-stream',
        'content-disposition': 'attachment; filename="report.bin"',
        'content-length': String(payload.byteLength),
      });
      res.end(payload);
      return;
    }

    // --- Oversized response (§48 limit testing) ---------------------------------
    if (url === '/api/oversized') {
      const payload = Buffer.alloc(5 * 1024 * 1024, 0x61); // 5 MiB
      res.writeHead(200, {
        'content-type': 'application/octet-stream',
        'content-length': String(payload.byteLength),
      });
      res.end(payload);
      return;
    }

    res.writeHead(404, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ error: 'not found', path: url }));
  }

  return new Promise((resolve) => {
    server.listen(0, '127.0.0.1', () => {
      const address = server.address();
      const port = typeof address === 'object' && address !== null ? address.port : 0;
      resolve({
        server,
        wss,
        url: `http://127.0.0.1:${port}`,
        host: '127.0.0.1',
        port,
        close: async () => {
          for (const client of wss.clients) client.terminate();
          await new Promise<void>((done) => wss.close(() => done()));
          await new Promise<void>((done) => server.close(() => done()));
        },
      });
    });
  });
}
