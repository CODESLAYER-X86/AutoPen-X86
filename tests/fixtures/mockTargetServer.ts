/**
 * Safe local test-target server (spec §34): a deliberately mock application
 * for tests. Never an external/real target. Serves:
 *   GET  /            — a small HTML page
 *   GET  /api/status  — JSON status
 *   POST /login       — sets a cookie
 */
import { createServer, type Server } from 'node:http';

export interface MockTarget {
  server: Server;
  url: string;
  port: number;
  close(): Promise<void>;
}

export function startMockTarget(): Promise<MockTarget> {
  const server = createServer((req, res) => {
    const url = req.url ?? '/';
    if (url === '/' || url === '/index.html') {
      res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
      res.end(
        [
          '<!doctype html><html><head><title>Mock Lab App</title></head><body>',
          '<h1>Mock Lab Application</h1>',
          '<form action="/login" method="post">',
          '<input name="username"><input type="password" name="password">',
          '</form>',
          '<!-- TODO: remove debug endpoint /api/status before production -->',
          '</body></html>',
        ].join(''),
      );
      return;
    }
    if (url === '/api/status') {
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ ok: true, version: '1.0.0-mock', authenticated: false }));
      return;
    }
    if (url === '/login' && req.method === 'POST') {
      res.writeHead(200, {
        'content-type': 'application/json',
        'set-cookie': 'MOCKSESS=abc123; HttpOnly; Path=/',
      });
      res.end(JSON.stringify({ success: true }));
      return;
    }
    res.writeHead(404, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ error: 'not found' }));
  });

  return new Promise((resolve) => {
    server.listen(0, '127.0.0.1', () => {
      const address = server.address();
      const port = typeof address === 'object' && address !== null ? address.port : 0;
      resolve({
        server,
        port,
        url: `http://127.0.0.1:${port}`,
        close: () =>
          new Promise<void>((resolveClose, rejectClose) => {
            server.close((error) => (error ? rejectClose(error) : resolveClose()));
          }),
      });
    });
  });
}
