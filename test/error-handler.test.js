/**
 * Tests for the top-level error handler (#312).
 *
 * Verifies that:
 *  1. Unhandled exceptions from route handlers produce a 500 whose body
 *     matches Fastify's default shape — the existing 91-byte response
 *     format must not regress (that's the baseline consumers rely on).
 *  2. The error's stack is actually logged (with method/url/hostname
 *     context), so production debugging has a real trace.
 *  3. 4xx errors are NOT stack-logged (they're expected client errors).
 *
 * Uses a minimal Fastify instance so the test exercises only the handler,
 * not the full server's auth/routing stack.
 */

import { describe, it, before, after } from 'node:test';
import assert from 'node:assert';
import Fastify from 'fastify';
import { registerErrorHandler } from '../src/utils/error-handler.js';

class LogCapture {
  constructor() { this.lines = []; }
  write(chunk) {
    try { this.lines.push(JSON.parse(chunk)); } catch { /* non-JSON */ }
    return true;
  }
  errorLines() {
    return this.lines.filter((l) => l.level >= 50);
  }
  clear() { this.lines.length = 0; }
}

describe('registerErrorHandler (#312)', () => {
  let app;
  const capture = new LogCapture();

  before(async () => {
    app = Fastify({
      logger: { level: 'error', stream: capture },
      disableRequestLogging: true
    });
    registerErrorHandler(app);
    app.get('/throw500', async () => { throw new Error('synthetic 5xx for test'); });
    app.get('/throw400', async () => {
      const err = new Error('bad client input');
      err.statusCode = 400;
      throw err;
    });
  });

  after(async () => { await app.close(); });

  it('500 response body matches Fastify default shape (no regression)', async () => {
    capture.clear();
    const res = await app.inject({ method: 'GET', url: '/throw500' });
    assert.strictEqual(res.statusCode, 500);
    assert.deepStrictEqual(res.json(), {
      statusCode: 500,
      error: 'Internal Server Error',
      message: 'synthetic 5xx for test'
    });
  });

  it('500 logs include the stack and request context', async () => {
    capture.clear();
    await app.inject({ method: 'GET', url: '/throw500', headers: { host: 'example.test' } });
    const line = capture.errorLines().find((l) => l.msg === 'Unhandled 5xx error');
    assert.ok(line, `expected 'Unhandled 5xx error' log line, got: ${JSON.stringify(capture.errorLines())}`);
    assert.strictEqual(line.method, 'GET');
    assert.strictEqual(line.url, '/throw500');
    assert.strictEqual(line.hostname, 'example.test');
    assert.ok(line.err && line.err.stack, 'expected err.stack in log');
    assert.ok(line.err.stack.includes('synthetic 5xx'), 'stack should identify the error');
  });

  it('4xx errors do not trigger the 5xx stack log', async () => {
    capture.clear();
    const res = await app.inject({ method: 'GET', url: '/throw400' });
    assert.strictEqual(res.statusCode, 400);
    const unhandled = capture.errorLines().filter((l) => l.msg === 'Unhandled 5xx error');
    assert.strictEqual(unhandled.length, 0, '4xx must not produce a 5xx stack log');
  });
});

// #376: Fastify-internal errors that fire BEFORE any user hook
// runs (notably FST_ERR_BAD_URL on malformed percent-encoding)
// previously bypassed every CORS-injecting handler in JSS, leaving
// the 400 response with no Access-Control-Allow-* headers — browsers
// surfaced the response as a CORS error instead of the real status.
// The fix uses Fastify's `frameworkErrors` option in createServer
// to attach the CORS header set whenever the bad request carried
// an `Origin` header.
describe('frameworkErrors injects CORS headers on FST_ERR_BAD_URL (#376)', () => {
  let server;
  let baseUrl;

  before(async () => {
    const { createServer } = await import('../src/server.js');
    server = createServer({ logger: false, forceCloseConnections: true });
    await server.listen({ port: 0, host: '127.0.0.1' });
    const addr = server.server.address();
    baseUrl = `http://127.0.0.1:${addr.port}`;
  });

  after(async () => {
    await server.close();
  });

  it('returns 400 with full CORS headers for a malformed-percent URL + Origin', async () => {
    // `%g1` is the canonical FST_ERR_BAD_URL trigger — `g` isn't a
    // valid hex digit, so the percent-decode bails before any route
    // handler is even resolved.
    const r = await fetch(`${baseUrl}/foo%g1`, {
      headers: { Origin: 'https://example.com' },
    });
    assert.strictEqual(r.status, 400);
    // CORS headers are what was missing pre-fix. ACAO should mirror
    // the request Origin (not `*`), since the request explicitly
    // sent one — that's what getCorsHeaders does.
    assert.strictEqual(r.headers.get('access-control-allow-origin'), 'https://example.com');
    assert.match(r.headers.get('access-control-allow-methods') || '', /GET/);
    assert.ok(r.headers.get('access-control-allow-headers'), 'ACAH must be set');
    assert.ok(r.headers.get('access-control-expose-headers'), 'ACEH must be set');
    // Body uses HTTP status text ("Bad Request"), not err.name
    // ("FastifyError") — matches Fastify's default body shape so
    // any pre-fix client parsing `error` keeps working.
    const body = await r.json();
    assert.strictEqual(body.error, 'Bad Request');
    assert.strictEqual(body.code, 'FST_ERR_BAD_URL');
    assert.strictEqual(body.statusCode, 400);
  });

  it('returns CORS headers (ACAO=*) and well-shaped JSON for the same bad URL without an Origin', async () => {
    // Non-browser clients without an Origin still receive the full
    // CORS header set — consistent with the rest of the server,
    // where the global onRequest hook always sets CORS. ACAO
    // defaults to `*` when no Origin was sent (per getCorsHeaders).
    const r = await fetch(`${baseUrl}/foo%g1`);
    assert.strictEqual(r.status, 400);
    assert.strictEqual(r.headers.get('access-control-allow-origin'), '*');
    assert.match(r.headers.get('access-control-allow-methods') || '', /GET/);
    assert.ok(r.headers.get('access-control-allow-headers'), 'ACAH must be set');
    const body = await r.json();
    assert.strictEqual(body.error, 'Bad Request');
    assert.strictEqual(body.code, 'FST_ERR_BAD_URL');
    assert.strictEqual(body.statusCode, 400);
  });

  it('does NOT regress: a normal 404 still carries CORS via the wildcard handler', async () => {
    // Belt-and-suspenders: the frameworkErrors hook shouldn't have
    // displaced any existing CORS behavior on responses that go
    // through the wildcard handler. Ask for a path that hits the
    // LDP wildcard and 404s (no such resource), confirm CORS.
    const r = await fetch(`${baseUrl}/nonexistent/deep/path`, {
      headers: { Origin: 'https://example.com' },
    });
    // Could be 401 or 404 depending on auth defaults; in either case
    // CORS must be present.
    assert.ok([401, 404].includes(r.status), `expected 401 or 404, got ${r.status}`);
    assert.ok(r.headers.get('access-control-allow-origin'),
      'ACAO must be set on the normal-handler error path too');
  });
});
