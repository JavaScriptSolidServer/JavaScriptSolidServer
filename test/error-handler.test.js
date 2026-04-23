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
