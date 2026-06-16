/**
 * Port + URL helpers for `jss start` (#557): findFreePort shifts off a
 * busy port (Vite-style); formatUrl turns a bind host into an openable
 * banner URL.
 */

import { describe, it } from 'node:test';
import assert from 'node:assert';
import { createServer } from 'net';
import { findFreePort, formatUrl } from '../src/utils/port.js';

const HOST = '127.0.0.1';

function listen(port, host) {
  return new Promise((resolve, reject) => {
    const srv = createServer();
    srv.once('error', reject);
    srv.listen(port, host, () => resolve(srv));
  });
}
function close(srv) {
  return new Promise((resolve) => srv.close(resolve));
}
function freePort(host) {
  return new Promise((resolve, reject) => {
    const srv = createServer();
    srv.once('error', reject);
    srv.listen(0, host, () => {
      const { port } = srv.address();
      srv.close(() => resolve(port));
    });
  });
}

describe('formatUrl (#557)', () => {
  it('rewrites wildcard bind addresses to localhost', () => {
    assert.strictEqual(formatUrl('0.0.0.0', 4443), 'http://localhost:4443');
    assert.strictEqual(formatUrl('::', 4443), 'http://localhost:4443');
    assert.strictEqual(formatUrl('*', 4443), 'http://localhost:4443');
  });

  it('passes a normal host through unchanged', () => {
    assert.strictEqual(formatUrl('example.com', 8080), 'http://example.com:8080');
    assert.strictEqual(formatUrl('127.0.0.1', 3000), 'http://127.0.0.1:3000');
  });

  it('brackets an IPv6 literal', () => {
    assert.strictEqual(formatUrl('::1', 4443), 'http://[::1]:4443');
    assert.strictEqual(formatUrl('fe80::1', 4443), 'http://[fe80::1]:4443');
  });

  it('honours the protocol argument', () => {
    assert.strictEqual(formatUrl('example.com', 443, 'https'), 'https://example.com:443');
    assert.strictEqual(formatUrl('0.0.0.0', 4443, 'https'), 'https://localhost:4443');
  });
});

describe('findFreePort (#557)', () => {
  it('returns the requested port when it is free', async () => {
    const p = await freePort(HOST);
    assert.strictEqual(await findFreePort(p, HOST), p);
  });

  it('shifts to the next free port when the requested one is busy', async () => {
    const p = await freePort(HOST);
    const blocker = await listen(p, HOST);
    try {
      const got = await findFreePort(p, HOST);
      assert.ok(got > p, `expected a port above ${p}, got ${got}`);
      assert.ok(got < p + 10, 'should stay within the probe window');
    } finally {
      await close(blocker);
    }
  });

  it('returns null when every port in the window is taken', async () => {
    const p = await freePort(HOST);
    const a = await listen(p, HOST);
    const b = await listen(p + 1, HOST);
    try {
      // window of 2 — both taken → no free port
      assert.strictEqual(await findFreePort(p, HOST, 2), null);
    } finally {
      await close(a);
      await close(b);
    }
  });

  it('re-throws a non-EADDRINUSE bind error instead of reporting "no free port"', async () => {
    // 192.0.2.0/24 (TEST-NET-1) isn't a local interface → EADDRNOTAVAIL,
    // which is a real failure, not a busy port. Must propagate so the CLI
    // surfaces the actual cause rather than "no free port found".
    await assert.rejects(
      () => findFreePort(40000, '192.0.2.1', 1),
      (err) => err && err.code !== undefined && err.code !== 'EADDRINUSE',
    );
  });
});
