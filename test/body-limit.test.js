/**
 * Configurable bodyLimit (#474).
 *
 * Before #474 the per-request body cap was hard-coded to 10 MiB inside
 * createServer's fastifyOptions, so any operator who wanted to accept
 * larger `git push` payloads (e.g. an established app repo with several
 * MB of history) had no way to raise it.
 *
 * The fix exposes `bodyLimit` as a createServer option / CLI flag
 * (`--body-limit`) / env var (`JSS_BODY_LIMIT`) / config key, accepting
 * either a number (bytes) or a size string ("100MB", "1GB", …).
 *
 * Tests here verify the surface end-to-end — server actually rejects
 * over-size requests with 413, AND the size-string parsing path works
 * the same as the numeric path. The default (10 MiB) is covered
 * implicitly by every other test in the suite continuing to pass.
 */

import { describe, it, before, after, afterEach } from 'node:test';
import assert from 'node:assert';
import { createServer } from '../src/server.js';
import fs from 'fs-extra';

const TEST_DATA_DIR = './test-data-body-limit';

let server;
let baseUrl;
let originalDataRoot;

async function startWith(bodyLimit) {
  await fs.emptyDir(TEST_DATA_DIR);
  server = createServer({
    logger: false,
    forceCloseConnections: true,
    root: TEST_DATA_DIR,
    bodyLimit,
  });
  await server.listen({ port: 0, host: '127.0.0.1' });
  const address = server.server.address();
  baseUrl = `http://127.0.0.1:${address.port}`;
}

describe('configurable bodyLimit (#474)', () => {
  before(() => {
    // createServer({ root }) mutates process.env.DATA_ROOT
    // (src/server.js:180). Snapshot the previous value so we can
    // restore it after the suite — otherwise the test directory
    // leaks into any subsequent test that reads DATA_ROOT.
    originalDataRoot = process.env.DATA_ROOT;
  });

  afterEach(async () => {
    if (server) {
      await server.close();
      server = null;
    }
    await fs.remove(TEST_DATA_DIR);
  });

  after(() => {
    if (originalDataRoot === undefined) delete process.env.DATA_ROOT;
    else process.env.DATA_ROOT = originalDataRoot;
  });

  it('rejects requests larger than a numeric bodyLimit with 413', async () => {
    await startWith(100); // 100 bytes
    // Body well over the cap — Fastify's body parser fires the 413
    // before any route handler (or auth) runs.
    const oversized = 'x'.repeat(500);
    const res = await fetch(`${baseUrl}/anywhere`, {
      method: 'PUT',
      headers: { 'Content-Type': 'text/plain' },
      body: oversized,
    });
    assert.strictEqual(res.status, 413,
      `expected 413 for 500-byte body against a 100-byte limit, got ${res.status}`);
  });

  it('parses string bodyLimit ("100B") via parseSize (same behaviour as numeric)', async () => {
    await startWith('100B');
    const oversized = 'x'.repeat(500);
    const res = await fetch(`${baseUrl}/anywhere`, {
      method: 'PUT',
      headers: { 'Content-Type': 'text/plain' },
      body: oversized,
    });
    assert.strictEqual(res.status, 413,
      `expected 413 from string-parsed bodyLimit "100B"; got ${res.status}`);
  });

  it('accepts requests within the configured bodyLimit (no 413)', async () => {
    await startWith('10KB');
    // Small body, well under the 10KB cap — must NOT 413. (We don't care
    // which downstream status fires — auth/404/etc. are fine; only that
    // the body-parser doesn't reject.)
    const small = 'x'.repeat(100);
    const res = await fetch(`${baseUrl}/anywhere`, {
      method: 'PUT',
      headers: { 'Content-Type': 'text/plain' },
      body: small,
    });
    assert.notStrictEqual(res.status, 413,
      `100-byte body under a 10KB cap should not 413; got ${res.status}`);
  });
});
