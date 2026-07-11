/**
 * api.serverInfo (#601) — a plugin can learn the server's own origin
 * instead of being told it via config (where a wrong value fails
 * quietly). Lazy by design: with port 0 the real port exists only once
 * the server is listening, so serverInfo() is a call, not a snapshot.
 */

import { describe, it, before, after, afterEach } from 'node:test';
import assert from 'node:assert';
import fs from 'fs-extra';
import path from 'path';
import os from 'os';

const TEST_DATA_DIR = './test-data-serverinfo';
const FIXTURE_DIR = path.join(os.tmpdir(), 'jss-serverinfo-fixture');

// Captures serverInfo at activate time and serves the live value per
// request — the two moments the seam has to be honest about.
const FIXTURE = `
export async function activate(api) {
  const atActivate = api.serverInfo();
  api.fastify.get('/info-app/now', async () => ({
    atActivate,
    now: api.serverInfo(),
  }));
}
`;

let server;
let baseUrl;
let originalDataRoot;

async function start(extraOptions = {}) {
  await fs.emptyDir(TEST_DATA_DIR);
  const { createServer } = await import('../src/server.js');
  server = createServer({
    logger: false,
    forceCloseConnections: true,
    root: TEST_DATA_DIR,
    plugins: [
      { id: 'info', module: path.join(FIXTURE_DIR, 'plugin.js'), prefix: '/info-app' },
    ],
    ...extraOptions,
  });
  await server.listen({ port: 0, host: '127.0.0.1' });
  baseUrl = `http://127.0.0.1:${server.server.address().port}`;
}

describe('api.serverInfo (#601)', () => {
  before(async () => {
    originalDataRoot = process.env.DATA_ROOT;
    await fs.emptyDir(FIXTURE_DIR);
    await fs.writeFile(path.join(FIXTURE_DIR, 'plugin.js'), FIXTURE);
  });
  after(async () => {
    await fs.remove(FIXTURE_DIR);
    if (originalDataRoot === undefined) delete process.env.DATA_ROOT;
    else process.env.DATA_ROOT = originalDataRoot;
  });
  afterEach(async () => {
    if (server) { await server.close(); server = null; }
    await fs.remove(TEST_DATA_DIR);
  });

  it('resolves the real port once listening, even when booted with port 0', async () => {
    await start({ port: 0, host: '127.0.0.1' });
    const boundPort = server.server.address().port;
    const res = await fetch(`${baseUrl}/info-app/now`);
    assert.strictEqual(res.status, 200);
    const { atActivate, now } = await res.json();
    assert.strictEqual(now.listening, true);
    assert.strictEqual(now.port, boundPort);
    assert.strictEqual(now.baseUrl, `http://127.0.0.1:${boundPort}`);
    assert.strictEqual(now.protocol, 'http');
    // At activate time the server wasn't listening yet; the configured
    // port 0 is reported as-is rather than masked by a default.
    assert.strictEqual(atActivate.listening, false);
    assert.strictEqual(atActivate.port, 0);
  });

  it('0.0.0.0 binds report localhost as the callable host', async () => {
    await start({ port: 0, host: '0.0.0.0' });
    const boundPort = server.server.address().port;
    const res = await fetch(`http://127.0.0.1:${boundPort}/info-app/now`);
    const { now } = await res.json();
    assert.strictEqual(now.host, 'localhost');
    assert.strictEqual(now.baseUrl, `http://localhost:${boundPort}`);
  });

  it('an explicit idpIssuer wins as the canonical public baseUrl', async () => {
    await start({ port: 0, host: '127.0.0.1', idpIssuer: 'https://pods.example/' });
    const res = await fetch(`${baseUrl}/info-app/now`);
    const { now } = await res.json();
    assert.strictEqual(now.baseUrl, 'https://pods.example');
    // The live bind details stay available alongside the override.
    assert.strictEqual(now.port, server.server.address().port);
  });
});
