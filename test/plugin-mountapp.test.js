/**
 * api.mountApp (#583) — a plugin mounting a node-style (req, res) handler
 * receives unconsumed request bodies, the exact shape the Tideholm and
 * bridge adapters hand-rolled. Verifies the scoped pass-through parser lets
 * a body-reading app work, host parsing stays intact outside the mount, and
 * a secondary mount prefix is WAC-exempted too.
 */

import { describe, it, before, after, afterEach } from 'node:test';
import assert from 'node:assert';
import fs from 'fs-extra';
import path from 'path';
import os from 'os';

const TEST_DATA_DIR = './test-data-mountapp';
const FIXTURE_DIR = path.join(os.tmpdir(), 'jss-mountapp-fixture');

// A plugin that mounts a plain node handler which reads the whole body and
// echoes it back — the app that hangs if Fastify drained the stream first.
const FIXTURE = `
export async function activate(api) {
  await api.mountApp((req, res) => {
    let body = '';
    req.on('data', (c) => { body += c; });
    req.on('end', () => {
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ echoed: body, method: req.method, url: req.url }));
    });
  });
  // A second mount under a different prefix, to prove secondary exemption.
  await api.mountApp((req, res) => {
    res.writeHead(200, { 'content-type': 'text/plain' });
    res.end('secondary');
  }, { prefix: '/wrapped2' });
  // Handlers that fail — sync throw and async rejection — to prove a
  // handler bug after hijack() answers 500 instead of hanging the client.
  await api.mountApp(() => { throw new Error('sync boom'); }, { prefix: '/boom' });
  await api.mountApp(async () => { throw new Error('async boom'); }, { prefix: '/boom-async' });
}
`;

// A plugin whose secondary mount prefix is invalid — must fail the boot.
const BAD_PREFIX_FIXTURE = `
export async function activate(api) {
  await api.mountApp((req, res) => res.end('x'), { prefix: 'chat' });
}
`;

let server;
let baseUrl;
let originalDataRoot;

async function start() {
  await fs.emptyDir(TEST_DATA_DIR);
  const { createServer } = await import('../src/server.js');
  server = createServer({
    logger: false,
    forceCloseConnections: true,
    root: TEST_DATA_DIR,
    plugins: [
      { id: 'wrapped', module: path.join(FIXTURE_DIR, 'plugin.js'), prefix: '/wrapped' },
    ],
  });
  await server.listen({ port: 0, host: '127.0.0.1' });
  baseUrl = `http://127.0.0.1:${server.server.address().port}`;
}

describe('api.mountApp (#583)', () => {
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

  it('a JSON POST body round-trips through the wrapped node handler', async () => {
    await start();
    const res = await fetch(`${baseUrl}/wrapped/api/thing`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ hello: 'world' }),
    });
    assert.strictEqual(res.status, 200);
    const body = await res.json();
    assert.strictEqual(body.echoed, JSON.stringify({ hello: 'world' }));
    assert.strictEqual(body.method, 'POST');
  });

  it('serves the bare prefix and the subtree, unauthenticated (WAC-exempt)', async () => {
    await start();
    const bare = await fetch(`${baseUrl}/wrapped`, { method: 'GET' });
    assert.strictEqual(bare.status, 200);
    const deep = await fetch(`${baseUrl}/wrapped/a/b/c`, { method: 'GET' });
    assert.strictEqual(deep.status, 200);
  });

  it('a secondary mount prefix is also served and WAC-exempt', async () => {
    await start();
    const res = await fetch(`${baseUrl}/wrapped2/anything`);
    assert.strictEqual(res.status, 200);
    assert.strictEqual(await res.text(), 'secondary');
  });

  it('host body parsing is unaffected outside the mount (LDP PUT still WAC-guarded)', async () => {
    await start();
    const res = await fetch(`${baseUrl}/somepod/private/x`, { method: 'PUT', body: 'data' });
    assert.ok([401, 403].includes(res.status), `expected WAC rejection, got ${res.status}`);
  });

  it('a handler that throws sync answers 500 and the server survives', async () => {
    await start();
    const res = await fetch(`${baseUrl}/boom`);
    assert.strictEqual(res.status, 500);
    // Process and server still alive: a healthy mount keeps answering.
    const ok = await fetch(`${baseUrl}/wrapped2/still-up`);
    assert.strictEqual(ok.status, 200);
  });

  it('a handler that rejects async answers 500 instead of leaking the rejection', async () => {
    await start();
    const res = await fetch(`${baseUrl}/boom-async`);
    assert.strictEqual(res.status, 500);
    const ok = await fetch(`${baseUrl}/wrapped2/still-up`);
    assert.strictEqual(ok.status, 200);
  });

  it('a provided-but-invalid secondary prefix fails the boot instead of mounting at the entry prefix', async () => {
    await fs.writeFile(path.join(FIXTURE_DIR, 'bad-prefix.js'), BAD_PREFIX_FIXTURE);
    await fs.emptyDir(TEST_DATA_DIR);
    const { createServer } = await import('../src/server.js');
    server = createServer({
      logger: false,
      forceCloseConnections: true,
      root: TEST_DATA_DIR,
      plugins: [
        { id: 'bad', module: path.join(FIXTURE_DIR, 'bad-prefix.js'), prefix: '/ok' },
      ],
    });
    await assert.rejects(
      server.listen({ port: 0, host: '127.0.0.1' }),
      /invalid prefix "chat"/,
    );
  });
});
