/**
 * api.reservePath (#602) — a plugin can claim protocol-pinned paths
 * outside its prefix: fixed roots (/xrpc) as WAC-exempt subtrees, and
 * parameterized documents (/:user/did.json) as exact-shape, read-only
 * exemptions inside the pod's WAC-governed namespace. Claims are
 * cross-plugin: a second claimant fails the boot naming both.
 */

import { describe, it, before, after, afterEach } from 'node:test';
import assert from 'node:assert';
import fs from 'fs-extra';
import path from 'path';
import os from 'os';

const TEST_DATA_DIR = './test-data-reservepath';
const FIXTURE_DIR = path.join(os.tmpdir(), 'jss-reservepath-fixture');

// An xrpc-style shim (fixed root) plus a did:web-style pinned document.
const FIXTURE = `
export async function activate(api) {
  api.reservePath('/xrpc');
  api.fastify.get('/xrpc/ping', async () => ({ pong: true }));

  api.reservePath('/:user/did.json');
  api.fastify.get('/:user/did.json', async (req) => ({ id: 'did:web:' + req.params.user }));
}
`;

// A rival that claims the same fixed root — must fail the boot.
const RIVAL_FIXTURE = `
export async function activate(api) {
  api.reservePath('/xrpc');
}
`;

// '//' normalizes to '' — pushed to appPaths it would match every URL
// and disable WAC wholesale. Must be rejected at activate.
const SLASHES_FIXTURE = `
export async function activate(api) {
  api.reservePath('//');
}
`;

let server;
let baseUrl;
let originalDataRoot;

async function start(plugins) {
  await fs.emptyDir(TEST_DATA_DIR);
  const { createServer } = await import('../src/server.js');
  server = createServer({
    logger: false,
    forceCloseConnections: true,
    root: TEST_DATA_DIR,
    plugins,
  });
  await server.listen({ port: 0, host: '127.0.0.1' });
  baseUrl = `http://127.0.0.1:${server.server.address().port}`;
}

const MAIN = () => [{ id: 'shim', module: path.join(FIXTURE_DIR, 'plugin.js'), prefix: '/shim' }];

describe('api.reservePath (#602)', () => {
  before(async () => {
    originalDataRoot = process.env.DATA_ROOT;
    await fs.emptyDir(FIXTURE_DIR);
    await fs.writeFile(path.join(FIXTURE_DIR, 'plugin.js'), FIXTURE);
    await fs.writeFile(path.join(FIXTURE_DIR, 'rival.js'), RIVAL_FIXTURE);
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

  it('a reserved fixed root serves unauthenticated', async () => {
    await start(MAIN());
    const res = await fetch(`${baseUrl}/xrpc/ping`);
    assert.strictEqual(res.status, 200);
    assert.deepStrictEqual(await res.json(), { pong: true });
  });

  it('WAC still guards unreserved paths', async () => {
    await start(MAIN());
    const res = await fetch(`${baseUrl}/somepod/private/x`, { method: 'PUT', body: 'data' });
    assert.ok([401, 403].includes(res.status), `expected WAC rejection, got ${res.status}`);
  });

  it('a parameterized reservation serves the pinned document shape', async () => {
    await start(MAIN());
    const res = await fetch(`${baseUrl}/alice/did.json`);
    assert.strictEqual(res.status, 200);
    assert.deepStrictEqual(await res.json(), { id: 'did:web:alice' });
  });

  it('parameterized reservations are read-only: writes to the shape stay WAC-guarded', async () => {
    await start(MAIN());
    // Without the method gate this PUT would skip WAC and fall through
    // to the LDP wildcard as an unauthenticated pod write.
    const res = await fetch(`${baseUrl}/alice/did.json`, { method: 'PUT', body: '{}' });
    assert.ok([401, 403].includes(res.status), `expected WAC rejection, got ${res.status}`);
  });

  it("reservePath('//') fails the boot instead of exempting every URL from WAC", async () => {
    await fs.writeFile(path.join(FIXTURE_DIR, 'slashes.js'), SLASHES_FIXTURE);
    await fs.emptyDir(TEST_DATA_DIR);
    const { createServer } = await import('../src/server.js');
    server = createServer({
      logger: false,
      forceCloseConnections: true,
      root: TEST_DATA_DIR,
      plugins: [
        { id: 'slashes', module: path.join(FIXTURE_DIR, 'slashes.js'), prefix: '/slashes' },
      ],
    });
    await assert.rejects(
      server.listen({ port: 0, host: '127.0.0.1' }),
      /reservePath needs an absolute path/,
    );
  });

  it('two plugins claiming the same path fail the boot naming both', async () => {
    await fs.emptyDir(TEST_DATA_DIR);
    const { createServer } = await import('../src/server.js');
    server = createServer({
      logger: false,
      forceCloseConnections: true,
      root: TEST_DATA_DIR,
      plugins: [
        ...MAIN(),
        { id: 'rival', module: path.join(FIXTURE_DIR, 'rival.js'), prefix: '/rival' },
      ],
    });
    await assert.rejects(
      server.listen({ port: 0, host: '127.0.0.1' }),
      /rival: path '\/xrpc' is already reserved by plugin 'shim'/,
    );
  });
});
