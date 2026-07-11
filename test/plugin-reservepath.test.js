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
  // A second identical claim by the same plugin is an idempotent no-op —
  // no duplicate matcher, no self-collision error.
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

// Same shape as the main plugin's /:user/did.json, different param name —
// exempts the same URLs, so it's the same claim and must collide.
const SHAPE_RIVAL_FIXTURE = `
export async function activate(api) {
  api.reservePath('/:acct/did.json');
}
`;

// '/:user.json' is NOT a param segment (mixes sigil with literal text);
// only the exact literal path is exempt, a sibling like /alice.json isn't.
const LITERALISH_FIXTURE = `
export async function activate(api) {
  api.reservePath('/:user.json');
  api.fastify.get('/:user.json', async () => ({ literal: true }));
}
`;

// A literal ':' segment ('/:/x') must NOT collide with the param shape
// '/:user/x' — different claim types that only alias if the collision
// key throws away the param-vs-literal distinction.
const LITERAL_COLON_FIXTURE = `
export async function activate(api) {
  api.reservePath('/:user/x');    // param
  api.fastify.get('/:user/x', async () => ({ param: true }));
}
`;
const COLON_SEG_FIXTURE = `
export async function activate(api) {
  api.reservePath('/:/x');        // literal ':' segment
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
    await fs.writeFile(path.join(FIXTURE_DIR, 'shape-rival.js'), SHAPE_RIVAL_FIXTURE);
    await fs.writeFile(path.join(FIXTURE_DIR, 'literalish.js'), LITERALISH_FIXTURE);
    await fs.writeFile(path.join(FIXTURE_DIR, 'literal-colon.js'), LITERAL_COLON_FIXTURE);
    await fs.writeFile(path.join(FIXTURE_DIR, 'colon-seg.js'), COLON_SEG_FIXTURE);
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

  it('a query string (even one containing /) does not affect shape matching', async () => {
    await start(MAIN());
    // The param class must not swallow '?': a '/' inside the query would
    // otherwise break the match for a path shape that is satisfied.
    const res = await fetch(`${baseUrl}/alice/did.json?redirect=/a/b`);
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

  it('same shape with a different param name is the same claim and collides', async () => {
    await fs.emptyDir(TEST_DATA_DIR);
    const { createServer } = await import('../src/server.js');
    server = createServer({
      logger: false,
      forceCloseConnections: true,
      root: TEST_DATA_DIR,
      plugins: [
        ...MAIN(),
        { id: 'shaperival', module: path.join(FIXTURE_DIR, 'shape-rival.js'), prefix: '/sr' },
      ],
    });
    await assert.rejects(
      server.listen({ port: 0, host: '127.0.0.1' }),
      /already reserved by plugin 'shim'/,
    );
  });

  it("'/:user.json' is literal, not a wildcard — a sibling stays WAC-guarded", async () => {
    await start([{ id: 'lit', module: path.join(FIXTURE_DIR, 'literalish.js'), prefix: '/lit' }]);
    // The exact reserved path serves...
    const exact = await fetch(`${baseUrl}/:user.json`);
    assert.strictEqual(exact.status, 200);
    // ...but a real single-segment sibling is NOT exempted (would be, if
    // the segment had been treated as a param).
    const sibling = await fetch(`${baseUrl}/alice.json`, { method: 'PUT', body: 'x' });
    assert.ok([401, 403].includes(sibling.status), `expected WAC rejection, got ${sibling.status}`);
  });

  it("a literal ':' segment does not alias a param shape (no false collision)", async () => {
    await start([
      { id: 'litcolon', module: path.join(FIXTURE_DIR, 'literal-colon.js'), prefix: '/lc' },
      { id: 'colonseg', module: path.join(FIXTURE_DIR, 'colon-seg.js'), prefix: '/cs' },
    ]);
    // Booted cleanly — the two reservations are distinct claims. The
    // param route still serves its shape.
    const res = await fetch(`${baseUrl}/alice/x`);
    assert.strictEqual(res.status, 200);
    assert.deepStrictEqual(await res.json(), { param: true });
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
