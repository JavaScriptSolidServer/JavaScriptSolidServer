/**
 * appPaths — WAC-exempt application mount points (#582).
 *
 * The global WAC preHandler authorizes every URL against pod ACLs and
 * rejects before routes run; the only escapes are its hardcoded prefix
 * list (/storage/, /db, /mcp, …). That means a third-party app plugin
 * registering routes on the returned fastify instance (#206's plugin-zero
 * pattern, e.g. a game mounted at /tideholm) has its POSTs swallowed by
 * WAC with no way to opt out.
 *
 * createServer({ appPaths: ['/myapp'] }) declares URL prefixes owned by
 * registered applications: requests at or below an app path skip the WAC
 * hook, and the app owns authentication and authorization under its
 * prefix — exactly the deal the bundled pseudo-plugins already have.
 *
 * Tests verify the seam end-to-end: an app route mounted on the returned
 * instance receives unauthenticated requests (WAC stays out), sibling LDP
 * paths keep full WAC enforcement, and malformed appPaths entries are
 * dropped rather than becoming accidental holes.
 */

import { describe, it, before, after, afterEach } from 'node:test';
import assert from 'node:assert';
import { createServer } from '../src/server.js';
import fs from 'fs-extra';

const TEST_DATA_DIR = './test-data-app-paths';

let server;
let baseUrl;
let originalDataRoot;

async function startWith(appPaths) {
  await fs.emptyDir(TEST_DATA_DIR);
  server = createServer({
    logger: false,
    forceCloseConnections: true,
    root: TEST_DATA_DIR,
    appPaths,
  });
  // An app in the #206 plugin-zero shape: routes registered on the returned
  // instance, answering with its own status codes (its own "auth").
  server.all('/myapp', echo);
  server.all('/myapp/*', echo);
  async function echo(request, reply) {
    reply.code(200).send({
      app: true,
      method: request.method,
      url: request.url,
      webId: request.webId ?? null, // hook skipped -> never set
    });
  }
  await server.listen({ port: 0, host: '127.0.0.1' });
  const address = server.server.address();
  baseUrl = `http://127.0.0.1:${address.port}`;
}

describe('appPaths application mount points (#582)', () => {
  before(() => {
    // createServer({ root }) mutates process.env.DATA_ROOT; snapshot so the
    // test dir doesn't leak into later suites.
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

  it('unauthenticated POST below an app path reaches the app handler', async () => {
    await startWith(['/myapp']);
    const res = await fetch(`${baseUrl}/myapp/api/action`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ hello: 'world' }),
    });
    assert.strictEqual(res.status, 200);
    const body = await res.json();
    assert.strictEqual(body.app, true);
    assert.strictEqual(body.method, 'POST');
  });

  it('the bare app path and query-string forms are exempt too', async () => {
    await startWith(['/myapp']);
    for (const path of ['/myapp', '/myapp?tab=map']) {
      const res = await fetch(`${baseUrl}${path}`, { method: 'POST' });
      assert.strictEqual(res.status, 200, `${path} should reach the app`);
    }
  });

  it('the WAC hook never sets request.webId on app-path requests', async () => {
    await startWith(['/myapp']);
    const res = await fetch(`${baseUrl}/myapp/whoami`);
    const body = await res.json();
    assert.strictEqual(body.webId, null);
  });

  it('sibling LDP paths keep full WAC enforcement', async () => {
    await startWith(['/myapp']);
    // Writing outside the app prefix without auth must still be rejected.
    const res = await fetch(`${baseUrl}/notes.jsonld`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/ld+json' },
      body: JSON.stringify({ '@id': '', name: 'x' }),
    });
    assert.ok(res.status === 401 || res.status === 403,
      `expected WAC rejection, got ${res.status}`);
  });

  it('a prefix match is a path-segment match, not a string prefix', async () => {
    await startWith(['/myapp']);
    // /myapplication must NOT be exempt just because it shares characters.
    const res = await fetch(`${baseUrl}/myapplication.jsonld`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/ld+json' },
      body: JSON.stringify({ '@id': '', name: 'x' }),
    });
    assert.ok(res.status === 401 || res.status === 403,
      `expected WAC rejection, got ${res.status}`);
  });

  it('trailing-slash entries are normalized, children still exempt', async () => {
    await startWith(['/myapp/']);
    const res = await fetch(`${baseUrl}/myapp/api/action`, { method: 'POST' });
    assert.strictEqual(res.status, 200);
  });

  it('malformed appPaths entries are dropped, not accidental holes', async () => {
    // No leading slash and bare '/' are both invalid; with them filtered out
    // the route registrations still exist but WAC fires first.
    await startWith(['myapp', '/', '///', '  ']);
    const res = await fetch(`${baseUrl}/myapp/api/action`, { method: 'POST' });
    assert.ok(res.status === 401 || res.status === 403,
      `expected WAC rejection (invalid entries dropped), got ${res.status}`);
  });

  it('omitting appPaths changes nothing (default off)', async () => {
    await startWith(undefined);
    const res = await fetch(`${baseUrl}/myapp/api/action`, { method: 'POST' });
    assert.ok(res.status === 401 || res.status === 403,
      `expected WAC rejection with no appPaths, got ${res.status}`);
  });
});
