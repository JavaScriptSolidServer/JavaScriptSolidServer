/**
 * api.plugins (#610) — a plugin can enumerate its co-loaded siblings
 * instead of being hand-fed a duplicate of the operator's plugins array
 * (which silently drifts). A read-only, frozen boot-time snapshot of
 * every entry's { id, prefix, module }, computed before any activate()
 * runs so it is complete regardless of load order.
 */

import { describe, it, before, after, afterEach } from 'node:test';
import assert from 'node:assert';
import fs from 'fs-extra';
import path from 'path';
import os from 'os';

const TEST_DATA_DIR = './test-data-roster';
const FIXTURE_DIR = path.join(os.tmpdir(), 'jss-roster-fixture');

// The FIRST plugin captures api.plugins at activate time and serves it.
// Because the roster is computed up front, it must already list the
// siblings that activate AFTER this one — the load-order-independence
// the seam exists to guarantee.
const REPORTER = `
export async function activate(api) {
  const atActivate = api.plugins;
  api.fastify.get('/a/roster', async () => ({
    plugins: atActivate,
    frozen: Object.isFrozen(atActivate),
    entryFrozen: atActivate.length > 0 ? Object.isFrozen(atActivate[0]) : null,
    self: atActivate.find((p) => p.id === 'roster-a') ?? null,
  }));
}
`;

// A sibling that registers no routes — it only needs to exist in the roster.
const NOOP = `export async function activate() {}`;

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

describe('api.plugins (#610)', () => {
  before(async () => {
    originalDataRoot = process.env.DATA_ROOT;
    await fs.emptyDir(FIXTURE_DIR);
    await fs.writeFile(path.join(FIXTURE_DIR, 'reporter.js'), REPORTER);
    await fs.writeFile(path.join(FIXTURE_DIR, 'noop.js'), NOOP);
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

  const reporter = path.join(FIXTURE_DIR, 'reporter.js');
  const noop = path.join(FIXTURE_DIR, 'noop.js');

  it('lists every loaded entry — including siblings that activate later', async () => {
    await start([
      { id: 'roster-a', module: reporter, prefix: '/a' },
      { id: 'roster-b', module: noop, prefix: '/b' },
      { id: 'roster-c', module: noop }, // no prefix
    ]);
    const res = await fetch(`${baseUrl}/a/roster`);
    assert.strictEqual(res.status, 200);
    const { plugins } = await res.json();

    // The reporter is entry 0 yet sees b and c (activated after it) —
    // the roster is complete up front, not accumulated during the loop.
    assert.deepStrictEqual(plugins.map((p) => p.id), ['roster-a', 'roster-b', 'roster-c']);
    const b = plugins.find((p) => p.id === 'roster-b');
    assert.strictEqual(b.prefix, '/b');
    assert.strictEqual(b.module, noop);
    // A no-prefix entry reports '' (same normalization the loader applies).
    assert.strictEqual(plugins.find((p) => p.id === 'roster-c').prefix, '');
  });

  it('includes the plugin itself', async () => {
    await start([
      { id: 'roster-a', module: reporter, prefix: '/a' },
      { id: 'roster-b', module: noop, prefix: '/b' },
    ]);
    const { self } = await (await fetch(`${baseUrl}/a/roster`)).json();
    assert.ok(self, 'the roster includes the reporting plugin');
    assert.strictEqual(self.prefix, '/a');
    assert.strictEqual(self.module, reporter);
  });

  it('is a frozen, read-only snapshot at both levels', async () => {
    await start([
      { id: 'roster-a', module: reporter, prefix: '/a' },
      { id: 'roster-b', module: noop, prefix: '/b' },
    ]);
    const { frozen, entryFrozen } = await (await fetch(`${baseUrl}/a/roster`)).json();
    assert.strictEqual(frozen, true, 'the array is frozen');
    assert.strictEqual(entryFrozen, true, 'each entry object is frozen');
  });
});
