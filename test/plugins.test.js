/**
 * Plugin loader (#206) — createServer({ plugins }) end to end.
 *
 * A fixture plugin (written to disk per test run, in the #206 activate(api)
 * shape both real consumers — Tideholm and bridge — already export) is
 * loaded from config and verified against the whole api surface: HTTP
 * routes under a WAC-exempt prefix (#582), auth.getAgent (#584), a
 * WebSocket endpoint through ws.route (#588), private storage under the
 * data root's dot-guard, config pass-through, and deactivate on close.
 * Failure paths (missing module, no activate export, bad prefix) must fail
 * listen() loudly rather than boot a server silently missing an app.
 */

import { describe, it, before, after, afterEach } from 'node:test';
import assert from 'node:assert';
import path from 'path';
import { WebSocket } from 'ws';
import fs from 'fs-extra';
import { createServer } from '../src/server.js';
import { pluginId } from '../src/plugins.js';

const TEST_DATA_DIR = './test-data-plugins';
const FIXTURE_DIR = './test-fixtures-plugins';

let server;
let baseUrl;
let originalDataRoot;

// The fixture records activation evidence into this file so tests can
// assert on what the plugin saw (config, prefix, storage dir, deactivate).
const EVIDENCE = path.resolve(FIXTURE_DIR, 'evidence.json');

const FIXTURE_PLUGIN = `
import fs from 'fs';

export async function activate(api) {
  const dir = api.storage.pluginDir();
  const evidence = {
    prefix: api.prefix,
    config: api.config,
    pluginDir: dir,
    hasGetAgent: typeof api.auth.getAgent === 'function',
    deactivated: false,
  };
  const record = () =>
    fs.writeFileSync(${JSON.stringify(EVIDENCE)}, JSON.stringify(evidence));
  record();

  api.fastify.all(api.prefix + '/echo', async (request, reply) => {
    const agent = await api.auth.getAgent(request);
    reply.code(200).send({ app: true, method: request.method, agent });
  });

  await api.ws.route(api.prefix + '/ws', (socket) => {
    socket.on('message', (data) => socket.send('pong:' + String(data)));
  });
  await api.ws.route(api.prefix + '/ws-throw', () => {
    throw new Error('plugin bug');
  });

  return {
    deactivate() {
      evidence.deactivated = true;
      record();
    },
  };
}
`;

async function startWith(plugins) {
  await fs.emptyDir(TEST_DATA_DIR);
  server = createServer({
    logger: false,
    forceCloseConnections: true,
    root: TEST_DATA_DIR,
    plugins,
  });
  await server.listen({ port: 0, host: '127.0.0.1' });
  const address = server.server.address();
  baseUrl = `http://127.0.0.1:${address.port}`;
}

function evidence() {
  return JSON.parse(fs.readFileSync(EVIDENCE, 'utf8'));
}

describe('plugin loader (#206)', () => {
  before(async () => {
    originalDataRoot = process.env.DATA_ROOT;
    await fs.emptyDir(FIXTURE_DIR);
    await fs.writeFile(path.join(FIXTURE_DIR, 'fixture-plugin.js'), FIXTURE_PLUGIN);
  });

  afterEach(async () => {
    if (server) {
      await server.close();
      server = null;
    }
    await fs.remove(TEST_DATA_DIR);
  });

  after(async () => {
    await fs.remove(FIXTURE_DIR);
    if (originalDataRoot === undefined) delete process.env.DATA_ROOT;
    else process.env.DATA_ROOT = originalDataRoot;
  });

  it('loads a plugin from config and serves its routes under a WAC-exempt prefix', async () => {
    await startWith([
      { module: `${FIXTURE_DIR}/fixture-plugin.js`, prefix: '/game', config: { bots: 3 } },
    ]);
    // Unauthenticated POST reaches the app: the prefix joined appPaths.
    const res = await fetch(`${baseUrl}/game/echo`, { method: 'POST' });
    assert.strictEqual(res.status, 200);
    const body = await res.json();
    assert.strictEqual(body.app, true);
    assert.strictEqual(body.method, 'POST');
    assert.strictEqual(body.agent, null); // getAgent callable, anon -> null
  });

  it('passes prefix and config through to activate()', async () => {
    await startWith([
      { module: `${FIXTURE_DIR}/fixture-plugin.js`, prefix: '/game/', config: { bots: 3 } },
    ]);
    const seen = evidence();
    assert.strictEqual(seen.prefix, '/game'); // trailing slash normalized
    assert.deepStrictEqual(seen.config, { bots: 3 });
    assert.strictEqual(seen.hasGetAgent, true);
  });

  it('ws.route serves a WebSocket endpoint under the prefix', async () => {
    await startWith([
      { module: `${FIXTURE_DIR}/fixture-plugin.js`, prefix: '/game' },
    ]);
    const ws = new WebSocket(`${baseUrl.replace('http', 'ws')}/game/ws`);
    await new Promise((resolve, reject) => {
      ws.on('open', resolve);
      ws.on('error', reject);
    });
    const reply = await new Promise((resolve, reject) => {
      ws.on('message', (data) => resolve(String(data)));
      ws.on('error', reject);
      ws.send('hello');
    });
    assert.strictEqual(reply, 'pong:hello');
    ws.close();
  });

  it('pluginDir is created under the data root and shielded from LDP', async () => {
    await startWith([
      { module: `${FIXTURE_DIR}/fixture-plugin.js`, prefix: '/game' },
    ]);
    const seen = evidence();
    assert.ok(seen.pluginDir.includes(path.join('.plugins', 'fixture-plugin')));
    assert.ok(fs.existsSync(seen.pluginDir));
    // Write a secret; the dot-guard must keep it unreachable over HTTP.
    await fs.writeFile(path.join(seen.pluginDir, 'secret.txt'), 'hush');
    const res = await fetch(`${baseUrl}/.plugins/fixture-plugin/secret.txt`);
    assert.notStrictEqual(res.status, 200);
  });

  it('deactivate() runs on server close', async () => {
    await startWith([
      { module: `${FIXTURE_DIR}/fixture-plugin.js`, prefix: '/game' },
    ]);
    assert.strictEqual(evidence().deactivated, false);
    await server.close();
    server = null;
    assert.strictEqual(evidence().deactivated, true);
  });

  it('sibling LDP paths keep full WAC enforcement', async () => {
    await startWith([
      { module: `${FIXTURE_DIR}/fixture-plugin.js`, prefix: '/game' },
    ]);
    const res = await fetch(`${baseUrl}/somepod/private/thing`, { method: 'PUT', body: 'x' });
    assert.ok([401, 403].includes(res.status), `expected WAC rejection, got ${res.status}`);
  });

  it('a plugin that cannot be imported fails listen() loudly', async () => {
    await fs.emptyDir(TEST_DATA_DIR);
    server = createServer({
      logger: false,
      forceCloseConnections: true,
      root: TEST_DATA_DIR,
      plugins: [{ module: `${FIXTURE_DIR}/no-such-plugin.js`, prefix: '/x' }],
    });
    await assert.rejects(
      server.listen({ port: 0, host: '127.0.0.1' }),
      /cannot import/,
    );
  });

  it('a throwing ws handler closes that socket but not the server', async () => {
    await startWith([
      { module: `${FIXTURE_DIR}/fixture-plugin.js`, prefix: '/game' },
    ]);
    const ws = new WebSocket(`${baseUrl.replace('http', 'ws')}/game/ws-throw`);
    await new Promise((resolve) => {
      ws.on('close', resolve);
      ws.on('error', resolve);
    });
    // The host survives its plugin's bug.
    const res = await fetch(`${baseUrl}/game/echo`);
    assert.strictEqual(res.status, 200);
  });

  it('derives collision-resistant ids and rejects duplicates', async () => {
    // Bare specifiers keep their full path; file paths use the basename.
    assert.strictEqual(pluginId({ module: '@scope1/pkg/plugin.js' }), 'scope1-pkg-plugin');
    assert.strictEqual(pluginId({ module: '@scope2/pkg/plugin.js' }), 'scope2-pkg-plugin');
    assert.strictEqual(pluginId({ module: '/some/machine/path/foo.js' }), 'foo');
    assert.strictEqual(pluginId({ module: './x.js', id: 'Custom Id!' }), 'custom-id');

    // Two entries reducing to the same id fail the boot, not share a dir.
    await fs.emptyDir(TEST_DATA_DIR);
    server = createServer({
      logger: false,
      forceCloseConnections: true,
      root: TEST_DATA_DIR,
      plugins: [
        { module: `${FIXTURE_DIR}/fixture-plugin.js`, prefix: '/a' },
        { module: `${FIXTURE_DIR}/fixture-plugin.js`, prefix: '/b' },
      ],
    });
    await assert.rejects(
      server.listen({ port: 0, host: '127.0.0.1' }),
      /duplicate id/,
    );
  });

  it('an invalid prefix fails listen() loudly', async () => {
    await fs.emptyDir(TEST_DATA_DIR);
    server = createServer({
      logger: false,
      forceCloseConnections: true,
      root: TEST_DATA_DIR,
      plugins: [{ module: `${FIXTURE_DIR}/fixture-plugin.js`, prefix: 'game' }],
    });
    await assert.rejects(
      server.listen({ port: 0, host: '127.0.0.1' }),
      /invalid prefix/,
    );
  });
});
