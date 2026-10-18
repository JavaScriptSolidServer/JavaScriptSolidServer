/**
 * --git and plugin-owned git paths (#616): core's git lane must not shadow a
 * plugin that serves git smart-HTTP under its own prefix. With --git on, a
 * request like GET /forge/<owner>/<name>.git/info/refs?service=git-receive-pack
 * used to be grabbed by core, looked up under the pod root, and answered 401
 * before the plugin ran. App plugins own their prefix: git-looking URLs below
 * an app path fall through to the plugin; pod git outside it is unchanged.
 */

import { describe, it, before, after, afterEach } from 'node:test';
import assert from 'node:assert';
import fs from 'fs-extra';
import path from 'path';
import os from 'os';

const TEST_DATA_DIR = './test-data-git-plugin-prefix';
const FIXTURE_DIR = path.join(os.tmpdir(), 'jss-git-plugin-prefix-fixture');

// A plugin that answers every request under its mount, git-shaped or not,
// and says which URL it saw — the forge's smart-HTTP lane, in miniature.
const FIXTURE = `
export async function activate(api) {
  await api.mountApp((req, res) => {
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ plugin: 'forge', method: req.method, url: req.url }));
  });
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
    git: true,
    plugins: [
      { id: 'forge', module: path.join(FIXTURE_DIR, 'plugin.js'), prefix: '/forge' },
    ],
  });
  await server.listen({ port: 0, host: '127.0.0.1' });
  baseUrl = `http://127.0.0.1:${server.server.address().port}`;
}

describe('--git defers to plugin-owned prefixes (#616)', () => {
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

  it('a push discovery under the plugin prefix reaches the plugin, unauthenticated', async () => {
    await start();
    const url = '/forge/alice/repo.git/info/refs?service=git-receive-pack';
    const res = await fetch(baseUrl + url);
    assert.strictEqual(res.status, 200, 'core did not answer 401 for the plugin\'s git URL');
    const body = await res.json();
    assert.strictEqual(body.plugin, 'forge', 'the plugin handled it');
    assert.strictEqual(body.url, url, 'the full git-shaped URL, query included, reached the plugin');
  });

  it('the pack services under the plugin prefix reach the plugin too', async () => {
    await start();
    for (const svc of ['git-receive-pack', 'git-upload-pack']) {
      const res = await fetch(`${baseUrl}/forge/alice/repo.git/${svc}`, {
        method: 'POST', headers: { 'content-type': `application/x-${svc}-request` }, body: '0000',
      });
      assert.strictEqual(res.status, 200, `${svc} reached the plugin`);
      assert.strictEqual((await res.json()).plugin, 'forge');
    }
  });

  it('pod git outside the prefix is still core\'s: a push there is auth-gated as before', async () => {
    await start();
    const res = await fetch(`${baseUrl}/alice/repo.git/info/refs?service=git-receive-pack`);
    assert.strictEqual(res.status, 401, 'core still guards pod repos (write needs auth)');
    const body = await res.json();
    assert.strictEqual(body.error, 'Write access required for push');
  });
});
