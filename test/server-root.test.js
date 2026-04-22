/**
 * Server-root landing page seed (#276).
 */

import { describe, it, before, after } from 'node:test';
import assert from 'node:assert';
import fs from 'fs-extra';
import { createServer } from '../src/server.js';
import { startTestServer, stopTestServer, request, assertStatus } from './helpers.js';

describe('Server-root landing page', () => {
  before(async () => {
    await startTestServer();
  });

  after(async () => {
    await stopTestServer();
  });

  it('seeds /index.html so GET / serves HTML', async () => {
    const res = await request('/', { headers: { Accept: 'text/html' } });
    assertStatus(res, 200);
    const body = await res.text();
    assert.match(body, /<title>JSS<\/title>/);
    assert.match(body, /A personal data server/);
  });

  it('landing page is publicly readable (no auth required)', async () => {
    const res = await request('/index.html');
    assertStatus(res, 200);
  });
});

// Operator's existing /index.html is preserved — dedicated server + data dir.
describe('Server-root landing — operator override', () => {
  let server;
  let baseUrl;
  const DATA_DIR = './test-data-server-root-override';
  const CUSTOM_HTML = '<!doctype html><html><body>my custom page</body></html>';

  before(async () => {
    await fs.remove(DATA_DIR);
    await fs.ensureDir(DATA_DIR);
    await fs.writeFile(`${DATA_DIR}/index.html`, CUSTOM_HTML);

    server = createServer({
      logger: false,
      root: DATA_DIR,
      forceCloseConnections: true,
    });
    await server.listen({ port: 0, host: '127.0.0.1' });
    baseUrl = `http://127.0.0.1:${server.server.address().port}`;
  });

  after(async () => {
    await server.close();
    await fs.remove(DATA_DIR);
  });

  it('does not overwrite operator-provided /index.html', async () => {
    const current = await fs.readFile(`${DATA_DIR}/index.html`, 'utf8');
    assert.strictEqual(current, CUSTOM_HTML);
  });

  it('GET / serves operator custom page', async () => {
    const res = await fetch(`${baseUrl}/`, { headers: { Accept: 'text/html' } });
    assert.strictEqual(res.status, 200);
    const body = await res.text();
    assert.match(body, /my custom page/);
  });
});
