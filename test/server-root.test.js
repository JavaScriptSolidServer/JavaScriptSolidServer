/**
 * Server-root landing page seed (#276).
 */

import { describe, it, before, after } from 'node:test';
import assert from 'node:assert';
import fs from 'fs-extra';
import { createServer } from '../src/server.js';
import { renderServerRoot } from '../src/ui/server-root.js';
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
  let savedDataRoot;
  const DATA_DIR = './test-data-server-root-override';
  const CUSTOM_HTML = '<!doctype html><html><body>my custom page</body></html>';

  before(async () => {
    // Capture process.env.DATA_ROOT — createServer mutates it when options.root
    // is provided. Restore in after() to avoid cross-test interference with
    // suites that rely on the default ./data dir.
    savedDataRoot = process.env.DATA_ROOT;

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
    if (savedDataRoot === undefined) delete process.env.DATA_ROOT;
    else process.env.DATA_ROOT = savedDataRoot;
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

describe('renderServerRoot — mode-specific output', () => {
  it('multi-user + IDP shows Create a pod + Sign in', () => {
    const html = renderServerRoot({ version: '1.0.0', singleUser: false, idp: true });
    assert.match(html, /Create a pod/);
    assert.match(html, /href="\/idp\/register"/);
    assert.match(html, /href="\/idp"/);
    assert.match(html, /Sign in/);
  });

  it('single-user + IDP shows Sign in only (no Create a pod)', () => {
    const html = renderServerRoot({ version: '1.0.0', singleUser: true, idp: true, singleUserName: 'alice' });
    assert.doesNotMatch(html, /Create a pod/);
    assert.match(html, /Sign in/);
  });

  it('multi-user without IDP shows only the Docs link', () => {
    const html = renderServerRoot({ version: '1.0.0', singleUser: false, idp: false });
    assert.doesNotMatch(html, /Create a pod/);
    assert.doesNotMatch(html, /Sign in/);
    assert.match(html, /Docs/);
  });

  it('single-user subtitle includes the pod name when provided', () => {
    const html = renderServerRoot({ version: '1.0.0', singleUser: true, idp: false, singleUserName: 'alice' });
    assert.match(html, /Personal pod for alice/);
  });

  it('lists enabled features', () => {
    const html = renderServerRoot({
      version: '1.0.0',
      singleUser: false,
      idp: true,
      enabled: { idp: true, nostr: true, webrtc: true, terminal: true }
    });
    assert.match(html, /<span>idp<\/span>/);
    assert.match(html, /<span>nostr<\/span>/);
    assert.match(html, /<span>webrtc<\/span>/);
    assert.match(html, /<span>terminal<\/span>/);
  });

  it('interpolates version', () => {
    const html = renderServerRoot({ version: '9.9.9' });
    assert.match(html, /<code>9\.9\.9<\/code>/);
  });

  it('escapes version to prevent injection', () => {
    const html = renderServerRoot({ version: '<script>alert(1)</script>' });
    assert.doesNotMatch(html, /<script>alert\(1\)<\/script>/);
    assert.match(html, /&lt;script&gt;/);
  });

  // Regression for the `$&` substitution gotcha (#433): a string used as
  // the second argument of String.prototype.replace interprets `$&`,
  // `$1`, etc. as substitution patterns. Interpolated values can contain
  // `$` (notably a singleUserName), so the renderer uses the function
  // form of replace instead. Asserting the literal `$&` survives the
  // round-trip would mean it survived as plain text.
  it('preserves $-patterns in singleUserName instead of treating them as replacement specials', () => {
    const html = renderServerRoot({
      version: '1.0.0',
      singleUser: true,
      idp: false,
      singleUserName: 'foo$&bar'
    });
    // The HTML escape converts `&` to `&amp;`; the rest must stay verbatim,
    // not be replaced by the matched template token.
    assert.match(html, /Personal pod for foo\$&amp;bar/,
      'singleUserName containing "$&" should land as-is, not trigger String.replace substitution');
    assert.doesNotMatch(html, /\{\{subtitle\}\}/, 'subtitle token should be fully consumed');
  });
});
