/**
 * Server-root landing page seed (#276 / #433 / #435).
 *
 * Phase 3 (#433) seeded a mode-specific landing page that went stale on
 * mode change. Phase 3 refinement (#435) replaced the mode-specific copy
 * with a single mode-agnostic page that adapts at load time via a HEAD
 * probe against /idp/register, so the same seeded HTML keeps working
 * across modes without regenerating the file.
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
    assert.match(body, /<title>JSS Solid pod<\/title>/);
    assert.match(body, /Your JSS Solid pod is running/);
  });

  it('landing page is publicly readable (no auth required)', async () => {
    const res = await request('/index.html');
    assertStatus(res, 200);
  });

  // Portability regression: the seeded ACLs must use './' (resolved
  // against the .acl's own URL) rather than '/' (the origin root).
  // The two coincide when JSS sits at the origin root, so a request
  // smoke-test would pass either way; only direct inspection of the
  // serialized accessTo catches a regression to the absolute form.
  // Without this, JSS mounted under a reverse-proxy path prefix would
  // see the seeded ACL match the origin root rather than the prefix.
  it('seeded ACLs use relative resourceUrl ("./" / "./index.html"), not absolute paths', async () => {
    const rootAcl = JSON.parse(await fs.readFile('./data/.acl', 'utf8'));
    const pageAcl = JSON.parse(await fs.readFile('./data/index.html.acl', 'utf8'));
    const rootAccessTo = rootAcl['@graph'][0]['acl:accessTo']['@id'];
    const pageAccessTo = pageAcl['@graph'][0]['acl:accessTo']['@id'];
    assert.strictEqual(rootAccessTo, './',
      `Expected /.acl accessTo to be relative './', got '${rootAccessTo}'`);
    assert.strictEqual(pageAccessTo, './index.html',
      `Expected /index.html.acl accessTo to be relative './index.html', got '${pageAccessTo}'`);
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

describe('renderServerRoot', () => {
  // Mode-agnostic copy: the same page is served regardless of single-user
  // vs multi-user. The status pill carries the mode label; the buttons
  // adapt at load time via the HEAD probe (verified separately below).
  it('renders the same mode-agnostic copy regardless of singleUser flag', () => {
    const single = renderServerRoot({ version: '1.0.0', singleUser: true });
    const multi = renderServerRoot({ version: '1.0.0', singleUser: false });

    // Same welcome copy, same primary CTA, same explainer.
    for (const html of [single, multi]) {
      assert.match(html, /<h1>Welcome<\/h1>/);
      assert.match(html, /Your JSS Solid pod is running/);
      assert.match(html, /open standard for personal data/);
    }

    // Mode pill differs.
    assert.match(single, /<code>single-user<\/code>/);
    assert.match(multi, /<code>multi-user<\/code>/);
  });

  it('always emits the Get started button pointing at the docs', () => {
    const html = renderServerRoot({ version: '1.0.0' });
    assert.match(html, /href="https:\/\/jss\.live\/docs\/getting-started\/"/);
    assert.match(html, /Get started/);
  });

  it('emits Sign up + Sign in buttons hidden for the HEAD probe to reveal', () => {
    const html = renderServerRoot({ version: '1.0.0' });
    // Both anchors are present in every mode; the inline script reveals
    // them based on what /idp/register actually returns.
    assert.match(html, /<a href="\/idp\/register"[^>]*data-cond="register"[^>]*hidden/);
    assert.match(html, /<a href="\/idp"[^>]*data-cond="login"[^>]*hidden/);
    assert.match(html, /Sign up/);
    assert.match(html, /Sign in/);
  });

  it('includes the HEAD-adaptive script targeting /idp/register', () => {
    const html = renderServerRoot({ version: '1.0.0' });
    assert.match(html, /fetch\(['"]\/idp\/register['"]/);
    assert.match(html, /method:\s*['"]HEAD['"]/);
    // The three documented branches: 200 → both, 403 → login only,
    // anything else → neither. Assert the magic numbers are present.
    assert.match(html, /res\.status === 200/);
    assert.match(html, /res\.status === 403/);
  });

  it('includes the live-URL script that fills in window.location.origin', () => {
    const html = renderServerRoot({ version: '1.0.0' });
    assert.match(html, /id="server-url"/);
    assert.match(html, /window\.location\.origin/);
  });

  it('lists enabled features as pills', () => {
    const html = renderServerRoot({
      version: '1.0.0',
      enabled: { idp: true, nostr: true, webrtc: true, terminal: true }
    });
    assert.match(html, /<span>idp<\/span>/);
    assert.match(html, /<span>nostr<\/span>/);
    assert.match(html, /<span>webrtc<\/span>/);
    assert.match(html, /<span>terminal<\/span>/);
  });

  it('interpolates version into the info box', () => {
    const html = renderServerRoot({ version: '9.9.9' });
    assert.match(html, /<code>9\.9\.9<\/code>/);
  });

  it('escapes version to prevent injection', () => {
    const html = renderServerRoot({ version: '<script>alert(1)</script>' });
    assert.doesNotMatch(html, /<script>alert\(1\)<\/script>/);
    assert.match(html, /&lt;script&gt;/);
  });

  it('points the footer at the GitHub repo and the customise hint', () => {
    const html = renderServerRoot({ version: '1.0.0' });
    assert.match(html, /href="https:\/\/github\.com\/JavaScriptSolidServer\/JavaScriptSolidServer"/);
    assert.match(html, /Customise this page/);
    assert.match(html, /<code>\/index\.html<\/code>/);
  });
});
