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
import { renderServerRoot, decideRevealForRegisterStatus } from '../src/ui/server-root.js';
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
  // The seeded HTML is fully static — no template substitution, no
  // values vary by request. This is deliberate: anything dynamic
  // (mode, features, version) goes stale on the next mode change or
  // upgrade because the seed is skip-if-exists. Static = honest.
  it('renders byte-identical HTML regardless of the ctx passed', () => {
    const a = renderServerRoot({ version: '1.0.0', singleUser: true, enabled: { idp: true } });
    const b = renderServerRoot({ version: '99.0.0', singleUser: false, enabled: {} });
    const c = renderServerRoot();
    assert.strictEqual(a, b);
    assert.strictEqual(b, c);
    assert.match(a, /<h1>Welcome<\/h1>/);
    assert.match(a, /Your JSS Solid pod is running/);
    assert.match(a, /open standard for personal data/);
  });

  it('does not bake mode, feature, or version pills into the seeded HTML', () => {
    // All three would go stale across mode changes / upgrades because
    // the seed is skip-if-exists. The CLI banner already lists them
    // at startup. Excluded from the seed entirely.
    const html = renderServerRoot({ version: '1.2.3', singleUser: true, enabled: { idp: true, nostr: true } });
    assert.doesNotMatch(html, /<code>single-user<\/code>/);
    assert.doesNotMatch(html, /<span>idp<\/span>/);
    assert.doesNotMatch(html, /<span>nostr<\/span>/);
    assert.doesNotMatch(html, /<code>1\.2\.3<\/code>/);
    // No info box at all — there's nothing left to put in it.
    assert.doesNotMatch(html, /class="info"/);
  });

  it('always emits the Get started button pointing at the docs First Run page', () => {
    const html = renderServerRoot({ version: '1.0.0' });
    // First Run is the friendly "you just installed it, now what?"
    // walkthrough — better destination for a first-time installer than
    // the encyclopedic Introduction page. See #440.
    assert.match(html, /href="https:\/\/jss\.live\/docs\/getting-started\/first-run"/);
    assert.match(html, /Get started/);
  });

  it('emits Sign up + Sign in buttons hidden for the HEAD probe to reveal, with page-relative hrefs', () => {
    const html = renderServerRoot({ version: '1.0.0' });
    // Page-relative (./idp/...) so a reverse-proxy mount under a path
    // prefix sends visitors into the correct prefix instead of the
    // origin root. Same rationale as the ./ ACL targets from #428.
    assert.match(html, /<a href="\.\/idp\/register"[^>]*data-cond="register"[^>]*hidden/);
    assert.match(html, /<a href="\.\/idp"[^>]*data-cond="login"[^>]*hidden/);
    assert.doesNotMatch(html, /<a href="\/idp\/register"/,
      'Sign up href must be page-relative for path-prefix portability');
    assert.doesNotMatch(html, /<a href="\/idp"/,
      'Sign in href must be page-relative for path-prefix portability');
    assert.match(html, /Sign up/);
    assert.match(html, /Sign in/);
  });

  it('overrides the .btn display rule for the [hidden] attribute so the buttons actually start hidden', () => {
    // Without an explicit !important [hidden] rule, the .btn class's
    // display:inline-block beats the UA stylesheet's [hidden]{display:none}
    // and the Sign up / Sign in anchors flash visible before the HEAD probe
    // finishes. The CSS rule is the load-bearing piece; assert it's there.
    const html = renderServerRoot({ version: '1.0.0' });
    assert.match(html, /\[hidden\]\s*\{[^}]*display:\s*none\s*!important/);
  });

  it('includes the HEAD-adaptive script targeting ./idp/register (page-relative)', () => {
    const html = renderServerRoot({ version: '1.0.0' });
    // Same path-prefix portability concern as the anchor hrefs.
    assert.match(html, /fetch\(['"]\.\/idp\/register['"]/);
    assert.doesNotMatch(html, /fetch\(['"]\/idp\/register['"]/,
      'HEAD probe URL must be page-relative for path-prefix portability');
    assert.match(html, /method:\s*['"]HEAD['"]/);
    assert.match(html, /res\.status === 200/);
    assert.match(html, /res\.status === 403/);
  });

  it('includes the live-URL script that resolves the document base, not just origin', () => {
    const html = renderServerRoot({ version: '1.0.0' });
    assert.match(html, /id="server-url"/);
    // Must use new URL('./', window.location.href) so a reverse-proxy
    // mount at a path prefix is preserved. window.location.origin alone
    // would drop the prefix and display the proxy origin instead.
    assert.match(html, /new URL\(['"]\.\/['"],\s*window\.location\.href\)/);
    assert.doesNotMatch(html, /textContent\s*=\s*window\.location\.origin/,
      'live-URL must not display origin-only — it would drop the path prefix on reverse-proxy mounts');
  });

  it('uses a page-relative fallback href on the live-URL anchor', () => {
    // Before the script runs (or if scripts are blocked / blocked by CSP),
    // the anchor is still clickable. A href="/" fallback would escape
    // any reverse-proxy path prefix; use href="./" so the link stays
    // inside the mount.
    const html = renderServerRoot({ version: '1.0.0' });
    assert.match(html, /<a id="server-url" href="\.\/"/);
    assert.doesNotMatch(html, /<a id="server-url" href="\/"/,
      'fallback href must be page-relative for path-prefix portability');
  });

  it('points the footer at the GitHub repo and the customise hint', () => {
    const html = renderServerRoot({ version: '1.0.0' });
    assert.match(html, /href="https:\/\/github\.com\/JavaScriptSolidServer\/JavaScriptSolidServer"/);
    assert.match(html, /Customise this page/);
    assert.match(html, /<code>\/index\.html<\/code>/);
  });
});

// Pure-function unit tests for the HEAD response → button-reveal matrix.
// The inline script in server-root.html implements the same matrix by
// hand; a regex check on the script text (above) catches outright drops
// of the literals, but only this helper test pins down the *behaviour*
// of the matrix without needing a DOM.
describe('decideRevealForRegisterStatus', () => {
  it('reveals both Sign up and Sign in for HTTP 200 (registration open)', () => {
    assert.deepStrictEqual(
      decideRevealForRegisterStatus(200),
      { register: true, login: true }
    );
  });

  it('reveals only Sign in for HTTP 403 (single-user — registration disabled)', () => {
    assert.deepStrictEqual(
      decideRevealForRegisterStatus(403),
      { register: false, login: true }
    );
  });

  it('reveals neither for HTTP 404 (no IDP)', () => {
    assert.deepStrictEqual(
      decideRevealForRegisterStatus(404),
      { register: false, login: false }
    );
  });

  it('reveals neither for any other status (e.g. 500)', () => {
    assert.deepStrictEqual(
      decideRevealForRegisterStatus(500),
      { register: false, login: false }
    );
  });

  it('reveals neither when status is undefined (network error)', () => {
    assert.deepStrictEqual(
      decideRevealForRegisterStatus(undefined),
      { register: false, login: false }
    );
  });
});
