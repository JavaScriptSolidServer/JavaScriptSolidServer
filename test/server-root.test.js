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

  // Regression for token re-scanning (#433 review thread): if the
  // renderer ran a chain of sequential .replace() calls, a value
  // containing a literal `{{actions}}` would land inside the subtitle
  // and then get expanded by the later `.replace(/{{actions}}/g, ...)`,
  // letting any pod owner inject other template fragments via their
  // singleUserName. The single-pass substitution prevents that.
  it('does not re-scan substituted values for further template tokens', () => {
    const html = renderServerRoot({
      version: '1.0.0',
      singleUser: true,
      idp: false,
      // The HTML escape only touches & < > " — { } pass through, so the
      // token would land in the output verbatim if the substitution were
      // multi-pass.
      singleUserName: 'evil{{actions}}name'
    });
    assert.match(html, /Personal pod for evil\{\{actions\}\}name/,
      'singleUserName containing a template token should appear as plain text, not be re-templated');
    // Sanity: the real {{actions}} slot is still resolved (Docs link is always present).
    assert.match(html, /href="https:\/\/javascriptsolidserver\.github\.io\/docs/);
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
