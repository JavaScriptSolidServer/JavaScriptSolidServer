/**
 * Passkey login degrades on WebView/insecure contexts (#556).
 *
 * Two problems on stale Android System WebViews (de-Googled phones):
 *   1. The login page's inline JS called `crypto.randomUUID()` to make a
 *      `visitorId` — missing on old WebViews (Chromium <92 / non-secure),
 *      so "Sign in with Passkey" threw `crypto.randomUUID is not a
 *      function`. Unlike jspod (#65), where the call lives inside the
 *      imported solid-oidc library, JSS OWNS the call site: the server
 *      already mints the challengeKey (Node crypto, always available)
 *      and returns it, so the browser call was redundant. Removed.
 *   2. Both passkey ceremonies (login get(), prompt create()) would
 *      fail deep with a cryptic WebAuthn error on a WebView that can't
 *      do WebAuthn at all. Now guarded with a secure-context /
 *      PublicKeyCredential check that steers the user to the password
 *      form (login) or "Skip for now" (prompt).
 */

import { describe, it, before, after } from 'node:test';
import assert from 'node:assert';
import { loginPage, passkeyPromptPage } from '../src/idp/views.js';
import { createServer } from '../src/server.js';
import { createServer as createNetServer } from 'net';
import fs from 'fs-extra';

const TEST_HOST = 'localhost';
const DATA_DIR = './test-data-passkey-degrade';

function getAvailablePort() {
  return new Promise((resolve, reject) => {
    const srv = createNetServer();
    srv.on('error', reject);
    srv.listen(0, TEST_HOST, () => {
      const port = srv.address().port;
      srv.close(() => resolve(port));
    });
  });
}

function inlineScripts(html) {
  return [...html.matchAll(/<script>([\s\S]*?)<\/script>/g)].map((m) => m[1]);
}

describe('passkey WebAuthn degradation (#556)', () => {
  describe('rendered pages', () => {
    it('login page no longer emits a browser crypto.randomUUID() call', () => {
      const html = loginPage('uid-1', 'client-1', null, true, true);
      assert.ok(!/crypto\.randomUUID\(\)/.test(html),
        'no crypto.randomUUID() call should survive in the served JS');
      assert.ok(html.includes('JSON.stringify({})'),
        'login options request sends an empty body (server mints challengeKey)');
    });

    it('login page guards on secure-context + WebAuthn before the ceremony', () => {
      const html = loginPage('uid-1', 'client-1', null, true, true);
      assert.ok(html.includes('isSecureContext') && html.includes('PublicKeyCredential'),
        'WebAuthn availability is checked up front');
    });

    it('passkey prompt page guards registration the same way', () => {
      const html = passkeyPromptPage('uid-1', 'acct-1');
      assert.ok(html.includes('isSecureContext') && html.includes('PublicKeyCredential'),
        'registration ceremony is guarded too');
    });

    it('every inline <script> in both pages is syntactically valid JS', () => {
      for (const html of [loginPage('u', 'c', null, true, true), passkeyPromptPage('u', 'a')]) {
        for (const src of inlineScripts(html)) {
          assert.doesNotThrow(() => new Function(src),
            'inline script must parse (escaping regression guard)');
        }
      }
    });
  });

  describe('options endpoint mints the challengeKey server-side', () => {
    let server;
    let baseUrl;
    let originalDataRoot;

    before(async () => {
      originalDataRoot = process.env.DATA_ROOT;
      await fs.remove(DATA_DIR);
      await fs.ensureDir(DATA_DIR);
      const port = await getAvailablePort();
      baseUrl = `http://${TEST_HOST}:${port}`;
      server = createServer({
        logger: false, root: DATA_DIR, idp: true,
        idpIssuer: baseUrl, forceCloseConnections: true,
      });
      await server.listen({ port, host: TEST_HOST });
    });

    after(async () => {
      if (server) await server.close();
      if (originalDataRoot === undefined) delete process.env.DATA_ROOT;
      else process.env.DATA_ROOT = originalDataRoot;
      await fs.remove(DATA_DIR);
    });

    it('returns a challengeKey for an EMPTY options body (no client visitorId needed)', async () => {
      // This is what the page now sends. The server falls back to its
      // own crypto.randomUUID() (Node, always available) and returns the
      // key the client echoes on verify — so dropping the browser call
      // is functionally complete, not a regression.
      const res = await fetch(`${baseUrl}/idp/passkey/login/options`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({}),
      });
      assert.strictEqual(res.status, 200, 'anonymous options request must succeed');
      const body = await res.json();
      assert.ok(typeof body.challengeKey === 'string' && body.challengeKey.length > 0,
        'server must return a challengeKey the client can echo on verify');
      assert.ok(body.challenge, 'WebAuthn challenge present');
    });
  });
});
