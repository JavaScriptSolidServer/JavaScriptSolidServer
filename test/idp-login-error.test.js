/**
 * Login-form error rendering (#514).
 *
 * Submitting the IdP sign-in form with bad credentials set
 * `interaction.lastError` and redirected back to the form — but
 * oidc-provider's Interaction.save() persists ONLY the fields in the
 * model's IN_PAYLOAD list, and `lastError` isn't one of them. The
 * property survived in memory, was silently dropped on save, and the
 * redirected GET re-rendered a pristine form: no error banner, user
 * retries blind (the "credibility cliff" in the issue).
 *
 * Fix: the message rides in `lastSubmission` — the IN_PAYLOAD slot
 * oidc-provider designates for form re-render state.
 *
 * The test drives the real OIDC interaction flow over HTTP (register
 * client → /idp/auth → interaction redirect → POST bad credentials →
 * follow redirect) with manual cookie threading, and asserts the
 * re-rendered form carries the error.
 */

import { describe, it, before, after } from 'node:test';
import assert from 'node:assert';
import { createServer } from '../src/server.js';
import { createServer as createNetServer } from 'net';
import fs from 'fs-extra';

const TEST_HOST = 'localhost';
const DATA_DIR = './test-data-idp-login-error';

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

// Collect cookies from a response and merge into a name→value jar.
function absorbCookies(jar, res) {
  for (const c of res.headers.getSetCookie?.() || []) {
    const [pair] = c.split(';');
    const eq = pair.indexOf('=');
    if (eq > 0) jar.set(pair.slice(0, eq).trim(), pair.slice(eq + 1).trim());
  }
}
function cookieHeader(jar) {
  return [...jar.entries()].map(([k, v]) => `${k}=${v}`).join('; ');
}

describe('IdP login form error rendering (#514)', () => {
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
      logger: false,
      root: DATA_DIR,
      idp: true,
      idpIssuer: baseUrl,
      forceCloseConnections: true,
    });
    await server.listen({ port, host: TEST_HOST });

    const res = await fetch(`${baseUrl}/.pods`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name: 'alice', email: 'a@example.org', password: 'correct123' }),
    });
    assert.strictEqual(res.status, 201, 'prereq: pod creation');
  });

  after(async () => {
    if (server) await server.close();
    if (originalDataRoot === undefined) delete process.env.DATA_ROOT;
    else process.env.DATA_ROOT = originalDataRoot;
    await fs.remove(DATA_DIR);
  });

  it('re-renders the form WITH the error after a failed login', async () => {
    // 1. Dynamic client registration
    const reg = await fetch(`${baseUrl}/idp/reg`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        redirect_uris: [`${baseUrl}/cb`],
        token_endpoint_auth_method: 'none',
        grant_types: ['authorization_code'],
        response_types: ['code'],
      }),
    });
    assert.strictEqual(reg.status, 201, 'client registration');
    const { client_id: clientId } = await reg.json();

    // 2. Start the auth flow → interaction redirect + session cookies
    const jar = new Map();
    const authUrl = `${baseUrl}/idp/auth?client_id=${encodeURIComponent(clientId)}` +
      `&redirect_uri=${encodeURIComponent(`${baseUrl}/cb`)}` +
      '&response_type=code&scope=openid+webid' +
      '&code_challenge_method=S256&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&state=s1';
    const auth = await fetch(authUrl, { redirect: 'manual' });
    absorbCookies(jar, auth);
    const interactionPath = auth.headers.get('location');
    assert.ok(interactionPath?.includes('/idp/interaction/'),
      `expected interaction redirect, got ${interactionPath}`);
    const interactionUrl = interactionPath.startsWith('http')
      ? interactionPath : `${baseUrl}${interactionPath}`;

    // 3. Submit WRONG credentials
    const post = await fetch(`${interactionUrl}/login`, {
      method: 'POST',
      redirect: 'manual',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        Cookie: cookieHeader(jar),
      },
      body: 'username=alice&password=definitely-wrong',
    });
    absorbCookies(jar, post);
    assert.ok([302, 303].includes(post.status),
      `failed login must redirect back to the form, got ${post.status}`);

    // 4. Follow the redirect — the re-rendered form must carry the error
    const rerender = await fetch(interactionUrl, {
      headers: { Cookie: cookieHeader(jar) },
    });
    assert.strictEqual(rerender.status, 200);
    const html = await rerender.text();
    assert.match(html, /<div class="error">Invalid username or password<\/div>/,
      're-rendered form must show the auth error (#514: lastError was dropped by Interaction.save)');
  });
});
