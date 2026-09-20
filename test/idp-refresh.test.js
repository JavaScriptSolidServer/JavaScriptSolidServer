/**
 * POST /idp/refresh — slide a still-valid IdP Bearer token forward (#587).
 */

import { describe, it, before, after } from 'node:test';
import assert from 'node:assert';
import * as jose from 'jose';
import { createServer } from '../src/server.js';
import fs from 'fs-extra';
import { createServer as createNetServer } from 'net';

const TEST_HOST = 'localhost';

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

async function createPod(baseUrl, name, email, password) {
  const res = await fetch(`${baseUrl}/.pods`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ name, email, password }),
  });
  const body = await res.json().catch(() => ({}));
  assert.strictEqual(res.status, 201, `pod create failed: ${JSON.stringify(body)}`);
  return body;
}

async function login(baseUrl, email, password) {
  const res = await fetch(`${baseUrl}/idp/credentials`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, password }),
  });
  const body = await res.json().catch(() => ({}));
  assert.strictEqual(res.status, 200, `login failed: ${JSON.stringify(body)}`);
  return body;
}

function refresh(baseUrl, token) {
  return fetch(`${baseUrl}/idp/refresh`, {
    method: 'POST',
    headers: { Authorization: `Bearer ${token}` },
  });
}

describe('POST /idp/refresh (#587)', () => {
  let server;
  let baseUrl;
  let originalDataRoot;
  const DATA_DIR = './test-data-idp-refresh';

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
  });

  after(async () => {
    await server.close();
    await fs.remove(DATA_DIR);
    if (originalDataRoot === undefined) delete process.env.DATA_ROOT;
    else process.env.DATA_ROOT = originalDataRoot;
  });

  it('rejects a request without a Bearer token (401)', async () => {
    const res = await fetch(`${baseUrl}/idp/refresh`, { method: 'POST' });
    assert.strictEqual(res.status, 401);
  });

  it('rejects a garbage token (401)', async () => {
    const res = await refresh(baseUrl, 'not.a.jwt');
    assert.strictEqual(res.status, 401);
  });

  it('issues a fresh token from a valid one, for the same WebID', async () => {
    const id = `alice${Date.now()}`;
    await createPod(baseUrl, id, `${id}@example.com`, 'oldpassword123');
    const first = await login(baseUrl, `${id}@example.com`, 'oldpassword123');

    const res = await refresh(baseUrl, first.access_token);
    assert.strictEqual(res.status, 200);
    const body = await res.json();
    assert.strictEqual(body.token_type, 'Bearer');
    assert.strictEqual(body.expires_in, 3600);
    assert.strictEqual(body.webid, first.webid);
    assert.ok(body.access_token && body.access_token !== first.access_token, 'a new token is issued');

    // The fresh token actually authenticates a protected request.
    const whoami = await fetch(`${baseUrl}/${id}/`, {
      headers: { Authorization: `Bearer ${body.access_token}` },
    });
    assert.ok(whoami.status < 400, `refreshed token should authenticate, got ${whoami.status}`);
  });

  it('preserves the original-auth-time (oat) claim across a refresh chain', async () => {
    const id = `bob${Date.now()}`;
    await createPod(baseUrl, id, `${id}@example.com`, 'oldpassword123');
    const first = await login(baseUrl, `${id}@example.com`, 'oldpassword123');
    const firstOat = jose.decodeJwt(first.access_token).oat;
    assert.strictEqual(typeof firstOat, 'number', 'credentials token carries oat');

    const r1 = await (await refresh(baseUrl, first.access_token)).json();
    const r2 = await (await refresh(baseUrl, r1.access_token)).json();
    assert.strictEqual(jose.decodeJwt(r1.access_token).oat, firstOat);
    assert.strictEqual(jose.decodeJwt(r2.access_token).oat, firstOat, 'oat is stable across the chain');
  });

  it('refuses to refresh once the chain exceeds refreshMaxAge', async () => {
    // Fresh server with a 0s cap: any token is already past the absolute age.
    const port = await getAvailablePort();
    const capBase = `http://${TEST_HOST}:${port}`;
    const capDir = './test-data-idp-refresh-cap';
    await fs.remove(capDir);
    const capServer = createServer({
      logger: false, root: capDir, idp: true, idpIssuer: capBase,
      refreshMaxAge: 0, forceCloseConnections: true,
    });
    await capServer.listen({ port, host: TEST_HOST });
    try {
      const id = `carol${Date.now()}`;
      await createPod(capBase, id, `${id}@example.com`, 'oldpassword123');
      const first = await login(capBase, `${id}@example.com`, 'oldpassword123');
      const res = await refresh(capBase, first.access_token);
      assert.strictEqual(res.status, 401);
      const body = await res.json();
      assert.strictEqual(body.error, 'invalid_grant');
    } finally {
      await capServer.close();
      await fs.remove(capDir);
    }
  });

  it('will not refresh a token this server did not issue (401)', async () => {
    // A well-formed JWT signed by a stranger key must not be refreshable.
    const { privateKey } = await jose.generateKeyPair('ES256');
    const forged = await new jose.SignJWT({ webid: `${baseUrl}/eve/profile/card#me`, sub: 'eve' })
      .setProtectedHeader({ alg: 'ES256' })
      .setIssuer(baseUrl)
      .setExpirationTime('1h')
      .sign(privateKey);
    const res = await refresh(baseUrl, forged);
    assert.strictEqual(res.status, 401);
  });
});
