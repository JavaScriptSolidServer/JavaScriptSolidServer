/**
 * PUT /idp/credentials — authenticated owner rotates their own password (#351)
 */

import { describe, it, before, after } from 'node:test';
import assert from 'node:assert';
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

async function loginToken(baseUrl, email, password) {
  const res = await fetch(`${baseUrl}/idp/credentials`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, password }),
  });
  const body = await res.json().catch(() => ({}));
  assert.strictEqual(res.status, 200, `login failed: ${JSON.stringify(body)}`);
  return body.access_token;
}

describe('PUT /idp/credentials — change password', () => {
  let server;
  let baseUrl;
  const DATA_DIR = './test-data-change-password';

  before(async () => {
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
  });

  it('rejects unauthenticated request with 401', async () => {
    const res = await fetch(`${baseUrl}/idp/credentials`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ currentPassword: 'a', newPassword: 'b' }),
    });
    assert.strictEqual(res.status, 401);
  });

  it('rejects missing fields with 400', async () => {
    const id = `alice${Date.now()}`;
    await createPod(baseUrl, id, `${id}@example.com`, 'oldpassword123');
    const token = await loginToken(baseUrl, `${id}@example.com`, 'oldpassword123');

    const res = await fetch(`${baseUrl}/idp/credentials`, {
      method: 'PUT',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${token}`,
      },
      body: JSON.stringify({ currentPassword: 'oldpassword123' }),
    });
    assert.strictEqual(res.status, 400);
  });

  it('rejects wrong current password with 401, hash unchanged', async () => {
    const id = `bob${Date.now()}`;
    await createPod(baseUrl, id, `${id}@example.com`, 'oldpassword123');
    const token = await loginToken(baseUrl, `${id}@example.com`, 'oldpassword123');

    const res = await fetch(`${baseUrl}/idp/credentials`, {
      method: 'PUT',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${token}`,
      },
      body: JSON.stringify({
        currentPassword: 'wrongpassword',
        newPassword: 'newpassword456',
      }),
    });
    assert.strictEqual(res.status, 401);

    // Original password still works
    const reLogin = await fetch(`${baseUrl}/idp/credentials`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: `${id}@example.com`, password: 'oldpassword123' }),
    });
    assert.strictEqual(reLogin.status, 200);
  });

  it('happy path: rotates password, old fails, new succeeds', async () => {
    const id = `carol${Date.now()}`;
    await createPod(baseUrl, id, `${id}@example.com`, 'oldpassword123');
    const token = await loginToken(baseUrl, `${id}@example.com`, 'oldpassword123');

    const res = await fetch(`${baseUrl}/idp/credentials`, {
      method: 'PUT',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${token}`,
      },
      body: JSON.stringify({
        currentPassword: 'oldpassword123',
        newPassword: 'newpassword456',
      }),
    });
    assert.strictEqual(res.status, 200);
    const body = await res.json();
    assert.strictEqual(body.ok, true);
    assert.ok(body.webid.includes(id), 'response carries webid');
    assert.ok(body.passwordChangedAt, 'response carries passwordChangedAt');

    // Old password rejected
    const oldRes = await fetch(`${baseUrl}/idp/credentials`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: `${id}@example.com`, password: 'oldpassword123' }),
    });
    assert.strictEqual(oldRes.status, 401);

    // New password accepted
    const newRes = await fetch(`${baseUrl}/idp/credentials`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: `${id}@example.com`, password: 'newpassword456' }),
    });
    assert.strictEqual(newRes.status, 200);
  });

  it('cross-account write: A authenticated cannot rotate B by sending B\'s currentPassword', async () => {
    const aId = `dave${Date.now()}`;
    const bId = `eve${Date.now() + 1}`;
    await createPod(baseUrl, aId, `${aId}@example.com`, 'apassword123');
    await createPod(baseUrl, bId, `${bId}@example.com`, 'bpassword123');

    const aToken = await loginToken(baseUrl, `${aId}@example.com`, 'apassword123');

    // A sends B's currentPassword → server resolves account from A's WebID, so the
    // currentPassword must match A's, not B's. With B's password it must fail 401
    // (and crucially must NOT touch B's account).
    const res = await fetch(`${baseUrl}/idp/credentials`, {
      method: 'PUT',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${aToken}`,
      },
      body: JSON.stringify({
        currentPassword: 'bpassword123',
        newPassword: 'hijack',
      }),
    });
    assert.strictEqual(res.status, 401);

    // B's password unchanged
    const bLogin = await fetch(`${baseUrl}/idp/credentials`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: `${bId}@example.com`, password: 'bpassword123' }),
    });
    assert.strictEqual(bLogin.status, 200);

    // A's password also unchanged
    const aLogin = await fetch(`${baseUrl}/idp/credentials`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: `${aId}@example.com`, password: 'apassword123' }),
    });
    assert.strictEqual(aLogin.status, 200);
  });
});
