/**
 * DELETE /idp/account — authenticated owner deletes their own account (#352)
 */

import { describe, it, before, after } from 'node:test';
import assert from 'node:assert';
import { createServer } from '../src/server.js';
import fs from 'fs-extra';
import path from 'path';
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

describe('DELETE /idp/account — self-delete', () => {
  let server;
  let baseUrl;
  let originalDataRoot;
  const DATA_DIR = './test-data-delete-account';

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

  it('rejects unauthenticated request with 401', async () => {
    const res = await fetch(`${baseUrl}/idp/account`, {
      method: 'DELETE',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ currentPassword: 'whatever' }),
    });
    assert.strictEqual(res.status, 401);
  });

  it('rejects missing currentPassword with 400', async () => {
    const id = `alice${Date.now()}`;
    await createPod(baseUrl, id, `${id}@example.com`, 'password123');
    const token = await loginToken(baseUrl, `${id}@example.com`, 'password123');

    const res = await fetch(`${baseUrl}/idp/account`, {
      method: 'DELETE',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${token}`,
      },
      body: JSON.stringify({}),
    });
    assert.strictEqual(res.status, 400);
  });

  it('rejects wrong currentPassword with 401, account untouched', async () => {
    const id = `bob${Date.now()}`;
    await createPod(baseUrl, id, `${id}@example.com`, 'password123');
    const token = await loginToken(baseUrl, `${id}@example.com`, 'password123');

    const res = await fetch(`${baseUrl}/idp/account`, {
      method: 'DELETE',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${token}`,
      },
      body: JSON.stringify({ currentPassword: 'wrongpassword' }),
    });
    assert.strictEqual(res.status, 401);

    // Account still works
    const reLogin = await fetch(`${baseUrl}/idp/credentials`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: `${id}@example.com`, password: 'password123' }),
    });
    assert.strictEqual(reLogin.status, 200);
  });

  it('happy path: deletes account; subsequent login fails with 401', async () => {
    const id = `carol${Date.now()}`;
    await createPod(baseUrl, id, `${id}@example.com`, 'password123');
    const token = await loginToken(baseUrl, `${id}@example.com`, 'password123');

    const res = await fetch(`${baseUrl}/idp/account`, {
      method: 'DELETE',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${token}`,
      },
      body: JSON.stringify({ currentPassword: 'password123' }),
    });
    assert.strictEqual(res.status, 200);
    const body = await res.json();
    assert.strictEqual(body.ok, true);
    assert.ok(body.webid.includes(id), 'response carries webid');
    assert.strictEqual(body.purged, false, 'purgeData defaults to false');

    // Login as the same user now fails
    const reLogin = await fetch(`${baseUrl}/idp/credentials`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: `${id}@example.com`, password: 'password123' }),
    });
    assert.strictEqual(reLogin.status, 401);
  });

  it('purgeData: true also wipes the pod filesystem tree', async () => {
    const id = `dave${Date.now()}`;
    await createPod(baseUrl, id, `${id}@example.com`, 'password123');
    const token = await loginToken(baseUrl, `${id}@example.com`, 'password123');

    // Pod tree exists before deletion
    const podPath = path.join(DATA_DIR, id);
    assert.strictEqual(await fs.pathExists(podPath), true,
      'pod data should exist before deletion');

    const res = await fetch(`${baseUrl}/idp/account`, {
      method: 'DELETE',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${token}`,
      },
      body: JSON.stringify({ currentPassword: 'password123', purgeData: true }),
    });
    assert.strictEqual(res.status, 200);
    const body = await res.json();
    assert.strictEqual(body.purged, true);

    // Pod tree gone
    assert.strictEqual(await fs.pathExists(podPath), false,
      'pod data should be purged');
  });

  it('purgeData: true removes the on-disk pod dir even when it has uppercase letters', async () => {
    // Regression for the bug where purge derived its path from
    // account.username (which createAccount lowercases) instead of
    // account.podName (which preserves the original case). On
    // case-sensitive filesystems the pod dir at <dataRoot>/Greta…/
    // wouldn't match the derived <dataRoot>/greta…/ path.
    const id = `Greta${Date.now()}`;
    await createPod(baseUrl, id, `${id.toLowerCase()}@example.com`, 'password123');
    const token = await loginToken(baseUrl, `${id.toLowerCase()}@example.com`, 'password123');

    const podPath = path.join(DATA_DIR, id); // mixed-case as created
    assert.strictEqual(await fs.pathExists(podPath), true,
      'pod data should exist at the mixed-case path before deletion');

    const res = await fetch(`${baseUrl}/idp/account`, {
      method: 'DELETE',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${token}`,
      },
      body: JSON.stringify({ currentPassword: 'password123', purgeData: true }),
    });
    assert.strictEqual(res.status, 200);
    const body = await res.json();
    assert.strictEqual(body.purged, true, 'purge should report success');

    assert.strictEqual(await fs.pathExists(podPath), false,
      'mixed-case pod dir should be gone (regression: not stranded by username lowercasing)');
  });

  it('purgeData: false (default) preserves the pod filesystem tree', async () => {
    const id = `frank${Date.now()}`;
    await createPod(baseUrl, id, `${id}@example.com`, 'password123');
    const token = await loginToken(baseUrl, `${id}@example.com`, 'password123');

    const podPath = path.join(DATA_DIR, id);
    assert.strictEqual(await fs.pathExists(podPath), true);

    const res = await fetch(`${baseUrl}/idp/account`, {
      method: 'DELETE',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${token}`,
      },
      // Note: no purgeData flag at all
      body: JSON.stringify({ currentPassword: 'password123' }),
    });
    assert.strictEqual(res.status, 200);

    // Account is gone but pod data preserved
    assert.strictEqual(await fs.pathExists(podPath), true,
      'pod data should be preserved when purgeData is omitted');
  });

  it('cross-account: A authenticated, sending B\'s password — fails 401, neither account touched', async () => {
    const aId = `eve${Date.now()}`;
    const bId = `mallory${Date.now() + 1}`;
    await createPod(baseUrl, aId, `${aId}@example.com`, 'apassword123');
    await createPod(baseUrl, bId, `${bId}@example.com`, 'bpassword123');

    const aToken = await loginToken(baseUrl, `${aId}@example.com`, 'apassword123');

    // A sends B's password — handler resolves account from A's WebID, so the
    // currentPassword must match A's. With B's password it fails 401 (and
    // crucially doesn't touch either account).
    const res = await fetch(`${baseUrl}/idp/account`, {
      method: 'DELETE',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${aToken}`,
      },
      body: JSON.stringify({ currentPassword: 'bpassword123' }),
    });
    assert.strictEqual(res.status, 401);

    // Both accounts still functional
    const aLogin = await fetch(`${baseUrl}/idp/credentials`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: `${aId}@example.com`, password: 'apassword123' }),
    });
    assert.strictEqual(aLogin.status, 200);

    const bLogin = await fetch(`${baseUrl}/idp/credentials`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: `${bId}@example.com`, password: 'bpassword123' }),
    });
    assert.strictEqual(bLogin.status, 200);
  });
});

describe('GET/POST /idp/account/delete — HTML form (#392)', () => {
  let server;
  let baseUrl;
  let originalDataRoot;
  const DATA_DIR = './test-data-delete-form';

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

  it('GET renders the form HTML', async () => {
    const res = await fetch(`${baseUrl}/idp/account/delete`);
    assert.strictEqual(res.status, 200);
    const ct = res.headers.get('content-type') || '';
    assert.match(ct, /text\/html/);
    const html = await res.text();
    assert.match(html, /<form\s[^>]*action="\/idp\/account\/delete"/);
    assert.match(html, /name="username"/);
    assert.match(html, /name="currentPassword"/);
    assert.match(html, /name="confirmUsername"/);
    assert.match(html, /name="purgeData"/);
    assert.match(html, /Delete my account permanently/);
  });

  it('POST happy path: deletes account, returns success HTML, login fails after', async () => {
    const id = `harry${Date.now()}`;
    await createPod(baseUrl, id, `${id}@example.com`, 'password123');

    const formBody = new URLSearchParams({
      username: id,
      currentPassword: 'password123',
      confirmUsername: id,
    });
    const res = await fetch(`${baseUrl}/idp/account/delete`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: formBody,
    });
    assert.strictEqual(res.status, 200);
    const html = await res.text();
    assert.match(html, /Account deleted/);

    // Login now fails
    const reLogin = await fetch(`${baseUrl}/idp/credentials`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: `${id}@example.com`, password: 'password123' }),
    });
    assert.strictEqual(reLogin.status, 401);
  });

  it('POST with purgeData=on also wipes the pod tree', async () => {
    const id = `iris${Date.now()}`;
    await createPod(baseUrl, id, `${id}@example.com`, 'password123');
    const podPath = path.join(DATA_DIR, id);
    assert.strictEqual(await fs.pathExists(podPath), true);

    const formBody = new URLSearchParams({
      username: id,
      currentPassword: 'password123',
      confirmUsername: id,
      purgeData: 'on',
    });
    const res = await fetch(`${baseUrl}/idp/account/delete`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: formBody,
    });
    assert.strictEqual(res.status, 200);
    assert.strictEqual(await fs.pathExists(podPath), false);
  });

  it('POST with mismatched confirmUsername renders form with error, account untouched', async () => {
    const id = `jack${Date.now()}`;
    await createPod(baseUrl, id, `${id}@example.com`, 'password123');

    const formBody = new URLSearchParams({
      username: id,
      currentPassword: 'password123',
      confirmUsername: 'totally-different',
    });
    const res = await fetch(`${baseUrl}/idp/account/delete`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: formBody,
    });
    assert.strictEqual(res.status, 200);
    const html = await res.text();
    assert.match(html, /Confirmation does not match/);
    // Username pre-filled in the form for retry
    assert.match(html, new RegExp(`value="${id}"`));

    // Account intact
    const login = await fetch(`${baseUrl}/idp/credentials`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: `${id}@example.com`, password: 'password123' }),
    });
    assert.strictEqual(login.status, 200);
  });

  it('POST with wrong password renders form with error, account untouched', async () => {
    const id = `kelly${Date.now()}`;
    await createPod(baseUrl, id, `${id}@example.com`, 'password123');

    const formBody = new URLSearchParams({
      username: id,
      currentPassword: 'wrong',
      confirmUsername: id,
    });
    const res = await fetch(`${baseUrl}/idp/account/delete`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: formBody,
    });
    assert.strictEqual(res.status, 200);
    const html = await res.text();
    assert.match(html, /incorrect/i);

    // Account intact
    const login = await fetch(`${baseUrl}/idp/credentials`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: `${id}@example.com`, password: 'password123' }),
    });
    assert.strictEqual(login.status, 200);
  });

  it('POST with missing fields renders form with error', async () => {
    const formBody = new URLSearchParams({
      username: 'someone',
      // currentPassword and confirmUsername omitted
    });
    const res = await fetch(`${baseUrl}/idp/account/delete`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: formBody,
    });
    assert.strictEqual(res.status, 200);
    const html = await res.text();
    assert.match(html, /required/i);
  });
});

describe('GET/POST /idp/account/delete — single-user mode renders disabled message', () => {
  let server;
  let baseUrl;
  let originalDataRoot;
  let originalPassword;
  const DATA_DIR = './test-data-delete-form-single';

  before(async () => {
    originalDataRoot = process.env.DATA_ROOT;
    originalPassword = process.env.JSS_SINGLE_USER_PASSWORD;
    process.env.JSS_SINGLE_USER_PASSWORD = 'singletest';
    await fs.remove(DATA_DIR);
    await fs.ensureDir(DATA_DIR);
    const port = await getAvailablePort();
    baseUrl = `http://${TEST_HOST}:${port}`;
    server = createServer({
      logger: false,
      root: DATA_DIR,
      idp: true,
      idpIssuer: baseUrl,
      singleUser: true,
      singleUserName: 'me',
      singleUserPassword: 'singletest',
      forceCloseConnections: true,
    });
    await server.listen({ port, host: TEST_HOST });
  });

  after(async () => {
    await server.close();
    await fs.remove(DATA_DIR);
    if (originalDataRoot === undefined) delete process.env.DATA_ROOT;
    else process.env.DATA_ROOT = originalDataRoot;
    if (originalPassword === undefined) delete process.env.JSS_SINGLE_USER_PASSWORD;
    else process.env.JSS_SINGLE_USER_PASSWORD = originalPassword;
  });

  it('GET renders the disabled message instead of the form', async () => {
    const res = await fetch(`${baseUrl}/idp/account/delete`);
    assert.strictEqual(res.status, 200);
    const html = await res.text();
    assert.match(html, /single-user mode/i);
    assert.match(html, /jss account delete/);
    // No form
    assert.doesNotMatch(html, /<form\s[^>]*action="\/idp\/account\/delete"/);
  });

  it('POST also returns the disabled message — does not delete', async () => {
    const formBody = new URLSearchParams({
      username: 'me',
      currentPassword: 'singletest',
      confirmUsername: 'me',
    });
    const res = await fetch(`${baseUrl}/idp/account/delete`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: formBody,
    });
    assert.strictEqual(res.status, 200);
    const html = await res.text();
    assert.match(html, /single-user mode/i);

    // Account still works
    const login = await fetch(`${baseUrl}/idp/credentials`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: 'me', password: 'singletest' }),
    });
    assert.strictEqual(login.status, 200);
  });
});

describe('DELETE /idp/account — single-user mode', () => {
  let server;
  let baseUrl;
  let originalDataRoot;
  let originalPassword;
  const DATA_DIR = './test-data-delete-account-single';

  before(async () => {
    originalDataRoot = process.env.DATA_ROOT;
    originalPassword = process.env.JSS_SINGLE_USER_PASSWORD;
    process.env.JSS_SINGLE_USER_PASSWORD = 'singletest';
    await fs.remove(DATA_DIR);
    await fs.ensureDir(DATA_DIR);
    const port = await getAvailablePort();
    baseUrl = `http://${TEST_HOST}:${port}`;
    server = createServer({
      logger: false,
      root: DATA_DIR,
      idp: true,
      idpIssuer: baseUrl,
      singleUser: true,
      singleUserName: 'me',
      singleUserPassword: 'singletest',
      forceCloseConnections: true,
    });
    await server.listen({ port, host: TEST_HOST });
  });

  after(async () => {
    await server.close();
    await fs.remove(DATA_DIR);
    if (originalDataRoot === undefined) delete process.env.DATA_ROOT;
    else process.env.DATA_ROOT = originalDataRoot;
    if (originalPassword === undefined) delete process.env.JSS_SINGLE_USER_PASSWORD;
    else process.env.JSS_SINGLE_USER_PASSWORD = originalPassword;
  });

  it('returns 403 in single-user mode (deletion would brick the server)', async () => {
    // Even with a valid token, the endpoint refuses in single-user mode.
    // Operator must use the CLI (`jss account delete`) instead.
    const token = await loginToken(baseUrl, 'me', 'singletest');

    const res = await fetch(`${baseUrl}/idp/account`, {
      method: 'DELETE',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${token}`,
      },
      body: JSON.stringify({ currentPassword: 'singletest' }),
    });
    assert.strictEqual(res.status, 403);
    const body = await res.json();
    assert.match(body.error_description || '', /single-user/i);

    // Account still functional
    const reLogin = await fetch(`${baseUrl}/idp/credentials`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: 'me', password: 'singletest' }),
    });
    assert.strictEqual(reLogin.status, 200);
  });
});
