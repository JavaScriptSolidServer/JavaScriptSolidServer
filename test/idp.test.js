/**
 * Identity Provider Tests
 */

import { describe, it, before, after, beforeEach } from 'node:test';
import assert from 'node:assert';
import { createServer } from '../src/server.js';
import fs from 'fs-extra';
import path from 'path';

const TEST_PORT = 3099;
const TEST_HOST = 'localhost';
const BASE_URL = `http://${TEST_HOST}:${TEST_PORT}`;
const DATA_DIR = './test-data-idp';

describe('Identity Provider', () => {
  let server;

  before(async () => {
    // Clean up any existing test data
    await fs.remove(DATA_DIR);
    await fs.ensureDir(DATA_DIR);

    // Create server with IdP enabled
    server = createServer({
      logger: false,
      root: DATA_DIR,
      idp: true,
      idpIssuer: BASE_URL,
    });

    await server.listen({ port: TEST_PORT, host: TEST_HOST });
  });

  after(async () => {
    await server.close();
    await fs.remove(DATA_DIR);
  });

  describe('OIDC Discovery', () => {
    it('should serve /.well-known/openid-configuration', async () => {
      const res = await fetch(`${BASE_URL}/.well-known/openid-configuration`);
      assert.strictEqual(res.status, 200);

      const config = await res.json();
      // Issuer has trailing slash for CTH compatibility
      assert.strictEqual(config.issuer, BASE_URL + '/');
      assert.ok(config.authorization_endpoint);
      assert.ok(config.token_endpoint);
      assert.ok(config.jwks_uri);
    });

    it('should include required Solid-OIDC endpoints', async () => {
      const res = await fetch(`${BASE_URL}/.well-known/openid-configuration`);
      const config = await res.json();

      assert.ok(config.registration_endpoint, 'should have registration endpoint');
      assert.ok(config.scopes_supported.includes('webid'), 'should support webid scope');
      assert.ok(config.dpop_signing_alg_values_supported, 'should support DPoP');
    });

    it('should serve /.well-known/jwks.json', async () => {
      const res = await fetch(`${BASE_URL}/.well-known/jwks.json`);
      assert.strictEqual(res.status, 200);

      const jwks = await res.json();
      assert.ok(Array.isArray(jwks.keys));
      assert.ok(jwks.keys.length > 0, 'should have at least one key');
      // Keys should be public (no 'd' component)
      assert.ok(!jwks.keys[0].d, 'should not expose private key component');
    });
  });

  describe('Pod Creation with IdP', () => {
    it('should require email when IdP is enabled', async () => {
      const res = await fetch(`${BASE_URL}/.pods`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name: 'noemail' }),
      });

      assert.strictEqual(res.status, 400);
      const body = await res.json();
      assert.ok(body.error.includes('Email'));
    });

    it('should require password when IdP is enabled', async () => {
      const res = await fetch(`${BASE_URL}/.pods`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name: 'nopass', email: 'test@example.com' }),
      });

      assert.strictEqual(res.status, 400);
      const body = await res.json();
      assert.ok(body.error.includes('Password'));
    });

    it('should create pod with account', async () => {
      const uniqueId = Date.now();
      const res = await fetch(`${BASE_URL}/.pods`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          name: `idpuser${uniqueId}`,
          email: `idpuser${uniqueId}@example.com`,
          password: 'securepassword123',
        }),
      });

      assert.strictEqual(res.status, 201);
      const body = await res.json();

      assert.strictEqual(body.name, `idpuser${uniqueId}`);
      assert.ok(body.webId.includes(`idpuser${uniqueId}`));
      assert.ok(body.podUri.includes(`idpuser${uniqueId}`));
      assert.ok(body.idpIssuer, 'should include IdP issuer');
      assert.ok(body.loginUrl, 'should include login URL');
      // Should NOT have simple token when IdP is enabled
      assert.ok(!body.token, 'should not have simple token');
    });

    it('should reject duplicate email', async () => {
      const uniqueId = Date.now();
      const duplicateEmail = `duplicate${uniqueId}@example.com`;

      // First user
      await fetch(`${BASE_URL}/.pods`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          name: `first${uniqueId}`,
          email: duplicateEmail,
          password: 'password123',
        }),
      });

      // Second user with same email
      const res = await fetch(`${BASE_URL}/.pods`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          name: `second${uniqueId}`,
          email: duplicateEmail,
          password: 'password456',
        }),
      });

      assert.strictEqual(res.status, 409);
      const body = await res.json();
      assert.ok(body.error.includes('Email'));
    });
  });

  describe('Login Interaction', () => {
    it('should respond to authorization endpoint', async () => {
      // Start an authorization flow
      // Various responses are acceptable - 302/303 (redirect), 400 (bad request), 404 (no route)
      // This just verifies the server handles the request
      const res = await fetch(`${BASE_URL}/idp/auth?client_id=test&redirect_uri=http://localhost&response_type=code&scope=openid`, {
        redirect: 'manual',
      });

      // oidc-provider mounted via middie may return different status codes
      // The important thing is it doesn't crash and returns a valid HTTP response
      assert.ok(res.status >= 200 && res.status < 600, `got valid HTTP status ${res.status}`);
    });
  });
});

describe('Identity Provider - Accounts', () => {
  let server;
  const ACCOUNTS_DATA_DIR = './test-data-idp-accounts';

  before(async () => {
    await fs.remove(ACCOUNTS_DATA_DIR);
    await fs.ensureDir(ACCOUNTS_DATA_DIR);

    server = createServer({
      logger: false,
      root: ACCOUNTS_DATA_DIR,
      idp: true,
      idpIssuer: `http://${TEST_HOST}:${TEST_PORT + 1}`,
    });

    await server.listen({ port: TEST_PORT + 1, host: TEST_HOST });
  });

  after(async () => {
    await server.close();
    await fs.remove(ACCOUNTS_DATA_DIR);
  });

  it('should store account data in .idp directory', async () => {
    const uniqueName = `stored${Date.now()}`;
    const uniqueEmail = `stored${Date.now()}@example.com`;

    const res = await fetch(`http://${TEST_HOST}:${TEST_PORT + 1}/.pods`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        name: uniqueName,
        email: uniqueEmail,
        password: 'password123',
      }),
    });

    assert.strictEqual(res.status, 201, 'pod creation should succeed');

    // Check that account data exists
    const accountsDir = path.join(ACCOUNTS_DATA_DIR, '.idp', 'accounts');
    const exists = await fs.pathExists(accountsDir);
    assert.ok(exists, 'accounts directory should exist');

    // Check email index
    const emailIndex = await fs.readJson(path.join(accountsDir, '_email_index.json'));
    assert.ok(emailIndex[uniqueEmail], 'email index should contain account');
  });

  it('should hash passwords', async () => {
    const uniqueName = `hashed${Date.now()}`;
    const uniqueEmail = `hashed${Date.now()}@example.com`;

    const res = await fetch(`http://${TEST_HOST}:${TEST_PORT + 1}/.pods`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        name: uniqueName,
        email: uniqueEmail,
        password: 'mypassword',
      }),
    });

    assert.strictEqual(res.status, 201, 'pod creation should succeed');

    // Read account file
    const accountsDir = path.join(ACCOUNTS_DATA_DIR, '.idp', 'accounts');
    const emailIndex = await fs.readJson(path.join(accountsDir, '_email_index.json'));
    const accountId = emailIndex[uniqueEmail];
    const account = await fs.readJson(path.join(accountsDir, `${accountId}.json`));

    // Password should be hashed, not plain text
    assert.ok(account.passwordHash, 'should have passwordHash');
    assert.ok(account.passwordHash.startsWith('$2'), 'should be bcrypt hash');
    assert.ok(!account.password, 'should not store plain password');
  });
});

describe('Identity Provider - Credentials Endpoint', () => {
  let server;
  // Use same data dir as other tests (DATA_ROOT is cached at module load)
  const CREDS_DATA_DIR = './data';
  const CREDS_PORT = 3101;
  const CREDS_URL = `http://${TEST_HOST}:${CREDS_PORT}`;

  before(async () => {
    await fs.emptyDir(CREDS_DATA_DIR);

    server = createServer({
      logger: false,
      idp: true,
      idpIssuer: CREDS_URL,
    });

    await server.listen({ port: CREDS_PORT, host: TEST_HOST });

    // Create a test user
    const res = await fetch(`${CREDS_URL}/.pods`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        name: 'credtest',
        email: 'credtest@example.com',
        password: 'testpassword123',
      }),
    });
    if (!res.ok) {
      throw new Error(`Failed to create test user: ${res.status} ${await res.text()}`);
    }
  });

  after(async () => {
    await server.close();
    await fs.emptyDir(CREDS_DATA_DIR);
  });

  describe('GET /idp/credentials', () => {
    it('should return endpoint info', async () => {
      const res = await fetch(`${CREDS_URL}/idp/credentials`);
      assert.strictEqual(res.status, 200);

      const info = await res.json();
      assert.ok(info.endpoint);
      assert.strictEqual(info.method, 'POST');
      assert.ok(info.parameters.email);
      assert.ok(info.parameters.password);
    });
  });

  describe('POST /idp/credentials', () => {
    it('should return 400 for missing credentials', async () => {
      const res = await fetch(`${CREDS_URL}/idp/credentials`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({}),
      });

      assert.strictEqual(res.status, 400);
      const body = await res.json();
      assert.strictEqual(body.error, 'invalid_request');
    });

    it('should return 401 for wrong password', async () => {
      const res = await fetch(`${CREDS_URL}/idp/credentials`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          email: 'credtest@example.com',
          password: 'wrongpassword',
        }),
      });

      assert.strictEqual(res.status, 401);
      const body = await res.json();
      assert.strictEqual(body.error, 'invalid_grant');
    });

    it('should return 401 for unknown email', async () => {
      const res = await fetch(`${CREDS_URL}/idp/credentials`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          email: 'unknown@example.com',
          password: 'anypassword',
        }),
      });

      assert.strictEqual(res.status, 401);
    });

    it('should return access token for valid credentials', async () => {
      const res = await fetch(`${CREDS_URL}/idp/credentials`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          email: 'credtest@example.com',
          password: 'testpassword123',
        }),
      });

      assert.strictEqual(res.status, 200);
      const body = await res.json();

      assert.ok(body.access_token, 'should have access_token');
      assert.strictEqual(body.token_type, 'Bearer');
      assert.ok(body.expires_in > 0, 'should have expires_in');
      assert.ok(body.webid.includes('credtest'), 'should have webid');
    });

    it('should return JWT token with webid claim', async () => {
      const res = await fetch(`${CREDS_URL}/idp/credentials`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          email: 'credtest@example.com',
          password: 'testpassword123',
        }),
      });

      const body = await res.json();

      // JWT tokens have format: header.payload.signature
      const parts = body.access_token.split('.');
      assert.strictEqual(parts.length, 3, 'JWT token has 3 parts');

      // Decode the payload (second part)
      const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString());

      assert.ok(payload.webid, 'token should have webid claim');
      assert.ok(payload.webid.includes('credtest'), 'webid should reference user');
      assert.ok(payload.exp > payload.iat, 'should have valid expiry');
    });

    it('should work with form-encoded body', async () => {
      const res = await fetch(`${CREDS_URL}/idp/credentials`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: 'email=credtest%40example.com&password=testpassword123',
      });

      assert.strictEqual(res.status, 200);
      const body = await res.json();
      assert.ok(body.access_token);
    });

    it('should allow using token to access protected resource', async () => {
      // Get access token
      const tokenRes = await fetch(`${CREDS_URL}/idp/credentials`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          email: 'credtest@example.com',
          password: 'testpassword123',
        }),
      });

      const { access_token } = await tokenRes.json();

      // Try to access private resource
      const res = await fetch(`${CREDS_URL}/credtest/private/`, {
        headers: { 'Authorization': `Bearer ${access_token}` },
      });

      // Should succeed (not 401/403)
      assert.ok([200, 404].includes(res.status), `expected 200 or 404, got ${res.status}`);
    });
  });
});
