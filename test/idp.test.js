/**
 * Identity Provider Tests
 */

import { describe, it, before, after, beforeEach } from 'node:test';
import assert from 'node:assert';
import { createServer } from '../src/server.js';
import fs from 'fs-extra';
import path from 'path';

const TEST_HOST = 'localhost';
import { createServer as createNetServer } from 'net';

/** Get an available port by briefly binding to port 0 */
async function getAvailablePort() {
  return new Promise((resolve, reject) => {
    const srv = createNetServer();
    srv.on('error', (err) => reject(err));
    srv.listen(0, TEST_HOST, () => {
      const port = srv.address().port;
      srv.close(() => resolve(port));
    });
  });
}

describe('Identity Provider', () => {
  let server;
  let baseUrl;
  const DATA_DIR = './test-data-idp';

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

  describe('OIDC Discovery', () => {
    it('should serve /.well-known/openid-configuration', async () => {
      const res = await fetch(`${baseUrl}/.well-known/openid-configuration`);
      assert.strictEqual(res.status, 200);

      const config = await res.json();
      // Issuer has trailing slash for CTH compatibility
      assert.strictEqual(config.issuer, baseUrl + '/');
      assert.ok(config.authorization_endpoint);
      assert.ok(config.token_endpoint);
      assert.ok(config.jwks_uri);
    });

    it('should include required Solid-OIDC endpoints', async () => {
      const res = await fetch(`${baseUrl}/.well-known/openid-configuration`);
      const config = await res.json();

      assert.ok(config.registration_endpoint, 'should have registration endpoint');
      assert.ok(config.scopes_supported.includes('webid'), 'should support webid scope');
      assert.ok(config.dpop_signing_alg_values_supported, 'should support DPoP');
    });

    it('should serve /.well-known/jwks.json', async () => {
      const res = await fetch(`${baseUrl}/.well-known/jwks.json`);
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
      const res = await fetch(`${baseUrl}/.pods`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name: 'noemail' }),
      });

      assert.strictEqual(res.status, 400);
      const body = await res.json();
      assert.ok(body.error.includes('Email'));
    });

    it('should require password when IdP is enabled', async () => {
      const res = await fetch(`${baseUrl}/.pods`, {
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
      const res = await fetch(`${baseUrl}/.pods`, {
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
      // Should also return a token for curl-based workflows
      assert.ok(body.token, 'should include token');

      // Token should work for authenticated requests
      const privateRes = await fetch(`${baseUrl}/${body.name}/private/`, {
        headers: { 'Authorization': `Bearer ${body.token}` },
      });
      assert.strictEqual(privateRes.status, 200, 'token should authenticate to private folder');
    });

    it('should reject duplicate email', async () => {
      const uniqueId = Date.now();
      const duplicateEmail = `duplicate${uniqueId}@example.com`;

      // First user
      await fetch(`${baseUrl}/.pods`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          name: `first${uniqueId}`,
          email: duplicateEmail,
          password: 'password123',
        }),
      });

      // Second user with same email
      const res = await fetch(`${baseUrl}/.pods`, {
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
      const res = await fetch(`${baseUrl}/idp/auth?client_id=test&redirect_uri=http://localhost&response_type=code&scope=openid`, {
        redirect: 'manual',
      });

      assert.ok(res.status >= 200 && res.status < 600, `got valid HTTP status ${res.status}`);
    });
  });

  // Regression coverage for #286 — friendly /idp landing + /idp/auth guard.
  describe('Landing page', () => {
    it('GET /idp returns the landing HTML', async () => {
      const res = await fetch(`${baseUrl}/idp`);
      assert.strictEqual(res.status, 200);
      assert.match(res.headers.get('content-type') || '', /text\/html/);
      const body = await res.text();
      assert.match(body, /Solid Pod Server/);
      assert.match(body, /Create Account/);
      assert.match(body, /href="\/idp\/register"/);
      // Sign-in note names pilot as the example client (#288).
      assert.match(body, /solid-apps\.github\.io\/pilot/);
    });

    it('GET /idp/auth without client_id redirects to /idp', async () => {
      const res = await fetch(`${baseUrl}/idp/auth`, { redirect: 'manual' });
      assert.strictEqual(res.status, 302);
      assert.strictEqual(res.headers.get('location'), '/idp');
    });

    it('HEAD /idp/auth without client_id also redirects to /idp', async () => {
      // Fastify auto-creates HEAD handlers for GET routes; the guard must
      // catch HEAD too so probing tools land on the friendly page rather
      // than the raw OIDC error.
      const res = await fetch(`${baseUrl}/idp/auth`, { method: 'HEAD', redirect: 'manual' });
      assert.strictEqual(res.status, 302);
      assert.strictEqual(res.headers.get('location'), '/idp');
    });

    it('GET /idp/auth WITH client_id still reaches oidc-provider', async () => {
      // Sanity: the guard must not block real OIDC requests. The provider
      // may legitimately redirect (e.g. to /idp/interaction/:uid) for
      // valid client/parameter combinations, so we test the precise
      // contract — the guard's specific 302→/idp response — rather than
      // "no redirect at all".
      const res = await fetch(
        `${baseUrl}/idp/auth?client_id=test&redirect_uri=http://localhost&response_type=code&scope=openid`,
        { redirect: 'manual' }
      );
      const location = res.headers.get('location');
      assert.ok(
        !(res.status === 302 && location === '/idp'),
        `request should bypass the /idp guard, got ${res.status} → ${location}`
      );
    });

    it('GET /idp/auth with empty client_id is a malformed OIDC request, not bare', async () => {
      // Tightened guard (=== undefined) lets ?client_id= pass through to
      // oidc-provider rather than redirecting to /idp.
      const res = await fetch(`${baseUrl}/idp/auth?client_id=`, { redirect: 'manual' });
      assert.notStrictEqual(res.headers.get('location'), '/idp');
    });
  });

  // Regression coverage for #284 — relaxed username regex + `..` rejection.
  // Each register call below also exercises the .jsonld pod-creation flow
  // from #283, since handleRegisterPost calls createPodStructure on success.
  describe('Register username validation (path mode)', () => {
    async function tryRegister(username) {
      const res = await fetch(`${baseUrl}/idp/register`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ username, password: 'secret-password', confirmPassword: 'secret-password' }),
      });
      const body = await res.text();
      return { status: res.status, body };
    }

    it('accepts plain alphanumeric (alice)', async () => {
      const r = await tryRegister('alice');
      assert.match(r.body, /Account created/);
    });

    it('accepts dash (alice-smith)', async () => {
      const r = await tryRegister('alice-smith');
      assert.match(r.body, /Account created/);
    });

    it('accepts dot (alice.smith)', async () => {
      const r = await tryRegister('alice.smith');
      assert.match(r.body, /Account created/);
    });

    it('accepts underscore (alice_work)', async () => {
      const r = await tryRegister('alice_work');
      assert.match(r.body, /Account created/);
    });

    it('rejects leading separator (.alice)', async () => {
      const r = await tryRegister('.alice');
      assert.match(r.body, /lowercase letters, numbers/);
    });

    it('rejects trailing separator (alice-)', async () => {
      const r = await tryRegister('alice-');
      assert.match(r.body, /lowercase letters, numbers/);
    });

    it('rejects consecutive dots (alice..bob)', async () => {
      const r = await tryRegister('alice..bob');
      // Quotes are HTML-escaped (&quot;) in the rendered error banner.
      assert.match(r.body, /cannot contain (?:"|&quot;)\.\.(?:"|&quot;)/);
    });

    it('rejects uppercase (Alice)', async () => {
      const r = await tryRegister('Alice');
      assert.match(r.body, /lowercase letters, numbers/);
    });

    it('rejects too short (ab)', async () => {
      const r = await tryRegister('ab');
      // Two-char names fail the regex (min 3 enforced by the pattern itself).
      assert.match(r.body, /lowercase letters, numbers|at least 3/);
    });
  });
});

// Subdomain mode: usernames become hostname components, so `.` and `_` are
// not allowed (server.js refuses to route multi-level subdomains).
describe('Identity Provider - Subdomain mode register validation', () => {
  let server;
  let baseUrl;
  const SUBDOMAIN_DATA_DIR = './test-data-idp-subdomain';

  before(async () => {
    await fs.remove(SUBDOMAIN_DATA_DIR);
    await fs.ensureDir(SUBDOMAIN_DATA_DIR);

    const port = await getAvailablePort();
    baseUrl = `http://${TEST_HOST}:${port}`;

    server = createServer({
      logger: false,
      root: SUBDOMAIN_DATA_DIR,
      idp: true,
      idpIssuer: baseUrl,
      subdomains: true,
      baseDomain: TEST_HOST,
      forceCloseConnections: true,
    });

    await server.listen({ port, host: TEST_HOST });
  });

  after(async () => {
    await server.close();
    await fs.remove(SUBDOMAIN_DATA_DIR);
  });

  async function tryRegister(username) {
    const res = await fetch(`${baseUrl}/idp/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ username, password: 'secret-password', confirmPassword: 'secret-password' }),
    });
    return { status: res.status, body: await res.text() };
  }

  it('accepts dash (alice-smith)', async () => {
    const r = await tryRegister('alice-smith');
    assert.match(r.body, /Account created/);
  });

  it('rejects dot (alice.smith) — would not be a single-level subdomain', async () => {
    const r = await tryRegister('alice.smith');
    assert.match(r.body, /subdomain mode disallows/);
  });

  it('rejects underscore (alice_work) — invalid in DNS hostnames', async () => {
    const r = await tryRegister('alice_work');
    assert.match(r.body, /subdomain mode disallows/);
  });
});

// Single-user mode: registration is disabled, so the /idp landing must
// suppress the "Create Account" button rather than ship a known 403 trap.
// Regression coverage for #290.
describe('Identity Provider - Single-user mode landing', () => {
  let server;
  let baseUrl;
  const SINGLE_USER_DATA_DIR = './test-data-idp-single-user';

  before(async () => {
    await fs.remove(SINGLE_USER_DATA_DIR);
    await fs.ensureDir(SINGLE_USER_DATA_DIR);

    const port = await getAvailablePort();
    baseUrl = `http://${TEST_HOST}:${port}`;

    server = createServer({
      logger: false,
      root: SINGLE_USER_DATA_DIR,
      idp: true,
      idpIssuer: baseUrl,
      singleUser: true,
      singleUserName: 'me',
      forceCloseConnections: true,
    });

    await server.listen({ port, host: TEST_HOST });
  });

  after(async () => {
    await server.close();
    await fs.remove(SINGLE_USER_DATA_DIR);
  });

  it('GET /idp omits the Create Account button', async () => {
    const res = await fetch(`${baseUrl}/idp`);
    assert.strictEqual(res.status, 200);
    const body = await res.text();
    // Sanity: the landing still rendered.
    assert.match(body, /Solid Pod Server/);
    // Button + register link must be absent — those would 403 in single-user mode.
    assert.doesNotMatch(body, /Create Account/);
    assert.doesNotMatch(body, /href="\/idp\/register"/);
    // Sign-in note should still mention pilot as the example client.
    assert.match(body, /solid-apps\.github\.io\/pilot/);
  });

  it('subtitle reflects the single-user shape', async () => {
    const res = await fetch(`${baseUrl}/idp`);
    const body = await res.text();
    assert.match(body, /Single-user pod/);
  });
});

// Root-level pod (singleUserName: '/') — verifies createRootPodStructure wires
// publicTypeIndex as public-read and privateTypeIndex as owner-only.
// Regression coverage for #297.
describe('Identity Provider - Root pod type index ACLs', () => {
  let server;
  let baseUrl;
  const ROOT_POD_DATA_DIR = './test-data-idp-root-pod';

  before(async () => {
    await fs.remove(ROOT_POD_DATA_DIR);
    await fs.ensureDir(ROOT_POD_DATA_DIR);

    const port = await getAvailablePort();
    baseUrl = `http://${TEST_HOST}:${port}`;

    server = createServer({
      logger: false,
      root: ROOT_POD_DATA_DIR,
      idp: true,
      idpIssuer: baseUrl,
      singleUser: true,
      singleUserName: '/',
      forceCloseConnections: true,
    });

    await server.listen({ port, host: TEST_HOST });
  });

  after(async () => {
    await server.close();
    await fs.remove(ROOT_POD_DATA_DIR);
  });

  it('publicTypeIndex is readable without auth', async () => {
    const res = await fetch(`${baseUrl}/settings/publicTypeIndex.jsonld`);
    assert.strictEqual(res.status, 200);
  });

  it('privateTypeIndex requires auth', async () => {
    const res = await fetch(`${baseUrl}/settings/privateTypeIndex.jsonld`);
    assert.strictEqual(res.status, 401);
  });

  it('prefs requires auth', async () => {
    const res = await fetch(`${baseUrl}/settings/prefs.jsonld`);
    assert.strictEqual(res.status, 401);
  });
});

describe('Identity Provider - Accounts', () => {
  let server;
  let accountsUrl;
  const ACCOUNTS_DATA_DIR = './test-data-idp-accounts';

  before(async () => {
    await fs.remove(ACCOUNTS_DATA_DIR);
    await fs.ensureDir(ACCOUNTS_DATA_DIR);

    const port = await getAvailablePort();
    accountsUrl = `http://${TEST_HOST}:${port}`;

    server = createServer({
      logger: false,
      root: ACCOUNTS_DATA_DIR,
      idp: true,
      idpIssuer: accountsUrl,
      forceCloseConnections: true,
    });

    await server.listen({ port, host: TEST_HOST });
  });

  after(async () => {
    await server.close();
    await fs.remove(ACCOUNTS_DATA_DIR);
  });

  it('should store account data in .idp directory', async () => {
    const uniqueName = `stored${Date.now()}`;
    const uniqueEmail = `stored${Date.now()}@example.com`;

    const res = await fetch(`${accountsUrl}/.pods`, {
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

    const res = await fetch(`${accountsUrl}/.pods`, {
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
  let credsUrl;
  const CREDS_DATA_DIR = './data';

  before(async () => {
    await fs.emptyDir(CREDS_DATA_DIR);

    const port = await getAvailablePort();
    credsUrl = `http://${TEST_HOST}:${port}`;

    server = createServer({
      logger: false,
      idp: true,
      idpIssuer: credsUrl,
      forceCloseConnections: true,
    });

    await server.listen({ port, host: TEST_HOST });

    // Create a test user
    const res = await fetch(`${credsUrl}/.pods`, {
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
      const res = await fetch(`${credsUrl}/idp/credentials`);
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
      const res = await fetch(`${credsUrl}/idp/credentials`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({}),
      });

      assert.strictEqual(res.status, 400);
      const body = await res.json();
      assert.strictEqual(body.error, 'invalid_request');
    });

    it('should return 401 for wrong password', async () => {
      const res = await fetch(`${credsUrl}/idp/credentials`, {
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
      const res = await fetch(`${credsUrl}/idp/credentials`, {
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
      const res = await fetch(`${credsUrl}/idp/credentials`, {
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
      const res = await fetch(`${credsUrl}/idp/credentials`, {
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
      const res = await fetch(`${credsUrl}/idp/credentials`, {
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
      const tokenRes = await fetch(`${credsUrl}/idp/credentials`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          email: 'credtest@example.com',
          password: 'testpassword123',
        }),
      });

      const { access_token } = await tokenRes.json();

      // Try to access private resource
      const res = await fetch(`${credsUrl}/credtest/private/`, {
        headers: { 'Authorization': `Bearer ${access_token}` },
      });

      // Should succeed (not 401/403)
      assert.ok([200, 404].includes(res.status), `expected 200 or 404, got ${res.status}`);
    });
  });
});

// Single-user + --idp must seed an IDP account so the operator can log in.
// Without this, the pod is created but is unloggable: registration is
// disabled in single-user mode and there's no pre-existing account.
// Regression for #323.
describe('Identity Provider — single-user password seeding (#323)', () => {
  // Save/restore DATA_ROOT and stdin.isTTY around each test so we don't
  // leak global state into other tests in the same `node --test` run.
  // For isTTY we capture the *property descriptor* so we can correctly
  // restore an inherited (prototype) accessor — Object.defineProperty
  // would otherwise leave a shadowing own-property behind.
  let originalDataRoot;
  let originalIsTTYDescriptor;
  let originalIsTTYWasOwn;
  before(() => {
    originalDataRoot = process.env.DATA_ROOT;
    originalIsTTYWasOwn = Object.prototype.hasOwnProperty.call(process.stdin, 'isTTY');
    originalIsTTYDescriptor = Object.getOwnPropertyDescriptor(process.stdin, 'isTTY');
    // Force non-TTY so the no-password test never blocks on an
    // unanswerable prompt when the suite is run from an interactive shell.
    Object.defineProperty(process.stdin, 'isTTY', { value: false, configurable: true });
  });
  after(() => {
    if (originalDataRoot === undefined) delete process.env.DATA_ROOT;
    else process.env.DATA_ROOT = originalDataRoot;
    if (originalIsTTYWasOwn && originalIsTTYDescriptor) {
      Object.defineProperty(process.stdin, 'isTTY', originalIsTTYDescriptor);
    } else {
      // Property was inherited; remove our shadowing own-property so
      // the prototype's accessor is visible again.
      delete process.stdin.isTTY;
    }
  });

  it('seeds an IDP account when singleUserPassword is provided', async () => {
    const dir = './test-data-su-pw-provided';
    await fs.remove(dir);
    await fs.ensureDir(dir);
    const port = await getAvailablePort();
    const baseUrl = `http://${TEST_HOST}:${port}`;
    const server = createServer({
      logger: false,
      root: dir,
      idp: true,
      idpIssuer: baseUrl,
      singleUser: true,
      singleUserName: 'me',
      singleUserPassword: 'hunter2-test',
      forceCloseConnections: true,
    });
    try {
      // createServer already sets DATA_ROOT when `root` is provided;
      // import accounts.js after listen() so it picks up the right path.
      await server.listen({ port, host: TEST_HOST });
      const { findByUsername, authenticate } = await import('../src/idp/accounts.js');
      const account = await findByUsername('me');
      assert.ok(account, 'IDP account for single-user "me" should exist');
      assert.strictEqual(account.username, 'me');
      assert.ok(account.webId.includes('/me/profile/card.jsonld#me'));
      const authed = await authenticate('me', 'hunter2-test');
      assert.ok(authed, 'should authenticate with the seeded password');
    } finally {
      await server.close();
      await fs.remove(dir);
    }
  });

  it('skips seeding (no error) when no password and not on a TTY', async () => {
    // The before() hook stubs stdin.isTTY=false so the seed step warns
    // and skips rather than blocking on an unanswerable prompt.
    const dir = './test-data-su-pw-missing';
    await fs.remove(dir);
    await fs.ensureDir(dir);
    const port = await getAvailablePort();
    const baseUrl = `http://${TEST_HOST}:${port}`;
    const server = createServer({
      logger: false,
      root: dir,
      idp: true,
      idpIssuer: baseUrl,
      singleUser: true,
      singleUserName: 'me',
      // singleUserPassword intentionally omitted
      forceCloseConnections: true,
    });
    try {
      await server.listen({ port, host: TEST_HOST });
      const { findByUsername } = await import('../src/idp/accounts.js');
      const account = await findByUsername('me');
      assert.strictEqual(account, null, 'no account should be seeded without a password');
      // Pod itself must still exist — server starts up regardless.
      const profileExists = await fs.pathExists(path.join(dir, 'me/profile/card.jsonld'));
      assert.ok(profileExists, 'pod should still be created');
    } finally {
      await server.close();
      await fs.remove(dir);
    }
  });

  it('is idempotent — restarting does not duplicate or error', async () => {
    const dir = './test-data-su-pw-idempotent';
    await fs.remove(dir);
    await fs.ensureDir(dir);
    const port = await getAvailablePort();
    const baseUrl = `http://${TEST_HOST}:${port}`;
    const startOnce = async () => {
      const s = createServer({
        logger: false,
        root: dir,
        idp: true,
        idpIssuer: baseUrl,
        singleUser: true,
        singleUserName: 'me',
        singleUserPassword: 'idem-pw',
        forceCloseConnections: true,
      });
      await s.listen({ port, host: TEST_HOST });
      return s;
    };
    let s1, s2;
    try {
      s1 = await startOnce();
      await s1.close();
      s2 = await startOnce();
      const { findByUsername, authenticate } = await import('../src/idp/accounts.js');
      const account = await findByUsername('me');
      assert.ok(account, 'account from first run should still exist');
      // Original password still valid (we didn't overwrite on the second run).
      const authed = await authenticate('me', 'idem-pw');
      assert.ok(authed);
    } finally {
      if (s2) await s2.close();
      await fs.remove(dir);
    }
  });

  it('does not seed when --idp is off', async () => {
    const dir = './test-data-su-pw-no-idp';
    await fs.remove(dir);
    await fs.ensureDir(dir);
    const port = await getAvailablePort();
    const server = createServer({
      logger: false,
      root: dir,
      idp: false,
      singleUser: true,
      singleUserName: 'me',
      singleUserPassword: 'should-be-ignored',
      forceCloseConnections: true,
    });
    try {
      await server.listen({ port, host: TEST_HOST });
      // No .idp directory should exist when idp is disabled.
      const idpDirExists = await fs.pathExists(path.join(dir, '.idp'));
      assert.strictEqual(idpDirExists, false, 'no .idp directory when --idp off');
    } finally {
      await server.close();
      await fs.remove(dir);
    }
  });
});
