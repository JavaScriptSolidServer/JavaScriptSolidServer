/**
 * getAgent — public request → WebID accessor (#584).
 *
 * Apps that own their own auth (appPaths mounts, #582) need to ask "who is
 * this?" without reaching into src/auth internals. auth.js at the package
 * root is the stable contract; these tests pin its shape so auth refactors
 * keep the seam:
 *
 *   - anonymous / malformed credentials  -> null, never a throw
 *   - a real IdP-issued Bearer token     -> the account's WebID
 *
 * The individual token schemes (Bearer, DPoP, NIP-98, LWS10-CID) are
 * exercised by their own suites; this one pins the public wrapper.
 */

import { describe, it, before, after, afterEach } from 'node:test';
import assert from 'node:assert';
import { createServer } from '../src/server.js';
import { getAgent } from '../auth.js';
import fs from 'fs-extra';

const TEST_DATA_DIR = './test-data-auth-agent';

let server;
let baseUrl;
let originalDataRoot;

describe('public getAgent accessor (#584)', () => {
  before(() => {
    originalDataRoot = process.env.DATA_ROOT;
  });

  afterEach(async () => {
    if (server) {
      await server.close();
      server = null;
    }
    await fs.remove(TEST_DATA_DIR);
  });

  after(() => {
    if (originalDataRoot === undefined) delete process.env.DATA_ROOT;
    else process.env.DATA_ROOT = originalDataRoot;
  });

  it('returns null for anonymous requests', async () => {
    assert.strictEqual(await getAgent({ headers: {} }), null);
  });

  it('returns null (not a throw) for malformed credentials', async () => {
    assert.strictEqual(await getAgent({ headers: { authorization: 'Bearer garbage' } }), null);
    assert.strictEqual(await getAgent({ headers: { authorization: 'Nonsense scheme' } }), null);
    assert.strictEqual(await getAgent({ headers: { authorization: '' } }), null);
  });

  it('resolves a real IdP Bearer token to the account WebID', async () => {
    await fs.emptyDir(TEST_DATA_DIR);
    server = createServer({
      logger: false,
      forceCloseConnections: true,
      root: TEST_DATA_DIR,
      idp: true,
      idpIssuer: 'http://127.0.0.1:0', // patched after listen below
    });
    await server.listen({ port: 0, host: '127.0.0.1' });
    baseUrl = `http://127.0.0.1:${server.server.address().port}`;

    let res = await fetch(`${baseUrl}/idp/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: 'agent', password: 'secret-word', confirmPassword: 'secret-word' }),
    });
    assert.ok(res.status < 400, `register failed: ${res.status}`);

    res = await fetch(`${baseUrl}/idp/credentials`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: 'agent', password: 'secret-word' }),
    });
    const cred = await res.json();
    assert.ok(cred.access_token, 'no token issued');

    const webId = await getAgent({ headers: { authorization: `Bearer ${cred.access_token}` } });
    assert.strictEqual(webId, cred.webid);
  });
});
