/**
 * Issuer normalization (#524).
 *
 * RFC 9207 requires the `iss` authorization-response parameter to be
 * byte-identical to the issuer identifier the client learned from
 * discovery. JSS's discovery handler normalizes the `issuer` field to
 * the trailing-slash form ("CTH compatibility"), but the oidc-provider
 * instance — which emits the RFC 9207 `iss` param and the `iss` claim
 * in tokens — was constructed with the RAW configured issuer. With an
 * issuer configured slash-free, strict clients (e.g. solid-oidc's
 * handleRedirectFromLogin) saw:
 *
 *   discovery issuer  → http://host:port/
 *   callback iss      → http://host:port
 *
 * and rejected the callback before the token request ever fired —
 * sign-in silently bounced (reproduced on Android/nodejs-mobile, #522).
 *
 * The fix normalizes inside createProvider with the SAME expression
 * the discovery handler uses. These tests pin both halves and their
 * equality so the two normalizations can't drift apart silently.
 */

import { describe, it, before, after } from 'node:test';
import assert from 'node:assert';
import { createServer } from '../src/server.js';
import { createProvider } from '../src/idp/provider.js';
import { createServer as createNetServer } from 'net';
import fs from 'fs-extra';

const TEST_HOST = 'localhost';
const DATA_DIR = './test-data-idp-issuer-norm';

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

describe('IdP issuer normalization (#524)', () => {
  let server;
  let baseUrl; // deliberately WITHOUT a trailing slash — the bug's trigger
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
      idpIssuer: baseUrl, // no trailing slash
      forceCloseConnections: true,
    });
    await server.listen({ port, host: TEST_HOST });
  });

  after(async () => {
    if (server) await server.close();
    if (originalDataRoot === undefined) delete process.env.DATA_ROOT;
    else process.env.DATA_ROOT = originalDataRoot;
    await fs.remove(DATA_DIR);
  });

  it('createProvider normalizes a slash-free issuer to the trailing-slash form', async () => {
    const provider = await createProvider(baseUrl);
    assert.strictEqual(provider.issuer, baseUrl + '/',
      'provider issuer must gain the trailing slash so the RFC 9207 iss param matches discovery');
  });

  it('createProvider leaves an already-slashed issuer unchanged', async () => {
    const provider = await createProvider(baseUrl + '/');
    assert.strictEqual(provider.issuer, baseUrl + '/',
      'an already-canonical issuer must pass through untouched');
  });

  it('provider issuer is byte-identical to the discovery `issuer` field (RFC 9207 contract)', async () => {
    // The cross-component pin: both sides normalize the same raw input
    // to the same string. If either normalization drifts, strict
    // clients break — this is the exact comparison solid-oidc's
    // handleRedirectFromLogin performs.
    const res = await fetch(`${baseUrl}/.well-known/openid-configuration`);
    assert.strictEqual(res.status, 200);
    const discovery = await res.json();

    const provider = await createProvider(baseUrl);
    assert.strictEqual(provider.issuer, discovery.issuer,
      `RFC 9207: provider iss (${provider.issuer}) must equal discovery issuer (${discovery.issuer})`);
  });
});
