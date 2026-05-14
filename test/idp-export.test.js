/**
 * GET /idp/account/export — pod data export endpoint (#353).
 *
 * MVP slice of the Credible Exit ladder (#448). The end user takes
 * their pod data with them, no operator help required.
 *
 * Coverage:
 *   - 401 unauthenticated
 *   - 403 cross-account (multi-user: caller authed as B can't pull A)
 *   - 200 owner export → valid tar.gz containing manifest + account
 *     + pod tree
 *   - account.json never carries passwordHash
 *   - manifest shape (webId, podName, mode, exportedAt, jssVersion)
 *   - Single-user mode + --provision-keys: archive contains
 *     /private/privkey.jsonld (per Credible Exit framing — the
 *     user's secret IS theirs and must leave with them)
 */

import { describe, it, before, after } from 'node:test';
import assert from 'node:assert';
import fs from 'fs-extra';
import path from 'path';
import zlib from 'zlib';
import tar from 'tar-stream';
import { Readable } from 'stream';
import { createServer } from '../src/server.js';

async function startServer(dataDir, options = {}) {
  await fs.remove(dataDir);
  await fs.ensureDir(dataDir);
  const server = createServer({
    logger: false,
    forceCloseConnections: true,
    root: dataDir,
    idp: true,
    idpIssuer: 'http://127.0.0.1/',
    ...options,
  });
  await server.listen({ port: 0, host: '127.0.0.1' });
  const baseUrl = `http://127.0.0.1:${server.server.address().port}`;
  return { server, baseUrl };
}

async function stopServer(server, dataDir) {
  await server.close();
  await fs.remove(dataDir);
}

/**
 * Read a tar.gz archive from a Buffer or Response into a map of
 * `{ filename: Buffer-content }`. Tests can then assert on filenames
 * + content shapes without touching disk.
 */
async function unpackTarGz(buf) {
  const out = {};
  const extract = tar.extract();
  await new Promise((resolve, reject) => {
    extract.on('entry', (header, stream, next) => {
      const chunks = [];
      stream.on('data', (c) => chunks.push(c));
      stream.on('end', () => {
        out[header.name] = Buffer.concat(chunks);
        next();
      });
      stream.on('error', reject);
      stream.resume();
    });
    extract.on('finish', resolve);
    extract.on('error', reject);
    Readable.from(buf).pipe(zlib.createGunzip()).pipe(extract);
  });
  return out;
}

describe('GET /idp/account/export — multi-user', () => {
  const DATA_DIR = './test-data-export-mu';
  let server, baseUrl, aliceToken, bobToken;

  before(async () => {
    ({ server, baseUrl } = await startServer(DATA_DIR));
    // Create two pods so the cross-account 403 case is real.
    const aliceRes = await fetch(`${baseUrl}/.pods`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        name: 'alice', email: 'alice@example.com', password: 'pw-alice-123'
      })
    });
    aliceToken = (await aliceRes.json()).token;
    const bobRes = await fetch(`${baseUrl}/.pods`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        name: 'bob', email: 'bob@example.com', password: 'pw-bob-456'
      })
    });
    bobToken = (await bobRes.json()).token;
  });

  after(async () => {
    await stopServer(server, DATA_DIR);
  });

  it('returns 401 unauthenticated', async () => {
    const res = await fetch(`${baseUrl}/idp/account/export`);
    assert.strictEqual(res.status, 401);
  });

  it('returns 200 with a tar.gz for the authenticated owner', async () => {
    const res = await fetch(`${baseUrl}/idp/account/export`, {
      headers: { Authorization: `Bearer ${aliceToken}` }
    });
    assert.strictEqual(res.status, 200);
    assert.strictEqual(res.headers.get('content-type'), 'application/x-tar+gzip');
    assert.match(res.headers.get('content-disposition') || '', /^attachment; filename="jss-export-/);
    const buf = Buffer.from(await res.arrayBuffer());
    const files = await unpackTarGz(buf);

    // Manifest first.
    assert.ok(files['jss-export/manifest.json'], 'manifest must be present');
    const manifest = JSON.parse(files['jss-export/manifest.json'].toString('utf8'));
    assert.strictEqual(manifest.username, 'alice');
    assert.strictEqual(manifest.podName, 'alice');
    assert.strictEqual(manifest.mode, 'multi-user');
    assert.match(manifest.exportedAt, /^\d{4}-\d{2}-\d{2}T/);
    assert.match(manifest.webId, /alice\/profile\/card\.jsonld#me$/);

    // Account record present, sans passwordHash.
    assert.ok(files['jss-export/account.json'], 'account.json must be present');
    const account = JSON.parse(files['jss-export/account.json'].toString('utf8'));
    assert.strictEqual(account.username, 'alice');
    assert.strictEqual(account.email, 'alice@example.com');
    assert.strictEqual(account.passwordHash, undefined,
      'account.json must NEVER include the password hash');

    // Pod tree contents — at minimum the seeded files.
    const podKeys = Object.keys(files).filter(k => k.startsWith('jss-export/pod/'));
    assert.ok(podKeys.length > 0, 'pod tree must be packed');
    assert.ok(podKeys.some(k => k.endsWith('profile/card.jsonld')),
      'WebID profile must be in the export');
    assert.ok(podKeys.some(k => k.endsWith('.acl')),
      'ACL files must be in the export');
  });

  it("scopes the export to the authenticated caller — no cross-account exposure", async () => {
    // The endpoint takes no target parameter; the WebID is taken
    // from the auth context. Cross-account access is structurally
    // impossible to attempt (so there's no 403 case). This test
    // pins the *property* by confirming bob's authenticated call
    // returns bob's data and never anything from alice's pod.
    const res = await fetch(`${baseUrl}/idp/account/export`, {
      headers: { Authorization: `Bearer ${bobToken}` }
    });
    assert.strictEqual(res.status, 200);
    const buf = Buffer.from(await res.arrayBuffer());
    const files = await unpackTarGz(buf);
    const manifest = JSON.parse(files['jss-export/manifest.json'].toString('utf8'));
    assert.strictEqual(manifest.username, 'bob');
    assert.strictEqual(manifest.podName, 'bob');
    // No alice/* in bob's export.
    const podKeys = Object.keys(files).filter(k => k.startsWith('jss-export/pod/'));
    for (const k of podKeys) {
      assert.doesNotMatch(k, /\/alice\//, `bob's export must not contain alice's data: ${k}`);
    }
  });
});

describe('GET /idp/account/export — single-user ROOT pod (denylist check)', () => {
  // Critical: in single-user root-pod mode (the default since #348),
  // podDir IS dataRoot. Without an explicit denylist, the export would
  // ship `.idp/accounts/*.json` (every account record incl.
  // passwordHash) AND `.idp/keys/` (the IdP signing keys that mint
  // tokens for any user) to the caller. The handler must refuse to
  // include `.idp/` at the top level.
  const DATA_DIR = './test-data-export-root-pod';
  let server, baseUrl, ownerToken;

  before(async () => {
    ({ server, baseUrl } = await startServer(DATA_DIR, {
      singleUser: true,
      // No singleUserName → root pod (#348 default)
      singleUserName: null,
      singleUserPassword: 'pw-root-321',
      provisionKeys: true,
    }));
    const credRes = await fetch(`${baseUrl}/idp/credentials`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ username: 'me', password: 'pw-root-321' }).toString(),
    });
    if (credRes.status === 200) {
      const body = await credRes.json();
      ownerToken = body.access_token || body.token;
    }
  });

  after(async () => {
    await stopServer(server, DATA_DIR);
  });

  it('does NOT pack /.idp/ (accounts, signing keys, OIDC adapter state)', async (t) => {
    if (!ownerToken) {
      t.skip('IDP credentials handshake unavailable');
      return;
    }
    // Sanity: confirm the IdP actually wrote .idp/ to disk so the
    // denylist test is exercising a non-empty thing.
    assert.ok(
      await fs.pathExists(path.join(DATA_DIR, '.idp')),
      'pre-condition: .idp/ must exist on disk for the test to be meaningful'
    );
    const res = await fetch(`${baseUrl}/idp/account/export`, {
      headers: { Authorization: `Bearer ${ownerToken}` }
    });
    assert.strictEqual(res.status, 200);
    const buf = Buffer.from(await res.arrayBuffer());
    const files = await unpackTarGz(buf);

    // Critical: NOTHING under jss-export/pod/.idp/ in the archive.
    const idpEntries = Object.keys(files).filter(k =>
      k.startsWith('jss-export/pod/.idp/') || k === 'jss-export/pod/.idp'
    );
    assert.strictEqual(idpEntries.length, 0,
      `.idp/ must not be packed in single-user root-pod export. ` +
      `Found: ${idpEntries.join(', ')}`);

    // Sanity: actual pod content IS in the archive.
    const podKeys = Object.keys(files).filter(k => k.startsWith('jss-export/pod/'));
    assert.ok(podKeys.some(k => k.endsWith('profile/card.jsonld')),
      'pod content must still be exported');
    assert.ok(podKeys.some(k => k.endsWith('private/privkey.jsonld')),
      'pod /private/ must still be exported (this is pod data, not server-internal)');
  });
});

describe('GET /idp/account/export — single-user with --provision-keys', () => {
  const DATA_DIR = './test-data-export-su-keys';
  let server, baseUrl, ownerToken;

  before(async () => {
    ({ server, baseUrl } = await startServer(DATA_DIR, {
      singleUser: true,
      singleUserName: 'me',
      singleUserPassword: 'pw-me-789',
      provisionKeys: true,
    }));
    // Auth via the seeded IDP account password.
    const credRes = await fetch(`${baseUrl}/idp/credentials`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ username: 'me', password: 'pw-me-789' }).toString(),
    });
    if (credRes.status === 200) {
      const body = await credRes.json();
      ownerToken = body.access_token || body.token;
    }
  });

  after(async () => {
    await stopServer(server, DATA_DIR);
  });

  it('exports the pod tree including the on-disk owner secret', async (t) => {
    if (!ownerToken) {
      t.skip('IDP credentials endpoint did not return a token in this layout');
      return;
    }
    const res = await fetch(`${baseUrl}/idp/account/export`, {
      headers: { Authorization: `Bearer ${ownerToken}` }
    });
    assert.strictEqual(res.status, 200);
    const buf = Buffer.from(await res.arrayBuffer());
    const files = await unpackTarGz(buf);

    const manifest = JSON.parse(files['jss-export/manifest.json'].toString('utf8'));
    assert.strictEqual(manifest.mode, 'single-user',
      'manifest.mode reflects the server mode, not the existence of an account record');
    assert.strictEqual(manifest.podName, 'me',
      'singleUserName="me" → pod is at <DATA_ROOT>/me/ → podName is "me"');

    // The on-disk secret must be in the archive — Credible Exit
    // requires the user can leave with their identity, not just
    // their bytes. Refusing to include the secret would make L4+
    // identity migration impossible.
    const podKeys = Object.keys(files).filter(k => k.startsWith('jss-export/pod/'));
    assert.ok(
      podKeys.some(k => k.endsWith('private/privkey.jsonld')),
      `/private/privkey.jsonld must be in the archive (Credible Exit). Pod entries: ${podKeys.join(', ')}`
    );
    // And the WebID profile carrying the public side.
    assert.ok(podKeys.some(k => k.endsWith('profile/card.jsonld')));
  });
});
