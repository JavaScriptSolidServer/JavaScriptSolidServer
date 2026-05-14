/**
 * NIP-05 MVP — /.well-known/nostr.json on single-user pods (#446).
 *
 * Implementation is a static file written during pod creation, not
 * a server-side handler. JSS already exposes /.well-known/* as a
 * public namespace (WAC bypass + dotfile allow-list); the LDP GET
 * handler serves the file like any other resource.
 *
 * Acceptance:
 *   - single-user + --provision-keys → 200 { names: { _: <hex> } }
 *     served at /.well-known/nostr.json, publicly readable, with
 *     CORS open for browser-based NIP-05 verifiers.
 *   - single-user without --provision-keys → no file written.
 *   - multi-user → no file written (next slice of #445 aggregates).
 */

import { describe, it, before, after } from 'node:test';
import assert from 'node:assert';
import fs from 'fs-extra';
import { createServer } from '../src/server.js';

const DATA_DIR = './test-data-nip05';

async function startServer(options = {}) {
  await fs.remove(DATA_DIR);
  await fs.ensureDir(DATA_DIR);
  const server = createServer({
    logger: false,
    forceCloseConnections: true,
    root: DATA_DIR,
    ...options
  });
  await server.listen({ port: 0, host: '127.0.0.1' });
  const baseUrl = `http://127.0.0.1:${server.server.address().port}`;
  return { server, baseUrl };
}

async function stopServer(server) {
  await server.close();
  await fs.remove(DATA_DIR);
}

describe('NIP-05 MVP — single-user with provisioned key', () => {
  let server, baseUrl;
  let savedDataRoot;

  before(async () => {
    savedDataRoot = process.env.DATA_ROOT;
    ({ server, baseUrl } = await startServer({
      singleUser: true,
      provisionKeys: true
    }));
  });

  after(async () => {
    await stopServer(server);
    if (savedDataRoot === undefined) delete process.env.DATA_ROOT;
    else process.env.DATA_ROOT = savedDataRoot;
  });

  it('writes the NIP-05 mapping with the reserved `_` name', async () => {
    const onDisk = JSON.parse(
      await fs.readFile(`${DATA_DIR}/.well-known/nostr.json`, 'utf8')
    );
    assert.deepStrictEqual(Object.keys(onDisk.names), ['_'],
      'MVP emits exactly one mapping (the `_` reserved name)');
    assert.match(onDisk.names._, /^[0-9a-f]{64}$/,
      'the `_` mapping must be a 32-byte hex pubkey');
  });

  it('serves the mapping over HTTP without auth (NIP-05 verifiers are unauth)', async () => {
    const res = await fetch(`${baseUrl}/.well-known/nostr.json`);
    assert.strictEqual(res.status, 200);
    const body = await res.json();
    assert.match(body.names._, /^[0-9a-f]{64}$/);
  });

  it('matches the same pubkey landed in the WebID profile VM', async () => {
    // Cross-check: the NIP-05 pubkey and the profile's
    // verificationMethod publicKeyMultibase should describe the
    // same key. If they ever diverge, an LWS-CID verifier would
    // accept the profile's VM but a NIP-05 verifier would attest
    // to a different identity for the same domain.
    const onDisk = JSON.parse(
      await fs.readFile(`${DATA_DIR}/.well-known/nostr.json`, 'utf8')
    );
    const profile = JSON.parse(
      await fs.readFile(`${DATA_DIR}/profile/card.jsonld`, 'utf8')
    );
    const vm = profile.verificationMethod[0];
    assert.ok(vm.publicKeyMultibase.includes(onDisk.names._),
      'NIP-05 pubkey hex must appear in the profile VM publicKeyMultibase');
  });
});

describe('NIP-05 MVP — single-user without a provisioned key', () => {
  let server;
  let savedDataRoot;

  before(async () => {
    savedDataRoot = process.env.DATA_ROOT;
    ({ server } = await startServer({ singleUser: true }));
  });

  after(async () => {
    await stopServer(server);
    if (savedDataRoot === undefined) delete process.env.DATA_ROOT;
    else process.env.DATA_ROOT = savedDataRoot;
  });

  it('does not create the file (nothing to publish)', async () => {
    assert.strictEqual(
      await fs.pathExists(`${DATA_DIR}/.well-known/nostr.json`),
      false,
      'no key → no NIP-05 mapping → no file'
    );
  });
});

describe('NIP-05 MVP — multi-user mode', () => {
  let server, baseUrl;
  let savedDataRoot;

  before(async () => {
    savedDataRoot = process.env.DATA_ROOT;
    // No singleUser → multi-user. The MVP only writes the NIP-05
    // file in single-user mode; aggregation across multi-user pods
    // is the next slice of #445.
    ({ server, baseUrl } = await startServer({}));
  });

  after(async () => {
    await stopServer(server);
    if (savedDataRoot === undefined) delete process.env.DATA_ROOT;
    else process.env.DATA_ROOT = savedDataRoot;
  });

  it('still does not write a server-level NIP-05 file when a pod is provisioned with keys', async () => {
    // Actually exercise the code path that *could* have written the
    // file — provision a multi-user pod with provisionKeys: true via
    // POST /.pods. The pod's own /<name>/private/privkey.jsonld
    // lands as expected, but the server-level /.well-known/nostr.json
    // must remain absent because this is multi-user mode.
    const res = await fetch(`${baseUrl}/.pods`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name: 'alice', provisionKeys: true })
    });
    assert.strictEqual(res.status, 201, 'pod creation must succeed');
    const body = await res.json();
    assert.ok(body.ownerKey, 'pod-level owner key must still be provisioned');

    // The pod's own privkey IS on disk — sanity check the multi-user
    // provisioning path still ran.
    assert.strictEqual(
      await fs.pathExists(`${DATA_DIR}/alice/private/privkey.jsonld`),
      true,
      'multi-user pod provisioning still writes the pod-internal privkey'
    );

    // …but no server-level NIP-05 file.
    assert.strictEqual(
      await fs.pathExists(`${DATA_DIR}/.well-known/nostr.json`),
      false,
      'multi-user mode must not write a server-level NIP-05 mapping'
    );
  });
});
