/**
 * Integration tests for the wired --provision-keys / `provisionKeys: true`
 * pod-creation flow (Phase 1 of #437).
 *
 * Covers:
 *   - POST /.pods with provisionKeys: true writes a Multikey doc
 *     to <pod>/private/privkey.jsonld
 *   - The seeded ACL on /private/ keeps the file private (401 unauth,
 *     200 with the owner token) — defence-in-depth alongside the
 *     0o600 file mode set by storage.write.
 *   - The HTTP response surfaces the public side (publicKeyMultibase)
 *     and the file URL, but never echoes the secret.
 *   - Default behaviour (no flag) does NOT write the file — opt-in
 *     stays opt-in.
 *   - createPodStructure called directly with provisionKeys returns
 *     the freshly-minted key material so a CLI caller can display it.
 *   - createPodStructure with provisionKeys=false returns no ownerKey.
 */

import { describe, it, before, after } from 'node:test';
import assert from 'node:assert';
import fs from 'fs-extra';
import path from 'path';
import {
  startTestServer,
  stopTestServer,
  request,
  assertStatus,
  getBaseUrl
} from './helpers.js';

// Local token stash — the createTestPod helper hardwires its own
// fetch call so we can't use it for the provisionKeys-true variant;
// just keep the token returned by our manual POST around for the
// authenticated WAC test below.
let ownerToken = null;
import { createPodStructure } from '../src/handlers/container.js';
import { decodeFFormSecp256k1 } from '../src/auth/nostr-keys.js';

describe('POST /.pods — provisionKeys: true (Phase 1 of #437)', () => {
  before(async () => {
    await startTestServer();
  });
  after(async () => {
    await stopTestServer();
  });

  it('creates the pod and writes /private/privkey.jsonld', async () => {
    const res = await fetch(`${getBaseUrl()}/.pods`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name: 'keyowner', provisionKeys: true })
    });
    assertStatus(res, 201);
    const body = await res.json();
    ownerToken = body.token;

    // Response surfaces the public side, never the secret.
    assert.ok(body.ownerKey, 'response should include ownerKey summary');
    assert.strictEqual(body.ownerKey.keyDocument, `${body.podUri}private/privkey.jsonld`);
    assert.match(body.ownerKey.publicKeyMultibase, /^fe70102[0-9a-f]{64}$/,
      'publicKeyMultibase should be the f-form secp256k1-pub Multikey');
    // No secret key on the wire under any field name.
    const flat = JSON.stringify(body);
    assert.doesNotMatch(flat, /secretKey|secret_key|nsec|privateKey/i,
      'response must not echo any secret material');

    // The file exists on disk and parses as the expected Multikey doc.
    const filePath = path.join('./data', 'keyowner', 'private', 'privkey.jsonld');
    assert.ok(await fs.pathExists(filePath), '/private/privkey.jsonld must exist');
    const doc = JSON.parse(await fs.readFile(filePath, 'utf8'));
    assert.strictEqual(doc['@context'], 'https://www.w3.org/ns/cid/v1');
    assert.strictEqual(doc.type, 'Multikey');
    assert.strictEqual(doc.controller, body.webId,
      'Phase 1 controller is the pod owner WebID (did:nostr lands in Phase 2)');
    assert.match(doc.publicKeyMultibase, /^fe70102[0-9a-f]{64}$/);
    assert.match(doc.secretKeyMultibase, /^f8126[0-9a-f]{64}$/);
    // Round-trip the public side through jss's existing decoder.
    const xonly = decodeFFormSecp256k1(doc.publicKeyMultibase);
    assert.match(xonly, /^[0-9a-f]{64}$/);
  });

  it('writes the secret with file mode 0o600 (POSIX defence-in-depth)', { skip: process.platform === 'win32' }, async () => {
    const filePath = path.join('./data', 'keyowner', 'private', 'privkey.jsonld');
    const stat = await fs.stat(filePath);
    // Strip the file-type bits (0o170000) and assert the perm bits.
    const mode = stat.mode & 0o777;
    assert.strictEqual(mode, 0o600,
      `Expected 0o600 on the secret key file, got 0o${mode.toString(8)}`);
  });

  it('blocks unauthenticated reads of the secret key (WAC)', async () => {
    const res = await request('/keyowner/private/privkey.jsonld');
    assertStatus(res, 401);
  });

  it('serves the secret to the authenticated owner (WAC)', async () => {
    assert.ok(ownerToken, 'pod owner token captured from the create response');
    const res = await fetch(`${getBaseUrl()}/keyowner/private/privkey.jsonld`, {
      headers: { Authorization: `Bearer ${ownerToken}` }
    });
    assertStatus(res, 200);
    const doc = await res.json();
    // The web user (pod owner) reads via HTTP/WAC — file mode 0o600
    // restricts unix-user-on-the-box access only, never this path.
    assert.strictEqual(doc.type, 'Multikey');
    assert.match(doc.secretKeyMultibase, /^f8126[0-9a-f]{64}$/);
  });

  it('does NOT write a key file when provisionKeys is omitted (opt-in)', async () => {
    const res = await fetch(`${getBaseUrl()}/.pods`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name: 'nokeys' })
    });
    assertStatus(res, 201);
    const body = await res.json();
    assert.strictEqual(body.ownerKey, undefined,
      'opt-in: response must not include ownerKey when flag is omitted');
    const filePath = path.join('./data', 'nokeys', 'private', 'privkey.jsonld');
    assert.strictEqual(await fs.pathExists(filePath), false,
      'opt-in: file must not be written when flag is omitted');
  });

  it('does NOT write a key file when provisionKeys is false (explicit opt-out)', async () => {
    const res = await fetch(`${getBaseUrl()}/.pods`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name: 'nokeys2', provisionKeys: false })
    });
    assertStatus(res, 201);
    const body = await res.json();
    assert.strictEqual(body.ownerKey, undefined);
    const filePath = path.join('./data', 'nokeys2', 'private', 'privkey.jsonld');
    assert.strictEqual(await fs.pathExists(filePath), false);
  });

  it('does NOT trigger on truthy non-true values (e.g. string "true")', async () => {
    // Defensive: only literal `true` activates the flag — keeps an
    // accidentally-string-coerced value from silently turning it on.
    const res = await fetch(`${getBaseUrl()}/.pods`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name: 'stringtrue', provisionKeys: 'true' })
    });
    assertStatus(res, 201);
    const body = await res.json();
    assert.strictEqual(body.ownerKey, undefined,
      'string "true" must not trigger key provisioning');
    const filePath = path.join('./data', 'stringtrue', 'private', 'privkey.jsonld');
    assert.strictEqual(await fs.pathExists(filePath), false);
  });
});

describe('createPodStructure — provisionKeys option (direct call)', () => {
  before(async () => {
    await startTestServer();
  });
  after(async () => {
    await stopTestServer();
  });

  it('returns ownerKey when provisionKeys is true', async () => {
    const podUri = 'http://127.0.0.1:0/direct1/';
    const webId = `${podUri}profile/card.jsonld#me`;
    const result = await createPodStructure(
      'direct1', webId, podUri, podUri.replace(/\/$/, '/'), 0,
      { provisionKeys: true }
    );
    assert.ok(result.ownerKey, 'createPodStructure must return ownerKey when provisionKeys is true');
    assert.match(result.ownerKey.publicHex, /^[0-9a-f]{64}$/);
    assert.match(result.ownerKey.secretHex, /^[0-9a-f]{64}$/);
    assert.strictEqual(result.ownerKey.publicMultibase, result.ownerKey.document.publicKeyMultibase);
    assert.strictEqual(result.ownerKey.document.controller, webId);
  });

  it('returns no ownerKey when the option is omitted', async () => {
    const podUri = 'http://127.0.0.1:0/direct2/';
    const webId = `${podUri}profile/card.jsonld#me`;
    const result = await createPodStructure(
      'direct2', webId, podUri, podUri.replace(/\/$/, '/'), 0
    );
    assert.strictEqual(result.ownerKey, undefined);
  });
});
