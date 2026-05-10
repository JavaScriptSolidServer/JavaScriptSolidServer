/**
 * Integration tests for the well-known did:nostr HTTP-resolution
 * endpoint (#407): JSS publishes DID docs at
 * `/.well-known/did/nostr/<pubkey>.json` for any local account whose
 * profile carries that pubkey as a CID verificationMethod, so JSS's
 * own resolver (and external clients like nostr.social, nostr.rocks)
 * can resolve same-pod identities without a third-party round-trip.
 */

import { describe, it, before, after, beforeEach } from 'node:test';
import assert from 'node:assert';
import path from 'path';
import fs from 'fs-extra';
import { createServer as createNetServer } from 'net';
import { generateSecretKey, getPublicKey } from '../src/nostr/event.js';
import { createServer } from '../src/server.js';
import { _resetIndexForTests } from '../src/idp/well-known-did-nostr.js';
import { extractNostrPubkeysFromProfile } from '../src/auth/nostr.js';

const TEST_HOST = '127.0.0.1';
const TEST_DATA_DIR = './data';

/** Pick an OS-assigned port up front so idpIssuer can include it. */
async function getAvailablePort() {
  return new Promise((resolve, reject) => {
    const srv = createNetServer();
    srv.on('error', reject);
    srv.listen(0, TEST_HOST, () => {
      const port = srv.address().port;
      srv.close(() => resolve(port));
    });
  });
}

function fformMultikey(xOnlyHex, parity = '02') {
  return 'f' + 'e701' + parity + xOnlyHex.toLowerCase();
}

async function patchProfileWithMultikey(podName, pubkey) {
  const profilePath = path.join(TEST_DATA_DIR, podName, 'profile', 'card.jsonld');
  const profile = await fs.readJson(profilePath);
  const VM_ID = `${profile['@id'].replace('#me', '')}#nostr-key-1`;
  profile.verificationMethod = [{
    id: VM_ID,
    type: 'Multikey',
    controller: profile['@id'],
    publicKeyMultibase: fformMultikey(pubkey),
  }];
  profile.authentication = [VM_ID];
  await fs.writeJson(profilePath, profile, { spaces: 2 });
}

describe('GET /.well-known/did/nostr/:pubkey (#407)', () => {
  let server;
  let baseUrl;
  let alicePk;

  before(async () => {
    // IdP must be enabled — pod creation only writes an account
    // record (the index this endpoint reads from) when the IdP is
    // running. Pods without IdP are out of scope for this MVP.
    //
    // Match the pattern in test/idp.test.js: pick an available port
    // BEFORE listen so we can pass the real baseUrl as idpIssuer.
    // (oidc-provider behavior depends on the issuer being accurate;
    // a static `http://127.0.0.1` with no port would mismatch.)
    await fs.remove(TEST_DATA_DIR);
    await fs.ensureDir(TEST_DATA_DIR);
    const port = await getAvailablePort();
    baseUrl = `http://${TEST_HOST}:${port}`;
    server = createServer({
      logger: false,
      root: TEST_DATA_DIR,
      idp: true,
      idpIssuer: baseUrl,
      forceCloseConnections: true,
    });
    await server.listen({ port, host: TEST_HOST });
    process.env.DATA_ROOT = path.resolve(TEST_DATA_DIR);
    // IdP-enabled pod creation requires email + password (so the
    // account record is written to _webid_index.json).
    const r = await fetch(`${baseUrl}/.pods`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        name: 'alice',
        email: 'alice@example.com',
        password: 'wellknown-test-password',
      }),
    });
    if (!r.ok) throw new Error(`pod create failed: ${r.status} ${await r.text()}`);
    const sk = generateSecretKey();
    alicePk = getPublicKey(sk);
    await patchProfileWithMultikey('alice', alicePk);
  });

  after(async () => {
    await server.close();
    await fs.remove(TEST_DATA_DIR);
  });

  beforeEach(() => {
    _resetIndexForTests();
  });

  it('returns a CID-shaped DID doc for a local account with the matching VM', async () => {
    const r = await fetch(`${baseUrl}/.well-known/did/nostr/${alicePk}.json`);
    assert.strictEqual(r.status, 200);
    assert.match(r.headers.get('content-type') || '', /did\+json/);
    assert.ok(r.headers.get('cache-control'));
    assert.ok(r.headers.get('nostr-timestamp'));
    assert.ok(r.headers.get('last-modified'));

    const doc = await r.json();
    assert.deepStrictEqual(doc['@context'], ['https://w3id.org/did', 'https://w3id.org/nostr/context']);
    assert.strictEqual(doc.id, `did:nostr:${alicePk}`);
    assert.strictEqual(doc.type, 'DIDNostr');
    assert.ok(Array.isArray(doc.alsoKnownAs));
    assert.match(doc.alsoKnownAs[0], /\/alice\/profile\/card\.jsonld#me$/);
    assert.strictEqual(doc.verificationMethod[0].type, 'Multikey');
    assert.strictEqual(doc.verificationMethod[0].publicKeyMultibase, fformMultikey(alicePk));
    assert.strictEqual(doc.authentication[0], `did:nostr:${alicePk}#key1`);
  });

  it('accepts the .jsonld suffix (alias)', async () => {
    const r = await fetch(`${baseUrl}/.well-known/did/nostr/${alicePk}.jsonld`);
    assert.strictEqual(r.status, 200);
    assert.match(r.headers.get('content-type') || '', /did\+ld\+json/);
    const doc = await r.json();
    assert.strictEqual(doc.id, `did:nostr:${alicePk}`);
  });

  it('accepts the bare pubkey (no extension)', async () => {
    const r = await fetch(`${baseUrl}/.well-known/did/nostr/${alicePk}`);
    assert.strictEqual(r.status, 200);
    const doc = await r.json();
    assert.strictEqual(doc.id, `did:nostr:${alicePk}`);
  });

  it('returns 404 for a pubkey no local account claims', async () => {
    const otherPk = getPublicKey(generateSecretKey());
    const r = await fetch(`${baseUrl}/.well-known/did/nostr/${otherPk}.json`);
    assert.strictEqual(r.status, 404);
  });

  it('returns 400 for a non-hex pubkey', async () => {
    const r = await fetch(`${baseUrl}/.well-known/did/nostr/not-a-real-pubkey.json`);
    assert.strictEqual(r.status, 400);
  });

  it('returns 400 for a wrong-length hex pubkey', async () => {
    const r = await fetch(`${baseUrl}/.well-known/did/nostr/abcdef.json`);
    assert.strictEqual(r.status, 400);
  });

  it('responds to HEAD with the same headers as GET (no body)', async () => {
    const r = await fetch(`${baseUrl}/.well-known/did/nostr/${alicePk}.json`, { method: 'HEAD' });
    assert.strictEqual(r.status, 200);
    assert.match(r.headers.get('content-type') || '', /did\+json/);
    assert.ok(r.headers.get('cache-control'));
    assert.ok(r.headers.get('last-modified'));
    // HEAD bodies must be empty.
    const text = await r.text();
    assert.strictEqual(text, '');
  });

  it('rejects writes (PUT/POST/PATCH/DELETE) with 405 Method Not Allowed', async () => {
    // Without these explicit handlers, the wildcard write routes
    // would accept unauthenticated writes under /.well-known/* (the
    // namespace bypasses the WAC preHandler).
    for (const method of ['PUT', 'POST', 'PATCH', 'DELETE']) {
      const r = await fetch(`${baseUrl}/.well-known/did/nostr/${alicePk}.json`, {
        method,
        headers: { 'Content-Type': 'application/json' },
        body: method === 'DELETE' ? undefined : '{}',
      });
      assert.strictEqual(r.status, 405, `${method} should be 405`);
      assert.match(r.headers.get('allow') || '', /GET/);
    }
  });

  it('does NOT publish a VM that is in verificationMethod but not in authentication', async () => {
    // Add a key to the profile under verificationMethod but explicitly
    // omit it from `authentication` — the user has decided this key
    // is NOT for auth (revocation pending, assertion-only, etc.).
    // Index must respect that intent.
    const otherSk = generateSecretKey();
    const otherPk = getPublicKey(otherSk);
    const profilePath = path.join(TEST_DATA_DIR, 'alice', 'profile', 'card.jsonld');
    const profile = await fs.readJson(profilePath);
    const REVOKED_VM_ID = `${profile['@id'].replace('#me', '')}#nostr-revoked`;
    profile.verificationMethod.push({
      id: REVOKED_VM_ID,
      type: 'Multikey',
      controller: profile['@id'],
      publicKeyMultibase: fformMultikey(otherPk),
    });
    // NOTE: NOT added to profile.authentication
    await fs.writeJson(profilePath, profile, { spaces: 2 });

    const r = await fetch(`${baseUrl}/.well-known/did/nostr/${otherPk}.json`);
    assert.strictEqual(r.status, 404);
  });
});

describe('extractNostrPubkeysFromProfile', () => {
  it('finds f-form Multikey entries', () => {
    const sk = generateSecretKey();
    const pk = getPublicKey(sk);
    const profile = {
      verificationMethod: [{
        id: '#k1',
        type: 'Multikey',
        publicKeyMultibase: fformMultikey(pk),
      }],
    };
    const found = extractNostrPubkeysFromProfile(profile);
    assert.strictEqual(found.length, 1);
    assert.strictEqual(found[0].pubkey, pk);
  });

  it('finds JsonWebKey entries with secp256k1 x-coord', () => {
    const sk = generateSecretKey();
    const pk = getPublicKey(sk);
    // x-coord is the hex pubkey base64url-encoded.
    const x = Buffer.from(pk, 'hex').toString('base64')
      .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    const profile = {
      verificationMethod: [{
        id: '#k1',
        type: 'JsonWebKey',
        publicKeyJwk: { kty: 'EC', crv: 'secp256k1', x, y: 'irrelevant' },
      }],
    };
    const found = extractNostrPubkeysFromProfile(profile);
    assert.strictEqual(found.length, 1);
    assert.strictEqual(found[0].pubkey, pk);
  });

  it('returns empty for profiles without Nostr-shaped VMs', () => {
    assert.deepStrictEqual(extractNostrPubkeysFromProfile({}), []);
    assert.deepStrictEqual(extractNostrPubkeysFromProfile({ verificationMethod: [] }), []);
    assert.deepStrictEqual(extractNostrPubkeysFromProfile({
      verificationMethod: [{ type: 'Ed25519VerificationKey2020' }],
    }), []);
  });

  it('returns empty for malformed input', () => {
    assert.deepStrictEqual(extractNostrPubkeysFromProfile(null), []);
    assert.deepStrictEqual(extractNostrPubkeysFromProfile('not an object'), []);
  });
});
