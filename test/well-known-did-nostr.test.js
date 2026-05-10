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
import { _resetIndexForTests, profilePathFromWebId } from '../src/idp/well-known-did-nostr.js';
import { extractNostrPubkeysFromProfile } from '../src/auth/nostr.js';

const TEST_HOST = '127.0.0.1';
// Dedicated per-suite directory so we don't clobber a developer's
// local `./data` (which is also JSS's default data root) and don't
// race with other suites that use `./data` via the shared helper.
const TEST_DATA_DIR = './test-data-well-known-did-nostr';

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
  // Capture the original DATA_ROOT before the suite mutates it, so
  // the after() hook can restore it. Other tests in the repo follow
  // this save/restore pattern (e.g. idp-change-password.test.js) to
  // avoid cross-test environment leakage.
  const originalDataRoot = process.env.DATA_ROOT;

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
    if (originalDataRoot === undefined) {
      delete process.env.DATA_ROOT;
    } else {
      process.env.DATA_ROOT = originalDataRoot;
    }
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
    // Per-status header policy: 404 still sets Nostr-Timestamp (so
    // clients can correlate the resolver clock with the negative
    // answer) and a short cache so newly added keys surface fast.
    assert.ok(r.headers.get('nostr-timestamp'));
    assert.match(r.headers.get('cache-control') || '', /max-age=60/);
  });

  it('returns 400 for a non-hex pubkey', async () => {
    const r = await fetch(`${baseUrl}/.well-known/did/nostr/not-a-real-pubkey.json`);
    assert.strictEqual(r.status, 400);
    // 400 sets Nostr-Timestamp but never caches (request was malformed).
    assert.ok(r.headers.get('nostr-timestamp'));
    assert.match(r.headers.get('cache-control') || '', /no-store/);
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

  it('OPTIONS advertises only safe methods (Allow consistent with 405)', async () => {
    // The wildcard `OPTIONS /*` advertises GET/HEAD/PUT/DELETE/PATCH/POST,
    // which is wrong for the read-only well-known namespace and
    // confusing to CORS preflights. Explicit OPTIONS handlers must
    // return the same Allow set as the 405 responses.
    for (const subpath of ['', '/', '/x', '/a/b']) {
      const r = await fetch(`${baseUrl}/.well-known/did/nostr${subpath}`, { method: 'OPTIONS' });
      assert.strictEqual(r.status, 204, `OPTIONS ${subpath} should be 204`);
      const allow = (r.headers.get('allow') || '').toUpperCase();
      assert.match(allow, /GET/, `Allow should include GET (got "${allow}")`);
      assert.match(allow, /HEAD/);
      assert.doesNotMatch(allow, /\bPUT\b/, `Allow should not advertise PUT (got "${allow}")`);
      assert.doesNotMatch(allow, /\bPOST\b/);
      assert.doesNotMatch(allow, /\bDELETE\b/);
      assert.doesNotMatch(allow, /\bPATCH\b/);
    }
  });

  it('blocks writes to multi-segment paths under the namespace', async () => {
    // The single-segment `:pubkeyAndExt` route only matches one
    // path component — `PUT /.well-known/did/nostr/a/b` would
    // otherwise fall through to the wildcard `PUT /*` and accept
    // an unauthenticated write since `/.well-known/*` bypasses
    // WAC. The wildcard 405 handler closes that.
    for (const subpath of ['', '/', '/a/b', '/foo/bar/baz.json']) {
      const url = `${baseUrl}/.well-known/did/nostr${subpath}`;
      for (const method of ['PUT', 'POST', 'PATCH', 'DELETE']) {
        const r = await fetch(url, {
          method,
          headers: { 'Content-Type': 'application/json' },
          body: method === 'DELETE' ? undefined : '{}',
        });
        assert.strictEqual(r.status, 405,
          `${method} ${url} should be 405 (got ${r.status})`);
      }
    }
  });

  it('indexes root-level pods (profile at /profile/card.jsonld, no podName prefix)', async () => {
    // Single-user / root-pod layout: the profile lives directly at
    // <DATA_ROOT>/profile/card.jsonld with no podName subdirectory,
    // even though the seeded IDP account record can have
    // `podName: 'me'`. The indexer must derive the on-disk path
    // from the WebID's pathname, NOT from podName, or this whole
    // class of pods is invisible to local DID resolution.
    const sk = generateSecretKey();
    const rootPk = getPublicKey(sk);
    const rootWebId = `${baseUrl}/profile/card.jsonld#me`;
    const rootProfilePath = path.join(TEST_DATA_DIR, 'profile', 'card.jsonld');
    const VM_ID = `${baseUrl}/profile/card.jsonld#nostr-root`;
    await fs.ensureDir(path.dirname(rootProfilePath));
    await fs.writeJson(rootProfilePath, {
      '@context': 'https://www.w3.org/ns/solid/v1',
      '@id': rootWebId,
      verificationMethod: [{
        id: VM_ID,
        type: 'Multikey',
        controller: rootWebId,
        publicKeyMultibase: fformMultikey(rootPk),
      }],
      authentication: [VM_ID],
    }, { spaces: 2 });

    // Synthesize a matching account record + index entry. We bypass
    // the IdP /pods POST flow because that creates a named pod with
    // its own subdirectory; we want the root-pod shape specifically.
    const accountsDir = path.join(TEST_DATA_DIR, '.idp', 'accounts');
    const indexPath = path.join(accountsDir, '_webid_index.json');
    const idx = await fs.readJson(indexPath);
    const accountId = 'root-pod-test-account';
    idx[rootWebId] = accountId;
    await fs.writeJson(indexPath, idx, { spaces: 2 });
    await fs.writeJson(path.join(accountsDir, `${accountId}.json`), {
      id: accountId,
      podName: 'me',           // intentionally != on-disk layout
      webId: rootWebId,
      email: 'root@example.com',
      // Other fields the account loader expects can be undefined for
      // the lookup we're doing — findById just returns the JSON.
    }, { spaces: 2 });

    const r = await fetch(`${baseUrl}/.well-known/did/nostr/${rootPk}.json`);
    assert.strictEqual(r.status, 200);
    const doc = await r.json();
    assert.strictEqual(doc.id, `did:nostr:${rootPk}`);
    assert.strictEqual(doc.alsoKnownAs[0], rootWebId);
  });

  // No `it()` here — path containment is now exercised directly
  // by unit tests on `profilePathFromWebId` below. The previous
  // integration-style test couldn't actually trigger the
  // containment branch because WHATWG URL parsing strips `..`
  // segments before path-resolution sees them, so the test
  // returned 404 for the wrong reason (URL normalization, not
  // containment).


  it('handles profiles whose authentication entries are relative fragments', async () => {
    // Profiles in the wild often use relative `#me`-style fragments
    // for the subject. The indexer must absolutize `authentication`
    // entries against the validated absolute subject, not re-derive
    // the base from `profile['@id']` (which would itself be relative
    // and produce unusable IDs).
    //
    // We simulate this by writing the profile with the `@id` set to
    // a relative fragment and the authentication entry as a relative
    // fragment too. If the absolute base is honored, `#nostr-rel`
    // resolves to the same VM ID as the absolutized version inside
    // `verificationMethod`, the auth-membership check passes, and
    // the DID doc is published.
    const sk = generateSecretKey();
    const pk = getPublicKey(sk);
    const profilePath = path.join(TEST_DATA_DIR, 'alice', 'profile', 'card.jsonld');
    const profile = await fs.readJson(profilePath);
    const absSubject = profile['@id'];           // e.g. http://.../alice/profile/card.jsonld#me
    const absSubjectNoHash = absSubject.replace('#me', '');
    profile['@id'] = '#me';                       // relative subject
    profile.verificationMethod = [{
      id: `${absSubjectNoHash}#nostr-rel`,        // VM stays absolute
      type: 'Multikey',
      controller: absSubject,
      publicKeyMultibase: fformMultikey(pk),
    }];
    profile.authentication = ['#nostr-rel'];      // relative auth ref
    await fs.writeJson(profilePath, profile, { spaces: 2 });

    const r = await fetch(`${baseUrl}/.well-known/did/nostr/${pk}.json`);
    assert.strictEqual(r.status, 200);
    const doc = await r.json();
    assert.strictEqual(doc.id, `did:nostr:${pk}`);

    // Restore the profile so the rest of the suite (and any later
    // re-runs without isolation) sees a well-formed absolute subject.
    profile['@id'] = absSubject;
    profile.verificationMethod = [{
      id: `${absSubjectNoHash}#nostr-key-1`,
      type: 'Multikey',
      controller: absSubject,
      publicKeyMultibase: fformMultikey(alicePk),
    }];
    profile.authentication = [`${absSubjectNoHash}#nostr-key-1`];
    await fs.writeJson(profilePath, profile, { spaces: 2 });
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

describe('Non-IdP /.well-known/did/nostr write blocking', () => {
  // Regression test for the case Copilot caught: even with IdP
  // disabled, writes under /.well-known/did/nostr/* must be 405.
  // /.well-known/* bypasses the WAC preHandler unconditionally,
  // so without dedicated 405 handlers the wildcard write routes
  // would accept unauthenticated PUT/POST and create files on
  // disk under this namespace.
  let server;
  let baseUrl;

  before(async () => {
    const port = await getAvailablePort();
    baseUrl = `http://${TEST_HOST}:${port}`;
    server = createServer({
      logger: false,
      root: TEST_DATA_DIR + '-noidp',
      idp: false,                       // <-- the point of the test
      forceCloseConnections: true,
    });
    await server.listen({ port, host: TEST_HOST });
  });

  after(async () => {
    await server.close();
    await fs.remove(TEST_DATA_DIR + '-noidp');
  });

  it('returns 405 for PUT/POST/PATCH/DELETE under the namespace', async () => {
    for (const subpath of ['', '/x', '/a/b']) {
      for (const method of ['PUT', 'POST', 'PATCH', 'DELETE']) {
        const r = await fetch(`${baseUrl}/.well-known/did/nostr${subpath}`, {
          method,
          headers: { 'Content-Type': 'application/json' },
          body: method === 'DELETE' ? undefined : '{}',
        });
        assert.strictEqual(r.status, 405,
          `${method} /.well-known/did/nostr${subpath} should be 405 in non-IdP mode (got ${r.status})`);
      }
    }
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

  it('finds JsonWebKey entries when y matches the BIP-340 canonical point', async () => {
    const { secp256k1 } = await import('@noble/curves/secp256k1');
    const sk = generateSecretKey();
    const pk = getPublicKey(sk);
    // x-coord is the hex pubkey base64url-encoded.
    const b64u = (hex) => Buffer.from(hex, 'hex').toString('base64')
      .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    const x = b64u(pk);
    // Compute the canonical (even-y) y for this x — same logic as
    // the verifier in src/auth/nostr.js.
    const point = secp256k1.ProjectivePoint.fromHex('02' + pk);
    const yHex = point.toAffine().y.toString(16).padStart(64, '0');
    const y = b64u(yHex);
    const profile = {
      verificationMethod: [{
        id: '#k1',
        type: 'JsonWebKey',
        publicKeyJwk: { kty: 'EC', crv: 'secp256k1', x, y },
      }],
    };
    const found = extractNostrPubkeysFromProfile(profile);
    assert.strictEqual(found.length, 1);
    assert.strictEqual(found[0].pubkey, pk);
  });

  it('rejects JsonWebKey entries with mismatched y (not the BIP-340 canonical point)', () => {
    const sk = generateSecretKey();
    const pk = getPublicKey(sk);
    const b64u = (hex) => Buffer.from(hex, 'hex').toString('base64')
      .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    const profile = {
      verificationMethod: [{
        id: '#k1',
        type: 'JsonWebKey',
        // Right x, but a y that's clearly not on-curve. Indexer must
        // refuse, otherwise it could publish a key the verifier will
        // reject (401 on advertised pubkey).
        publicKeyJwk: { kty: 'EC', crv: 'secp256k1', x: b64u(pk), y: b64u('00'.repeat(32)) },
      }],
    };
    assert.deepStrictEqual(extractNostrPubkeysFromProfile(profile), []);
  });

  it('rejects JsonWebKey entries missing y', () => {
    const sk = generateSecretKey();
    const pk = getPublicKey(sk);
    const x = Buffer.from(pk, 'hex').toString('base64')
      .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    const profile = {
      verificationMethod: [{ id: '#k1', type: 'JsonWebKey',
        publicKeyJwk: { kty: 'EC', crv: 'secp256k1', x } }],
    };
    assert.deepStrictEqual(extractNostrPubkeysFromProfile(profile), []);
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

describe('profilePathFromWebId — DATA_ROOT containment', () => {
  // Pure unit tests; no server. Exercises the containment branch
  // directly with raw inputs that bypass URL parsing's `..`
  // normalization, since that's the layer that would matter if a
  // future caller ever bypassed `new URL()`.
  const DATA_ROOT = '/srv/jss/data';

  it('resolves a normal pathname under dataRoot', () => {
    const p = profilePathFromWebId(DATA_ROOT, 'http://example/alice/profile/card.jsonld#me');
    assert.strictEqual(p, '/srv/jss/data/alice/profile/card.jsonld');
  });

  it('resolves a root-pod pathname under dataRoot', () => {
    const p = profilePathFromWebId(DATA_ROOT, 'http://example/profile/card.jsonld#me');
    assert.strictEqual(p, '/srv/jss/data/profile/card.jsonld');
  });

  it('rejects unparseable webIds', () => {
    assert.strictEqual(profilePathFromWebId(DATA_ROOT, 'not a url'), null);
    assert.strictEqual(profilePathFromWebId(DATA_ROOT, null), null);
    assert.strictEqual(profilePathFromWebId(DATA_ROOT, 42), null);
  });

  it('does NOT escape dataRoot for `..` traversal in the URL pathname', () => {
    // WHATWG URL parsing already strips this — confirm the result
    // stays inside dataRoot regardless.
    const p = profilePathFromWebId(DATA_ROOT, 'http://example/../../../etc/passwd');
    assert.ok(p === null || p.startsWith('/srv/jss/data'),
      `expected containment, got ${p}`);
  });

  it('keeps a relative dataRoot + plausible webId inside the absolute dataRoot', () => {
    // Sanity test for the relative-dataRoot case. With dataRoot
    // `./inner` and a normal-looking webId pathname, the resolved
    // path lives at `<cwd>/inner/some/profile/card.jsonld` —
    // INSIDE the resolved-absolute innerRoot. (URL normalization
    // already strips `..` segments before path-resolution sees
    // them, so a "real" outside-dataRoot result isn't reachable
    // through URL-parsed webIds in practice. The containment
    // check stays as defense-in-depth for any future caller that
    // bypasses URL parsing.)
    const innerRoot = './nonexistent-inner-root';
    const p = profilePathFromWebId(innerRoot, 'http://example/some/profile/card.jsonld');
    assert.ok(p && p.startsWith(path.resolve(innerRoot)),
      `expected ${p} to be under ${path.resolve(innerRoot)}`);
  });

  it('every URL-parseable webId with `..` segments still resolves inside dataRoot', () => {
    // The production path is unreachable via URL-parsed input —
    // WHATWG URL parsing strips `..` before our path-resolution
    // sees it. This test asserts the resulting INVARIANT (every
    // URL-parseable webId stays inside dataRoot) across a few
    // traversal-shaped inputs, so any future regression where
    // someone bypasses URL parsing or breaks the leading-slash
    // strip would surface here.
    for (const evil of [
      'http://h/../../../etc/passwd',
      'http://h//../etc/passwd',
      'http://h/.%2e/etc/passwd',
      'http://h/foo/../../../etc/passwd',
    ]) {
      const p = profilePathFromWebId(DATA_ROOT, evil);
      assert.ok(
        p === null || p.startsWith(DATA_ROOT + path.sep) || p === DATA_ROOT,
        `${evil} → ${p} escaped DATA_ROOT`,
      );
    }
  });
});
