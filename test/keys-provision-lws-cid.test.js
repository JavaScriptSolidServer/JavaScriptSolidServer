/**
 * End-to-end: a JWT signed with the on-disk Phase 1 owner secret,
 * with `kid` pointing at the Phase 2 verificationMethod that lands
 * in the seeded WebID profile, authenticates as the pod owner via
 * the existing LWS-CID verifier (src/auth/lws-cid.js).
 *
 * This is the single test that proves Phase 2 of #437 (#443) closes
 * the loop: keypair on disk → public side in profile → JWT signed
 * with the secret → verifier accepts → WebID returned.
 *
 * Builds the JWT inline (signing primitives from @noble/curves are
 * already a jss dep). Stubs global.fetch so the verifier's profile
 * GET is served from an in-memory profile produced by the actual
 * generateProfile helper — no test fixtures, no second source of
 * truth for the profile shape.
 */

import { describe, it, before, after, beforeEach } from 'node:test';
import assert from 'node:assert';
import { sha256 } from '@noble/hashes/sha2';
import { secp256k1 } from '@noble/curves/secp256k1';
import { provisionOwnerKey } from '../src/keys/provision.js';
import { generateProfile } from '../src/webid/profile.js';
import { verifyLwsCidAuth, _clearProfileCacheForTests } from '../src/auth/lws-cid.js';

const POD_ORIGIN = 'https://alice.example';
const POD_URI = `${POD_ORIGIN}/`;
const WEBID = `${POD_URI}profile/card.jsonld#me`;
const DOC_URL = `${POD_URI}profile/card.jsonld`;
const ISSUER = `${POD_ORIGIN}/`;

function b64u(bytes) {
  return Buffer.from(bytes).toString('base64')
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function makeEs256kJwt({ secretHex, header, payload }) {
  const h64 = b64u(Buffer.from(JSON.stringify(header)));
  const p64 = b64u(Buffer.from(JSON.stringify(payload)));
  const signingInput = Buffer.from(`${h64}.${p64}`, 'utf8');
  const msgHash = sha256(signingInput);
  const sig = secp256k1.sign(msgHash, hexToBytes(secretHex));
  return `${h64}.${p64}.${b64u(sig.toCompactRawBytes())}`;
}

function hexToBytes(hex) {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

function makeRequest(token, { host = 'alice.example', proto = 'https' } = {}) {
  return {
    headers: { authorization: `Bearer ${token}`, host },
    protocol: proto
  };
}

describe('Phase 2: LWS-CID round-trip with provisioned owner key (#443)', () => {
  let realFetch;
  let servedProfile = null;

  before(() => {
    realFetch = global.fetch;
    global.fetch = async (url) => {
      const u = String(url);
      if (u === DOC_URL && servedProfile) {
        return new Response(JSON.stringify(servedProfile), {
          status: 200,
          headers: { 'content-type': 'application/ld+json' }
        });
      }
      return new Response('not found', { status: 404 });
    };
  });

  after(() => {
    global.fetch = realFetch;
  });

  beforeEach(() => {
    servedProfile = null;
    _clearProfileCacheForTests();
  });

  it('verifies a JWT signed with the on-disk secret against the seeded profile', async () => {
    // 1. Provision an owner key (same call site as createPodStructure /
    //    createRootPodStructure use during pod creation).
    const owner = provisionOwnerKey({ webId: WEBID });

    // 2. Build the seeded WebID profile with the owner VM injected
    //    (same call as createPodStructure makes after #443).
    servedProfile = generateProfile({
      webId: WEBID,
      name: 'me',
      podUri: POD_URI,
      issuer: ISSUER,
      ownerVm: owner.vm
    });

    // Sanity: the profile should carry the VM and reference it from
    // authentication / assertionMethod (the last two are what lets the
    // VM count as an auth factor without a separate PATCH).
    assert.strictEqual(servedProfile.verificationMethod.length, 1);
    assert.strictEqual(servedProfile.verificationMethod[0]['@id'], owner.vm['@id']);
    assert.deepStrictEqual(servedProfile.authentication, [owner.vm['@id']]);
    assert.deepStrictEqual(servedProfile.assertionMethod, [owner.vm['@id']]);

    // 3. Sign an LWS-CID JWT with the on-disk secret. `kid` points at
    //    the VM's `@id` — that's how the verifier locates the public
    //    key in the profile.
    const now = Math.floor(Date.now() / 1000);
    const token = makeEs256kJwt({
      secretHex: owner.secretHex,
      header: { alg: 'ES256K', typ: 'JWT', kid: owner.vm['@id'] },
      payload: {
        iss: WEBID,
        sub: WEBID,
        aud: POD_ORIGIN,
        client_id: WEBID,
        iat: now,
        exp: now + 60
      }
    });

    // 4. Verify via the existing LWS-CID verifier (no changes to
    //    src/auth/lws-cid.js — Phase 2 only landed the profile wire).
    const result = await verifyLwsCidAuth(makeRequest(token));
    assert.strictEqual(result.error, null,
      `LWS-CID verification should succeed; got error: ${result.error}`);
    assert.strictEqual(result.webId, WEBID,
      'verifier should return the pod owner WebID as the authenticated identity');
  });

  it('rejects a JWT signed with a different secret (sanity)', async () => {
    // Provision the real owner key and seed the profile with its VM,
    // but sign the JWT with an UNRELATED secret. The verifier should
    // refuse — proves the signature check is doing real work, not
    // just rubber-stamping anything addressed to the right kid.
    const owner = provisionOwnerKey({ webId: WEBID });
    servedProfile = generateProfile({
      webId: WEBID,
      name: 'me',
      podUri: POD_URI,
      issuer: ISSUER,
      ownerVm: owner.vm
    });

    const wrongSecret = provisionOwnerKey({ webId: WEBID }).secretHex;
    const now = Math.floor(Date.now() / 1000);
    const token = makeEs256kJwt({
      secretHex: wrongSecret,
      header: { alg: 'ES256K', typ: 'JWT', kid: owner.vm['@id'] },
      payload: {
        iss: WEBID, sub: WEBID, aud: POD_ORIGIN, client_id: WEBID,
        iat: now, exp: now + 60
      }
    });

    const result = await verifyLwsCidAuth(makeRequest(token));
    assert.strictEqual(result.webId, null,
      'mismatched secret must not authenticate');
    // Match the specific verifier error prefix, not just any string
    // containing "signature" — JWS-related errors (expired, malformed,
    // bad nbf, etc.) also mention "signature" but for the wrong
    // reasons. We want to prove the signature *check* did real work.
    assert.match(result.error || '', /signature verification failed/,
      'error should be the signature-verification path, not some other JWT failure');
  });
});
