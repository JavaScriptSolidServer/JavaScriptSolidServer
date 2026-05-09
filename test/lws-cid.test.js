/**
 * LWS10-CID JWT verifier tests
 *
 * Covers the verifier logic in isolation by stubbing global.fetch so we
 * can hand-craft both the JWT and the profile document. Real end-to-end
 * tests against a running server are filed as a follow-up.
 */

import { describe, it, before, beforeEach, after } from 'node:test';
import assert from 'node:assert';
import { secp256k1 } from '@noble/curves/secp256k1';
import { sha256 } from '@noble/hashes/sha256';
import { hasLwsCidAuth, verifyLwsCidAuth } from '../src/auth/lws-cid.js';

// --- helpers ---------------------------------------------------------

function b64u(bytes) {
  return Buffer.from(bytes).toString('base64')
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function jwkFromSecp256k1(privKey) {
  const pub = secp256k1.getPublicKey(privKey, /*compressed=*/false); // 65 bytes: 0x04 || x || y
  return {
    kty: 'EC',
    crv: 'secp256k1',
    x: b64u(pub.slice(1, 33)),
    y: b64u(pub.slice(33, 65)),
    alg: 'ES256K',
  };
}

function makeJwt({ privKey, header, payload }) {
  const h64 = b64u(Buffer.from(JSON.stringify(header)));
  const p64 = b64u(Buffer.from(JSON.stringify(payload)));
  const signingInput = Buffer.from(`${h64}.${p64}`, 'utf8');
  const msgHash = sha256(signingInput);
  const sig = secp256k1.sign(msgHash, privKey);
  // Compact 64-byte r||s — what JWS expects.
  return `${h64}.${p64}.${b64u(sig.toCompactRawBytes())}`;
}

function makeRequest(token, { host = 'pod.example', proto = 'https' } = {}) {
  return {
    headers: {
      authorization: `Bearer ${token}`,
      host,
    },
    protocol: proto,
  };
}

const WEBID = 'https://pod.example/profile/card.jsonld#me';
const DOC_URL = 'https://pod.example/profile/card.jsonld';
const VM_ID = `${DOC_URL}#nostr-key-1`;
const POD_ORIGIN = 'https://pod.example';

// Minimal CID-shaped profile.
function buildProfile(jwk, { withAuthRef = true, controller = WEBID } = {}) {
  return {
    '@context': {
      cid: 'https://www.w3.org/ns/cid/v1#',
      controller: { '@id': 'cid:controller', '@type': '@id' },
      verificationMethod: { '@id': 'cid:verificationMethod', '@container': '@set' },
      authentication: { '@id': 'cid:authentication', '@type': '@id', '@container': '@set' },
      publicKeyJwk: { '@id': 'cid:publicKeyJwk', '@type': '@json' },
    },
    '@id': WEBID,
    controller,
    verificationMethod: [
      {
        id: VM_ID,
        type: 'JsonWebKey',
        controller: WEBID,
        publicKeyJwk: jwk,
      },
    ],
    ...(withAuthRef ? { authentication: [VM_ID] } : {}),
  };
}

// --- fetch stub ------------------------------------------------------

const realFetch = global.fetch;
let nextProfile = null;
let nextStatus = 200;

function installFetchStub() {
  global.fetch = async (url) => {
    if (String(url) === DOC_URL) {
      return new Response(JSON.stringify(nextProfile), {
        status: nextStatus,
        headers: { 'content-type': 'application/ld+json' },
      });
    }
    return new Response('not found', { status: 404 });
  };
}
function restoreFetch() { global.fetch = realFetch; }

// --- tests -----------------------------------------------------------

describe('hasLwsCidAuth', () => {
  it('detects Bearer JWT with URL kid', () => {
    const token = makeJwt({
      privKey: secp256k1.utils.randomPrivateKey(),
      header: { alg: 'ES256K', kid: VM_ID, typ: 'JWT' },
      payload: { sub: WEBID, iss: WEBID, client_id: WEBID, iat: Math.floor(Date.now()/1000) },
    });
    assert.strictEqual(hasLwsCidAuth(makeRequest(token)), true);
  });

  it('rejects Bearer JWT with opaque fingerprint kid (looks like IDP JWT)', () => {
    const token = makeJwt({
      privKey: secp256k1.utils.randomPrivateKey(),
      header: { alg: 'ES256K', kid: 'c1f52577', typ: 'JWT' },
      payload: { sub: WEBID, iss: WEBID, client_id: WEBID, iat: Math.floor(Date.now()/1000) },
    });
    assert.strictEqual(hasLwsCidAuth(makeRequest(token)), false);
  });

  it('rejects DPoP', () => {
    assert.strictEqual(hasLwsCidAuth({ headers: { authorization: 'DPoP eyJ...' } }), false);
  });

  it('rejects Nostr', () => {
    assert.strictEqual(hasLwsCidAuth({ headers: { authorization: 'Nostr abc' } }), false);
  });

  it('rejects no authorization header', () => {
    assert.strictEqual(hasLwsCidAuth({ headers: {} }), false);
  });

  it('rejects malformed JWT', () => {
    assert.strictEqual(hasLwsCidAuth(makeRequest('not.a.jwt')), false);
  });
});

describe('verifyLwsCidAuth', () => {
  let priv;
  let jwk;

  before(() => {
    installFetchStub();
  });

  after(() => {
    restoreFetch();
  });

  beforeEach(() => {
    priv = secp256k1.utils.randomPrivateKey();
    jwk = jwkFromSecp256k1(priv);
    nextStatus = 200;
    nextProfile = buildProfile(jwk);
  });

  it('verifies a valid ES256K JWT against a CID-shaped profile', async () => {
    const now = Math.floor(Date.now() / 1000);
    const token = makeJwt({
      privKey: priv,
      header: { alg: 'ES256K', kid: VM_ID, typ: 'JWT' },
      payload: {
        sub: WEBID, iss: WEBID, client_id: WEBID,
        aud: [POD_ORIGIN], iat: now, exp: now + 60,
      },
    });
    const result = await verifyLwsCidAuth(makeRequest(token));
    assert.strictEqual(result.error, null);
    assert.strictEqual(result.webId, WEBID);
  });

  it('rejects "none" alg', async () => {
    const token = makeJwt({
      privKey: priv,
      header: { alg: 'none', kid: VM_ID, typ: 'JWT' },
      payload: { sub: WEBID, iss: WEBID, client_id: WEBID, iat: Math.floor(Date.now()/1000) },
    });
    const r = await verifyLwsCidAuth(makeRequest(token));
    assert.strictEqual(r.webId, null);
    assert.match(r.error, /none/);
  });

  it('rejects when sub != iss', async () => {
    const token = makeJwt({
      privKey: priv,
      header: { alg: 'ES256K', kid: VM_ID },
      payload: {
        sub: WEBID, iss: 'https://other/#me', client_id: WEBID,
        iat: Math.floor(Date.now()/1000),
      },
    });
    const r = await verifyLwsCidAuth(makeRequest(token));
    assert.match(r.error, /sub.*iss.*client_id/);
  });

  it('rejects when kid is in a different document than sub', async () => {
    const otherKid = 'https://other.example/profile/card.jsonld#k1';
    const token = makeJwt({
      privKey: priv,
      header: { alg: 'ES256K', kid: otherKid },
      payload: { sub: WEBID, iss: WEBID, client_id: WEBID, iat: Math.floor(Date.now()/1000) },
    });
    const r = await verifyLwsCidAuth(makeRequest(token));
    assert.match(r.error, /not in the subject/);
  });

  it('rejects expired JWT', async () => {
    const past = Math.floor(Date.now() / 1000) - 3600;
    const token = makeJwt({
      privKey: priv,
      header: { alg: 'ES256K', kid: VM_ID },
      payload: {
        sub: WEBID, iss: WEBID, client_id: WEBID,
        aud: [POD_ORIGIN], iat: past - 60, exp: past,
      },
    });
    const r = await verifyLwsCidAuth(makeRequest(token));
    assert.match(r.error, /expired/);
  });

  it('rejects when kid does not match any VM in the profile', async () => {
    const ghostKid = `${DOC_URL}#nope`;
    const token = makeJwt({
      privKey: priv,
      header: { alg: 'ES256K', kid: ghostKid },
      payload: { sub: WEBID, iss: WEBID, client_id: WEBID, iat: Math.floor(Date.now()/1000) },
    });
    const r = await verifyLwsCidAuth(makeRequest(token));
    assert.match(r.error, /no verificationMethod/);
  });

  it('rejects when VM is not in authentication list', async () => {
    nextProfile = buildProfile(jwk, { withAuthRef: false });
    const token = makeJwt({
      privKey: priv,
      header: { alg: 'ES256K', kid: VM_ID },
      payload: { sub: WEBID, iss: WEBID, client_id: WEBID, iat: Math.floor(Date.now()/1000) },
    });
    const r = await verifyLwsCidAuth(makeRequest(token));
    assert.match(r.error, /not listed in authentication/);
  });

  it('rejects when audience does not include this server', async () => {
    const token = makeJwt({
      privKey: priv,
      header: { alg: 'ES256K', kid: VM_ID },
      payload: {
        sub: WEBID, iss: WEBID, client_id: WEBID,
        aud: ['https://elsewhere/'], iat: Math.floor(Date.now()/1000),
      },
    });
    const r = await verifyLwsCidAuth(makeRequest(token));
    assert.match(r.error, /aud.*does not include/);
  });

  it('rejects tampered signature', async () => {
    const now = Math.floor(Date.now() / 1000);
    const valid = makeJwt({
      privKey: priv,
      header: { alg: 'ES256K', kid: VM_ID },
      payload: { sub: WEBID, iss: WEBID, client_id: WEBID, aud: [POD_ORIGIN], iat: now, exp: now+60 },
    });
    // Flip a bit in the signature.
    const parts = valid.split('.');
    const sigBuf = Buffer.from(parts[2].replace(/-/g, '+').replace(/_/g, '/'), 'base64');
    sigBuf[0] ^= 0xff;
    parts[2] = b64u(sigBuf);
    const tampered = parts.join('.');
    const r = await verifyLwsCidAuth(makeRequest(tampered));
    assert.match(r.error, /signature/);
  });

  it('rejects when VM is signed with different key than JWT', async () => {
    // Profile advertises VM for one key; token signed with another.
    const otherPriv = secp256k1.utils.randomPrivateKey();
    nextProfile = buildProfile(jwkFromSecp256k1(otherPriv));
    const now = Math.floor(Date.now() / 1000);
    const token = makeJwt({
      privKey: priv,
      header: { alg: 'ES256K', kid: VM_ID },
      payload: { sub: WEBID, iss: WEBID, client_id: WEBID, aud: [POD_ORIGIN], iat: now, exp: now+60 },
    });
    const r = await verifyLwsCidAuth(makeRequest(token));
    assert.match(r.error, /signature/);
  });

  it('rejects when profile fetch fails', async () => {
    nextStatus = 404;
    nextProfile = null;
    const token = makeJwt({
      privKey: priv,
      header: { alg: 'ES256K', kid: VM_ID },
      payload: { sub: WEBID, iss: WEBID, client_id: WEBID, iat: Math.floor(Date.now()/1000) },
    });
    const r = await verifyLwsCidAuth(makeRequest(token));
    assert.match(r.error, /could not fetch/);
  });
});
