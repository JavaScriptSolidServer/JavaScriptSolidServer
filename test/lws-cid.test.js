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
import * as jose from 'jose';
import { hasLwsCidAuth, verifyLwsCidAuth, _clearProfileCacheForTests } from '../src/auth/lws-cid.js';

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

function makeRequest(token, { host = 'example.com', proto = 'https' } = {}) {
  return {
    headers: {
      authorization: `Bearer ${token}`,
      host,
    },
    protocol: proto,
  };
}

const WEBID = 'https://example.com/profile/card.jsonld#me';
const DOC_URL = 'https://example.com/profile/card.jsonld';
const VM_ID = `${DOC_URL}#nostr-key-1`;
const POD_ORIGIN = 'https://example.com';

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
// Per-URL response overrides — set { status, headers, body } per URL to
// inject redirects, oversized bodies, or non-default content-types.
let urlResponses = new Map();

function installFetchStub() {
  global.fetch = async (url) => {
    const u = String(url);
    if (urlResponses.has(u)) {
      const { status = 200, headers = {}, body = '' } = urlResponses.get(u);
      return new Response(body, { status, headers });
    }
    if (u === DOC_URL) {
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
  // Default valid claims — tests can override per-case.
  function claims(now = Math.floor(Date.now() / 1000), extra = {}) {
    return { sub: WEBID, iss: WEBID, client_id: WEBID, aud: [POD_ORIGIN], iat: now, exp: now + 60, ...extra };
  }

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
    urlResponses = new Map();
    // Cache must not survive between tests; otherwise nextProfile
    // changes are masked by a stale hit on DOC_URL.
    _clearProfileCacheForTests();
  });

  it('verifies a valid ES256K JWT against a CID-shaped profile', async () => {
    const token = makeJwt({
      privKey: priv,
      header: { alg: 'ES256K', kid: VM_ID, typ: 'JWT' },
      payload: claims(),
    });
    const result = await verifyLwsCidAuth(makeRequest(token));
    assert.strictEqual(result.error, null);
    assert.strictEqual(result.webId, WEBID);
  });

  it('rejects "none" alg', async () => {
    const token = makeJwt({
      privKey: priv,
      header: { alg: 'none', kid: VM_ID, typ: 'JWT' },
      payload: claims(),
    });
    const r = await verifyLwsCidAuth(makeRequest(token));
    assert.strictEqual(r.webId, null);
    assert.match(r.error, /none/);
  });

  it('rejects when sub != iss', async () => {
    const token = makeJwt({
      privKey: priv,
      header: { alg: 'ES256K', kid: VM_ID },
      payload: claims(undefined, { iss: 'https://other.example/profile#me' }),
    });
    const r = await verifyLwsCidAuth(makeRequest(token));
    assert.match(r.error, /sub.*iss.*client_id/);
  });

  it('rejects when kid is in a different document than sub', async () => {
    const otherKid = 'https://other.example/profile/card.jsonld#k1';
    const token = makeJwt({
      privKey: priv,
      header: { alg: 'ES256K', kid: otherKid },
      payload: claims(),
    });
    const r = await verifyLwsCidAuth(makeRequest(token));
    assert.match(r.error, /not in the subject/);
  });

  it('rejects expired JWT', async () => {
    const past = Math.floor(Date.now() / 1000) - 3600;
    const token = makeJwt({
      privKey: priv,
      header: { alg: 'ES256K', kid: VM_ID },
      payload: claims(past, { iat: past - 60, exp: past }),
    });
    const r = await verifyLwsCidAuth(makeRequest(token));
    assert.match(r.error, /expired/);
  });

  it('rejects nbf in the future', async () => {
    const now = Math.floor(Date.now() / 1000);
    const token = makeJwt({
      privKey: priv,
      header: { alg: 'ES256K', kid: VM_ID },
      payload: claims(now, { nbf: now + 600 }),
    });
    const r = await verifyLwsCidAuth(makeRequest(token));
    assert.match(r.error, /not yet valid/);
  });

  it('rejects iat too far in the future', async () => {
    const now = Math.floor(Date.now() / 1000);
    const token = makeJwt({
      privKey: priv,
      header: { alg: 'ES256K', kid: VM_ID },
      payload: claims(now, { iat: now + 600, exp: now + 1200 }),
    });
    const r = await verifyLwsCidAuth(makeRequest(token));
    assert.match(r.error, /iat is in the future/);
  });

  it('rejects iat too old', async () => {
    const now = Math.floor(Date.now() / 1000);
    const token = makeJwt({
      privKey: priv,
      header: { alg: 'ES256K', kid: VM_ID },
      payload: claims(now, { iat: now - 7200, exp: now + 60 }),
    });
    const r = await verifyLwsCidAuth(makeRequest(token));
    assert.match(r.error, /iat too old/);
  });

  it('rejects non-numeric exp', async () => {
    const now = Math.floor(Date.now() / 1000);
    const token = makeJwt({
      privKey: priv,
      header: { alg: 'ES256K', kid: VM_ID },
      payload: claims(now, { exp: '9999999999' }),
    });
    const r = await verifyLwsCidAuth(makeRequest(token));
    assert.match(r.error, /exp claim/);
  });

  it('rejects non-numeric iat', async () => {
    const now = Math.floor(Date.now() / 1000);
    const token = makeJwt({
      privKey: priv,
      header: { alg: 'ES256K', kid: VM_ID },
      payload: claims(now, { iat: 'right-now' }),
    });
    const r = await verifyLwsCidAuth(makeRequest(token));
    assert.match(r.error, /iat claim/);
  });

  it('rejects missing exp', async () => {
    const now = Math.floor(Date.now() / 1000);
    const token = makeJwt({
      privKey: priv,
      header: { alg: 'ES256K', kid: VM_ID },
      payload: claims(now, { exp: undefined }),
    });
    const r = await verifyLwsCidAuth(makeRequest(token));
    assert.match(r.error, /exp claim is required/);
  });

  it('rejects missing iat', async () => {
    const now = Math.floor(Date.now() / 1000);
    const token = makeJwt({
      privKey: priv,
      header: { alg: 'ES256K', kid: VM_ID },
      payload: claims(now, { iat: undefined }),
    });
    const r = await verifyLwsCidAuth(makeRequest(token));
    assert.match(r.error, /iat claim is required/);
  });

  it('rejects lifetime > 1 hour (replay window cap)', async () => {
    const now = Math.floor(Date.now() / 1000);
    const token = makeJwt({
      privKey: priv,
      header: { alg: 'ES256K', kid: VM_ID },
      payload: claims(now, { iat: now, exp: now + 7200 }),
    });
    const r = await verifyLwsCidAuth(makeRequest(token));
    assert.match(r.error, /lifetime exceeds maximum/);
  });

  it('rejects exp <= iat', async () => {
    const now = Math.floor(Date.now() / 1000);
    const token = makeJwt({
      privKey: priv,
      header: { alg: 'ES256K', kid: VM_ID },
      payload: claims(now, { iat: now, exp: now }),
    });
    const r = await verifyLwsCidAuth(makeRequest(token));
    assert.match(r.error, /exp must be after iat/);
  });

  it('rejects missing aud', async () => {
    const now = Math.floor(Date.now() / 1000);
    const token = makeJwt({
      privKey: priv,
      header: { alg: 'ES256K', kid: VM_ID },
      payload: claims(now, { aud: undefined }),
    });
    const r = await verifyLwsCidAuth(makeRequest(token));
    assert.match(r.error, /aud claim is required/);
  });

  it('rejects when kid does not match any VM in the profile', async () => {
    const ghostKid = `${DOC_URL}#nope`;
    const token = makeJwt({
      privKey: priv,
      header: { alg: 'ES256K', kid: ghostKid },
      payload: claims(),
    });
    const r = await verifyLwsCidAuth(makeRequest(token));
    assert.match(r.error, /no verificationMethod/);
  });

  it('rejects when VM is not in authentication list', async () => {
    nextProfile = buildProfile(jwk, { withAuthRef: false });
    const token = makeJwt({
      privKey: priv,
      header: { alg: 'ES256K', kid: VM_ID },
      payload: claims(),
    });
    const r = await verifyLwsCidAuth(makeRequest(token));
    assert.match(r.error, /not listed in authentication/);
  });

  it('rejects when audience does not include this server', async () => {
    const token = makeJwt({
      privKey: priv,
      header: { alg: 'ES256K', kid: VM_ID },
      payload: claims(undefined, { aud: ['https://elsewhere.example/'] }),
    });
    const r = await verifyLwsCidAuth(makeRequest(token));
    assert.match(r.error, /aud.*does not include/);
  });

  it('rejects when server origin cannot be determined', async () => {
    const token = makeJwt({
      privKey: priv,
      header: { alg: 'ES256K', kid: VM_ID },
      payload: claims(),
    });
    // No host header, no x-forwarded-host, no fastify hostname.
    const req = { headers: { authorization: `Bearer ${token}` } };
    const r = await verifyLwsCidAuth(req);
    assert.match(r.error, /cannot determine server origin/);
  });

  it('honors x-forwarded-proto/host for aud check (behind reverse proxy)', async () => {
    const token = makeJwt({
      privKey: priv,
      header: { alg: 'ES256K', kid: VM_ID },
      payload: claims(undefined, { aud: ['https://public.example'] }),
    });
    const req = {
      headers: {
        authorization: `Bearer ${token}`,
        host: 'internal:8080',
        'x-forwarded-proto': 'https',
        'x-forwarded-host': 'public.example',
      },
      protocol: 'http',
    };
    const r = await verifyLwsCidAuth(req);
    assert.strictEqual(r.error, null);
    assert.strictEqual(r.webId, WEBID);
  });

  it('rejects tampered signature', async () => {
    const valid = makeJwt({
      privKey: priv,
      header: { alg: 'ES256K', kid: VM_ID },
      payload: claims(),
    });
    const parts = valid.split('.');
    const sigBuf = Buffer.from(parts[2].replace(/-/g, '+').replace(/_/g, '/'), 'base64');
    sigBuf[0] ^= 0xff;
    parts[2] = b64u(sigBuf);
    const tampered = parts.join('.');
    const r = await verifyLwsCidAuth(makeRequest(tampered));
    assert.match(r.error, /signature/);
  });

  it('rejects when VM is signed with different key than JWT', async () => {
    const otherPriv = secp256k1.utils.randomPrivateKey();
    nextProfile = buildProfile(jwkFromSecp256k1(otherPriv));
    const token = makeJwt({
      privKey: priv,
      header: { alg: 'ES256K', kid: VM_ID },
      payload: claims(),
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
      payload: claims(),
    });
    const r = await verifyLwsCidAuth(makeRequest(token));
    assert.match(r.error, /could not fetch/);
  });

  it('rejects when CID document has no controller / @id / id (vacuous bypass)', async () => {
    // Profile that's structurally complete enough to find a VM, but has
    // no top-level controller or @id at all.
    nextProfile = {
      '@context': { cid: 'https://www.w3.org/ns/cid/v1#' },
      verificationMethod: [{
        id: VM_ID,
        type: 'JsonWebKey',
        controller: WEBID,
        publicKeyJwk: jwk,
      }],
      authentication: [VM_ID],
    };
    const token = makeJwt({
      privKey: priv,
      header: { alg: 'ES256K', kid: VM_ID },
      payload: claims(),
    });
    const r = await verifyLwsCidAuth(makeRequest(token));
    assert.match(r.error, /no controller or @id/);
  });

  it('handles comma-separated x-forwarded-host (multi-proxy chain)', async () => {
    const token = makeJwt({
      privKey: priv,
      header: { alg: 'ES256K', kid: VM_ID },
      payload: claims(undefined, { aud: ['https://public.example'] }),
    });
    const req = {
      headers: {
        authorization: `Bearer ${token}`,
        'x-forwarded-proto': 'https, http',
        'x-forwarded-host': 'public.example, internal.lan',
      },
    };
    const r = await verifyLwsCidAuth(req);
    assert.strictEqual(r.error, null);
    assert.strictEqual(r.webId, WEBID);
  });

  it('refuses cross-origin redirect during profile fetch', async () => {
    urlResponses.set(DOC_URL, {
      status: 302,
      headers: { location: 'https://attacker.example/profile/card.jsonld' },
    });
    const token = makeJwt({
      privKey: priv,
      header: { alg: 'ES256K', kid: VM_ID },
      payload: claims(),
    });
    const r = await verifyLwsCidAuth(makeRequest(token));
    assert.match(r.error, /cross-origin redirect refused/);
  });

  it('rejects profile larger than the byte cap', async () => {
    // 300 KB of JSON — over the 256 KB cap.
    const huge = 'x'.repeat(300 * 1024);
    urlResponses.set(DOC_URL, {
      status: 200,
      headers: { 'content-type': 'application/ld+json' },
      body: JSON.stringify({ junk: huge }),
    });
    const token = makeJwt({
      privKey: priv,
      header: { alg: 'ES256K', kid: VM_ID },
      payload: claims(),
    });
    const r = await verifyLwsCidAuth(makeRequest(token));
    assert.match(r.error, /CID document too large/);
  });

  it('rejects when Content-Length header announces oversize body', async () => {
    urlResponses.set(DOC_URL, {
      status: 200,
      headers: {
        'content-type': 'application/ld+json',
        'content-length': String(10 * 1024 * 1024), // 10 MB declared
      },
      body: JSON.stringify({}), // body is small but header lies
    });
    const token = makeJwt({
      privKey: priv,
      header: { alg: 'ES256K', kid: VM_ID },
      payload: claims(),
    });
    const r = await verifyLwsCidAuth(makeRequest(token));
    assert.match(r.error, /too large/);
  });

  it('SSRF: rejects kid pointing at localhost', async () => {
    const localKid = 'https://localhost/profile/card.jsonld#me';
    const token = makeJwt({
      privKey: priv,
      header: { alg: 'ES256K', kid: localKid },
      payload: claims(undefined, {
        sub: localKid, iss: localKid, client_id: localKid,
      }),
    });
    const r = await verifyLwsCidAuth(makeRequest(token));
    // SSRF guard fires inside fetchProfile and surfaces as "could not
    // fetch CID document: SSRF protection: ...".
    assert.match(r.error, /SSRF protection/);
  });

  // --- non-ES256K alg coverage (the jose-driven branch) -------------

  describe('non-ES256K algorithms via jose', () => {
    async function runHappyPath(alg) {
      const kp = await jose.generateKeyPair(alg, { extractable: true });
      const publicJwk = await jose.exportJWK(kp.publicKey);
      publicJwk.alg = alg;
      nextProfile = buildProfile(publicJwk);

      const now = Math.floor(Date.now() / 1000);
      const token = await new jose.SignJWT(claims(now))
        .setProtectedHeader({ alg, kid: VM_ID, typ: 'JWT' })
        .sign(kp.privateKey);
      const r = await verifyLwsCidAuth(makeRequest(token));
      assert.strictEqual(r.error, null, `unexpected error: ${r.error}`);
      assert.strictEqual(r.webId, WEBID);
    }

    it('verifies ES256 (P-256)', async () => { await runHappyPath('ES256'); });
    it('verifies EdDSA (Ed25519)', async () => { await runHappyPath('EdDSA'); });
    it('verifies RS256 (RSA-2048)', async () => { await runHappyPath('RS256'); });

    it('rejects RS256 with tampered payload', async () => {
      const kp = await jose.generateKeyPair('RS256', { extractable: true, modulusLength: 2048 });
      const publicJwk = await jose.exportJWK(kp.publicKey);
      publicJwk.alg = 'RS256';
      nextProfile = buildProfile(publicJwk);

      const now = Math.floor(Date.now() / 1000);
      const token = await new jose.SignJWT(claims(now))
        .setProtectedHeader({ alg: 'RS256', kid: VM_ID })
        .sign(kp.privateKey);
      // Tamper with payload portion (middle section).
      const parts = token.split('.');
      const decoded = JSON.parse(Buffer.from(parts[1].replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString());
      decoded.sub = 'https://attacker.example/#me';
      parts[1] = b64u(Buffer.from(JSON.stringify(decoded)));
      const tampered = parts.join('.');
      const r = await verifyLwsCidAuth(makeRequest(tampered));
      assert.notStrictEqual(r.error, null);
    });
  });
});
