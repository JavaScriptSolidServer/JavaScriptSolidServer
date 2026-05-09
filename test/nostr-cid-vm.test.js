/**
 * NIP-98 → WebID via verificationMethod lookup (#399)
 *
 * Covers `verifyNostrAuth`'s new tryResolveViaCidVerificationMethod
 * step: when a Nostr-signed request hits a pod whose owner's WebID
 * profile declares the request's signing pubkey as a CID-v1
 * verificationMethod (in `authentication`), authenticate as the
 * WebID rather than as `did:nostr:<pubkey>`.
 *
 * Stubs global.fetch so we hand-craft the profile document. Real
 * Schnorr signatures are produced via the in-tree nostr/event
 * primitives.
 */

import { describe, it, before, beforeEach, after } from 'node:test';
import assert from 'node:assert';
import { generateSecretKey, getPublicKey, finalizeEvent } from '../src/nostr/event.js';
import { verifyNostrAuth } from '../src/auth/nostr.js';

// --- helpers ---------------------------------------------------------

function nip98Authorization({ method, url, secretKey, createdAt }) {
  const event = finalizeEvent({
    kind: 27235,
    created_at: createdAt ?? Math.floor(Date.now() / 1000),
    tags: [['u', url], ['method', method.toUpperCase()]],
    content: '',
  }, secretKey);
  const token = Buffer.from(JSON.stringify(event)).toString('base64');
  return { authHeader: `Nostr ${token}`, event };
}

function makeRequest({ method = 'GET', url, host = 'alice.example.com', extra = {} } = {}) {
  const fullUrl = url ?? `https://${host}/private/data.ttl`;
  const path = new URL(fullUrl).pathname;
  return {
    method,
    url: path,
    protocol: 'https',
    hostname: host,
    headers: { authorization: '', host, ...extra.headers },
    subdomainsEnabled: true,
    baseDomain: 'example.com',
    podName: host.split('.')[0] === 'example' ? null : host.split('.')[0],
  };
}

// f-form Multikey for the CCG-compromise Nostr recipe:
// "f" + "e701" + parity (default 02) + 32-byte xonly hex.
function nostrPubkeyToFformMultikey(pubHex, parity = '02') {
  return `f` + 'e701' + parity + pubHex.toLowerCase();
}

// --- profile fixtures ------------------------------------------------

const POD_HOST = 'alice.example.com';
const WEBID = `https://${POD_HOST}/profile/card.jsonld#me`;
const DOC_URL = `https://${POD_HOST}/profile/card.jsonld`;

function buildProfile({ pubkey, vmId = `${DOC_URL}#nostr-key-1`, withAuth = true, jwk = null } = {}) {
  const vm = jwk
    ? { id: vmId, type: 'JsonWebKey', controller: WEBID, publicKeyJwk: jwk }
    : { id: vmId, type: 'Multikey',  controller: WEBID,
        publicKeyMultibase: nostrPubkeyToFformMultikey(pubkey) };
  return {
    '@context': {
      cid: 'https://www.w3.org/ns/cid/v1#',
      controller: { '@id': 'cid:controller', '@type': '@id' },
      verificationMethod: { '@id': 'cid:verificationMethod', '@container': '@set' },
      authentication: { '@id': 'cid:authentication', '@type': '@id', '@container': '@set' },
      publicKeyMultibase: { '@id': 'cid:publicKeyMultibase' },
      publicKeyJwk: { '@id': 'cid:publicKeyJwk', '@type': '@json' },
    },
    '@id': WEBID,
    controller: WEBID,
    verificationMethod: [vm],
    ...(withAuth ? { authentication: [vmId] } : {}),
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
    // Anything else (the did-nostr.js DID-doc resolver fallback) — 404
    // so the secondary lookup short-circuits.
    return new Response('not found', { status: 404 });
  };
}
function restoreFetch() { global.fetch = realFetch; }

// --- tests -----------------------------------------------------------

describe('NIP-98 + CID verificationMethod lookup (#399)', () => {
  let sk, pk;

  before(() => {
    installFetchStub();
  });
  after(() => {
    restoreFetch();
  });

  beforeEach(() => {
    sk = generateSecretKey();
    pk = getPublicKey(sk);
    nextStatus = 200;
    nextProfile = buildProfile({ pubkey: pk });
  });

  it('upgrades did:nostr → WebID when the pubkey is in the profile as f-form Multikey VM', async () => {
    const url = `https://${POD_HOST}/private/data.ttl`;
    const { authHeader } = nip98Authorization({ method: 'GET', url, secretKey: sk });
    const req = makeRequest({ url });
    req.headers.authorization = authHeader;

    const r = await verifyNostrAuth(req);
    assert.strictEqual(r.error, null);
    assert.strictEqual(r.webId, WEBID);
  });

  it('upgrades did:nostr → WebID when the pubkey is in the profile as JsonWebKey VM', async () => {
    // x-coord is the hex pubkey base64url-encoded.
    const x = Buffer.from(pk, 'hex').toString('base64')
      .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    nextProfile = buildProfile({
      pubkey: pk,
      jwk: { kty: 'EC', crv: 'secp256k1', alg: 'ES256K', x, y: 'irrelevant-for-this-match' },
    });
    const url = `https://${POD_HOST}/private/data.ttl`;
    const { authHeader } = nip98Authorization({ method: 'GET', url, secretKey: sk });
    const req = makeRequest({ url });
    req.headers.authorization = authHeader;

    const r = await verifyNostrAuth(req);
    assert.strictEqual(r.error, null);
    assert.strictEqual(r.webId, WEBID);
  });

  it('falls back to did:nostr when the profile has no matching VM', async () => {
    const otherSk = generateSecretKey();
    const otherPk = getPublicKey(otherSk);
    nextProfile = buildProfile({ pubkey: otherPk }); // VM has a different key

    const url = `https://${POD_HOST}/private/data.ttl`;
    const { authHeader } = nip98Authorization({ method: 'GET', url, secretKey: sk });
    const req = makeRequest({ url });
    req.headers.authorization = authHeader;

    const r = await verifyNostrAuth(req);
    assert.strictEqual(r.error, null);
    assert.strictEqual(r.webId, `did:nostr:${pk}`);
  });

  it('falls back to did:nostr when the matching VM is NOT in authentication', async () => {
    nextProfile = buildProfile({ pubkey: pk, withAuth: false });

    const url = `https://${POD_HOST}/private/data.ttl`;
    const { authHeader } = nip98Authorization({ method: 'GET', url, secretKey: sk });
    const req = makeRequest({ url });
    req.headers.authorization = authHeader;

    const r = await verifyNostrAuth(req);
    assert.strictEqual(r.error, null);
    assert.strictEqual(r.webId, `did:nostr:${pk}`);
  });

  it('falls back to did:nostr when the profile fetch fails', async () => {
    nextStatus = 404;
    nextProfile = null;

    const url = `https://${POD_HOST}/private/data.ttl`;
    const { authHeader } = nip98Authorization({ method: 'GET', url, secretKey: sk });
    const req = makeRequest({ url });
    req.headers.authorization = authHeader;

    const r = await verifyNostrAuth(req);
    assert.strictEqual(r.error, null);
    assert.strictEqual(r.webId, `did:nostr:${pk}`);
  });

  it('still rejects an invalid signature regardless of the profile', async () => {
    const url = `https://${POD_HOST}/private/data.ttl`;
    const { authHeader, event } = nip98Authorization({ method: 'GET', url, secretKey: sk });
    // Tamper: re-encode the event with a flipped signature byte.
    const decoded = JSON.parse(Buffer.from(authHeader.slice(6), 'base64').toString());
    decoded.sig = decoded.sig.slice(0, -2) + (decoded.sig.endsWith('00') ? 'ff' : '00');
    const tampered = `Nostr ${Buffer.from(JSON.stringify(decoded)).toString('base64')}`;
    const req = makeRequest({ url });
    req.headers.authorization = tampered;

    const r = await verifyNostrAuth(req);
    assert.strictEqual(r.webId, null);
    assert.match(r.error, /signature/);
  });
});
