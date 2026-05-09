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
import { secp256k1 } from '@noble/curves/secp256k1';
import { generateSecretKey, getPublicKey, finalizeEvent } from '../src/nostr/event.js';
import { verifyNostrAuth } from '../src/auth/nostr.js';
import { _clearProfileCacheForTests } from '../src/auth/cid-doc-fetch.js';

/** Compute the BIP-340 even-y JWK coordinates for an x-only Nostr pubkey. */
function evenYJwk(xOnlyHex) {
  const point = secp256k1.ProjectivePoint.fromHex('02' + xOnlyHex);
  const aff = point.toAffine();
  const xHex = aff.x.toString(16).padStart(64, '0');
  const yHex = aff.y.toString(16).padStart(64, '0');
  const b64u = (hex) => Buffer.from(hex, 'hex').toString('base64')
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  return { kty: 'EC', crv: 'secp256k1', alg: 'ES256K', x: b64u(xHex), y: b64u(yHex) };
}

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

function makeRequest({ method = 'GET', url, host = 'alice.example.com', mode = 'subdomain', extra = {} } = {}) {
  const fullUrl = url ?? `https://${host}/private/data.ttl`;
  const path = new URL(fullUrl).pathname;
  const base = {
    method,
    url: path,
    protocol: 'https',
    hostname: host,
    headers: { authorization: '', host, ...extra.headers },
  };
  if (mode === 'subdomain') {
    return {
      ...base,
      subdomainsEnabled: true,
      baseDomain: 'example.com',
      podName: host.split('.')[0] === 'example' ? null : host.split('.')[0],
    };
  }
  // Path mode (JSS default): no subdomains, pod is first URL segment.
  return { ...base, subdomainsEnabled: false };
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

// Path-mode equivalents (JSS's default deployment shape).
const PATH_HOST = 'example.com';
const PATH_PODNAME = 'alice';
const PATH_WEBID = `https://${PATH_HOST}/${PATH_PODNAME}/profile/card.jsonld#me`;
const PATH_DOC_URL = `https://${PATH_HOST}/${PATH_PODNAME}/profile/card.jsonld`;

function buildProfile({ pubkey, vmId = `${DOC_URL}#nostr-key-1`, withAuth = true, jwk = null, webId = WEBID } = {}) {
  const vm = jwk
    ? { id: vmId, type: 'JsonWebKey', controller: webId, publicKeyJwk: jwk }
    : { id: vmId, type: 'Multikey',  controller: webId,
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
    '@id': webId,
    controller: webId,
    verificationMethod: [vm],
    ...(withAuth ? { authentication: [vmId] } : {}),
  };
}

// --- fetch stub ------------------------------------------------------

const realFetch = global.fetch;
let nextProfile = null;
let nextStatus = 200;
let urlResponses = new Map();
let pathProfile = null;

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
    if (u === PATH_DOC_URL) {
      return new Response(JSON.stringify(pathProfile), {
        status: pathProfile ? 200 : 404,
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
    pathProfile = null;
    urlResponses = new Map();
    // Cache lives in cid-doc-fetch.js now and is shared with lws-cid.js;
    // must clear so a previous test's profile doesn't satisfy this one.
    _clearProfileCacheForTests();
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
    // Construct a real even-y JWK so the verifier's full-point match
    // succeeds (matching by x alone would be unsafe — see #400 pass 3).
    nextProfile = buildProfile({ pubkey: pk, jwk: evenYJwk(pk) });
    const url = `https://${POD_HOST}/private/data.ttl`;
    const { authHeader } = nip98Authorization({ method: 'GET', url, secretKey: sk });
    const req = makeRequest({ url });
    req.headers.authorization = authHeader;

    const r = await verifyNostrAuth(req);
    assert.strictEqual(r.error, null);
    assert.strictEqual(r.webId, WEBID);
  });

  it("rejects when CID document's subject differs from computed owner WebID", async () => {
    // Profile sits at the expected docUrl but declares a DIFFERENT
    // @id. Without the subject check, this would let an attacker
    // host a card.jsonld whose @id is "...#bob" + a Nostr VM under
    // bob's name, and trick us into authenticating as bob when the
    // request URL says alice.
    nextProfile = {
      ...buildProfile({ pubkey: pk }),
      '@id': `${DOC_URL}#bob`,
      controller: `${DOC_URL}#bob`,
    };
    const url = `https://${POD_HOST}/private/data.ttl`;
    const { authHeader } = nip98Authorization({ method: 'GET', url, secretKey: sk });
    const req = makeRequest({ url });
    req.headers.authorization = authHeader;

    const r = await verifyNostrAuth(req);
    // Falls back to did:nostr — VM lookup refused due to subject mismatch.
    assert.strictEqual(r.webId, `did:nostr:${pk}`);
  });

  it('rejects a JWK with the right x but wrong y (curve-point integrity)', async () => {
    const goodJwk = evenYJwk(pk);
    // Flip the y to invalid — same x, different y → not on canonical
    // BIP-340 point, so should NOT match the Nostr key.
    const badJwk = { ...goodJwk, y: goodJwk.y.slice(0, -1) + (goodJwk.y.endsWith('A') ? 'B' : 'A') };
    nextProfile = buildProfile({ pubkey: pk, jwk: badJwk });
    const url = `https://${POD_HOST}/private/data.ttl`;
    const { authHeader } = nip98Authorization({ method: 'GET', url, secretKey: sk });
    const req = makeRequest({ url });
    req.headers.authorization = authHeader;

    const r = await verifyNostrAuth(req);
    assert.strictEqual(r.webId, `did:nostr:${pk}`); // fell through to did:nostr
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

  it('upgrades did:nostr → WebID in single-user mode', async () => {
    // Single-user: one pod at the host root, WebID at /profile/card.jsonld#me.
    const SINGLE_HOST = 'pod.example.com';
    const SINGLE_DOC = `https://${SINGLE_HOST}/profile/card.jsonld`;
    const SINGLE_WEBID = `${SINGLE_DOC}#me`;
    urlResponses.set(SINGLE_DOC, {
      status: 200,
      headers: { 'content-type': 'application/ld+json' },
      body: JSON.stringify(buildProfile({
        pubkey: pk,
        vmId: `${SINGLE_DOC}#nostr-key-1`,
        webId: SINGLE_WEBID,
      })),
    });
    const url = `https://${SINGLE_HOST}/private/data.ttl`;
    const { authHeader } = nip98Authorization({ method: 'GET', url, secretKey: sk });
    const req = makeRequest({ url, host: SINGLE_HOST, mode: 'path' });
    req.singleUser = true;
    req.subdomainsEnabled = false;
    req.headers.authorization = authHeader;

    const r = await verifyNostrAuth(req);
    assert.strictEqual(r.error, null);
    assert.strictEqual(r.webId, SINGLE_WEBID);
  });

  it('upgrades did:nostr → WebID in single-user mode with a named pod', async () => {
    // singleUser=true + singleUserName='alice' mounts the pod at
    // /alice/, with WebID at /alice/profile/card.jsonld#me.
    const NAMED_HOST = 'pod.example.com';
    const NAMED_DOC = `https://${NAMED_HOST}/alice/profile/card.jsonld`;
    const NAMED_WEBID = `${NAMED_DOC}#me`;
    urlResponses.set(NAMED_DOC, {
      status: 200,
      headers: { 'content-type': 'application/ld+json' },
      body: JSON.stringify(buildProfile({
        pubkey: pk,
        vmId: `${NAMED_DOC}#nostr-key-1`,
        webId: NAMED_WEBID,
      })),
    });
    const url = `https://${NAMED_HOST}/alice/private/data.ttl`;
    const { authHeader } = nip98Authorization({ method: 'GET', url, secretKey: sk });
    const req = makeRequest({ url, host: NAMED_HOST, mode: 'path' });
    req.singleUser = true;
    req.singleUserName = 'alice';
    req.subdomainsEnabled = false;
    req.headers.authorization = authHeader;

    const r = await verifyNostrAuth(req);
    assert.strictEqual(r.error, null);
    assert.strictEqual(r.webId, NAMED_WEBID);
  });

  it('handles IPv6 literal host without crashing the host parser', async () => {
    // host.split(':')[0] would mangle '[::1]:3000' to '['. The
    // URL-aware parser must give a usable hostname instead of
    // crashing. Sign with the IPv6 host so the existing NIP-98
    // URL-match check passes — this test is about getPodOwnerWebId
    // not crashing, not about URL matching.
    const v6Host = '[2001:db8::1]:8443';
    const url = `https://${v6Host}/private/data.ttl`;
    const { authHeader } = nip98Authorization({ method: 'GET', url, secretKey: sk });
    const req = makeRequest({ url, host: v6Host, mode: 'path' });
    req.headers.authorization = authHeader;
    req.subdomainsEnabled = false;

    const r = await verifyNostrAuth(req);
    // No crash. The IPv6 path-mode WebID is malformed (a known
    // limitation matching JSS pod creation, see in-source comment),
    // so this falls back to did:nostr — that's the explicit
    // acceptable outcome.
    assert.strictEqual(r.error, null);
    assert.strictEqual(r.webId, `did:nostr:${pk}`);
  });

  it('handles host:port without breaking baseDomain match', async () => {
    // Subdomain-enabled deployment, request landed on base domain
    // with a port. The base-domain comparison must work when the
    // host carries a port — without port stripping, hostNoPort !==
    // baseDomain and the path-mode-on-base branch never matches.
    const PORT_HOST = 'example.com:8080';
    const SUB_HOST = 'alice.example.com';
    const SUB_DOC = `https://${SUB_HOST}/profile/card.jsonld`;
    const SUB_WEBID = `${SUB_DOC}#me`;
    urlResponses.set(SUB_DOC, {
      status: 200,
      headers: { 'content-type': 'application/ld+json' },
      body: JSON.stringify(buildProfile({
        pubkey: pk,
        vmId: `${SUB_DOC}#nostr-key-1`,
        webId: SUB_WEBID,
      })),
    });
    // Sign with the same host:port the request will carry, so the
    // existing NIP-98 URL-match check passes — this test is about the
    // base-domain comparison in WebID derivation, not URL matching.
    const url = `https://${PORT_HOST}/alice/private/data.ttl`;
    const { authHeader } = nip98Authorization({ method: 'GET', url, secretKey: sk });
    const req = makeRequest({ url, host: PORT_HOST, mode: 'subdomain' });
    // Hit the base domain (no podName).
    req.podName = null;
    req.headers.authorization = authHeader;

    const r = await verifyNostrAuth(req);
    assert.strictEqual(r.error, null);
    assert.strictEqual(r.webId, SUB_WEBID);
  });

  it('upgrades did:nostr → WebID in path mode even when host carries a port', async () => {
    // Reverse proxies forward Host with port (e.g. example.com:8080).
    // The computed ownerWebId must match what JSS stores at pod
    // creation, which uses request.hostname (port-stripped). Otherwise
    // the subject-identity check would reject valid requests.
    pathProfile = buildProfile({
      pubkey: pk,
      vmId: `${PATH_DOC_URL}#nostr-key-1`,
      webId: PATH_WEBID,
    });
    // Sign with the port-included URL so the existing NIP-98 URL-match
    // check passes — this test is about WebID derivation, not URL matching.
    const PORT_HOST = `${PATH_HOST}:8080`;
    const url = `https://${PORT_HOST}/${PATH_PODNAME}/private/data.ttl`;
    const { authHeader } = nip98Authorization({ method: 'GET', url, secretKey: sk });
    const req = makeRequest({ url, host: PORT_HOST, mode: 'path' });
    req.headers.authorization = authHeader;

    const r = await verifyNostrAuth(req);
    assert.strictEqual(r.error, null);
    assert.strictEqual(r.webId, PATH_WEBID); // canonical, port-stripped
  });

  it('upgrades did:nostr → WebID in path mode (subdomains disabled, JSS default)', async () => {
    // JSS's default deployment shape: pod is the first URL segment
    // and the WebID lives under that path.
    pathProfile = buildProfile({
      pubkey: pk,
      vmId: `${PATH_DOC_URL}#nostr-key-1`,
      webId: PATH_WEBID,
    });
    const url = `https://${PATH_HOST}/${PATH_PODNAME}/private/data.ttl`;
    const { authHeader } = nip98Authorization({ method: 'GET', url, secretKey: sk });
    const req = makeRequest({ url, host: PATH_HOST, mode: 'path' });
    req.headers.authorization = authHeader;

    const r = await verifyNostrAuth(req);
    assert.strictEqual(r.error, null);
    assert.strictEqual(r.webId, PATH_WEBID);
  });

  it('refuses cross-origin redirect during profile fetch (falls back to did:nostr)', async () => {
    // Pod-owner profile URL 302s to an attacker-controlled host. The
    // redirect must be refused regardless of where it points; the VM
    // lookup gets nothing and we fall through to did:nostr.
    urlResponses.set(DOC_URL, {
      status: 302,
      headers: { location: 'https://attacker.example/profile/card.jsonld' },
    });
    const url = `https://${POD_HOST}/private/data.ttl`;
    const { authHeader } = nip98Authorization({ method: 'GET', url, secretKey: sk });
    const req = makeRequest({ url });
    req.headers.authorization = authHeader;

    const r = await verifyNostrAuth(req);
    assert.strictEqual(r.error, null);
    assert.strictEqual(r.webId, `did:nostr:${pk}`);
  });

  it('refuses oversized profile bodies (falls back to did:nostr)', async () => {
    const huge = 'x'.repeat(300 * 1024);
    urlResponses.set(DOC_URL, {
      status: 200,
      headers: { 'content-type': 'application/ld+json' },
      body: JSON.stringify({ junk: huge }),
    });
    const url = `https://${POD_HOST}/private/data.ttl`;
    const { authHeader } = nip98Authorization({ method: 'GET', url, secretKey: sk });
    const req = makeRequest({ url });
    req.headers.authorization = authHeader;

    const r = await verifyNostrAuth(req);
    assert.strictEqual(r.webId, `did:nostr:${pk}`);
  });

  it('rejects malformed Host header (URL-injection defense)', async () => {
    // Host carries `@` which would steer the computed owner WebID at
    // attacker.com if we naively passed it through new URL().
    const url = `https://${POD_HOST}/private/data.ttl`;
    const { authHeader } = nip98Authorization({ method: 'GET', url, secretKey: sk });
    const req = makeRequest({ url });
    req.headers.authorization = authHeader;
    req.headers.host = `${POD_HOST}@attacker.example`;

    const r = await verifyNostrAuth(req);
    // The URL match runs first and rejects on the malformed host.
    assert.match(r.error, /invalid characters/);
  });

  it('lowercases x-forwarded-proto so HTTPS still matches profile @id', async () => {
    // Some proxies send `X-Forwarded-Proto: HTTPS` (uppercase). The
    // computed WebID must use the lowercase form so the subject-identity
    // check still matches a profile @id that uses lowercase `https://`.
    const url = `https://${POD_HOST}/private/data.ttl`;
    const { authHeader } = nip98Authorization({ method: 'GET', url, secretKey: sk });
    const req = makeRequest({ url });
    req.headers.authorization = authHeader;
    req.headers['x-forwarded-proto'] = 'HTTPS';

    const r = await verifyNostrAuth(req);
    assert.strictEqual(r.error, null);
    assert.strictEqual(r.webId, WEBID);
  });

  it('handles array-valued forwarded headers without throwing', async () => {
    // Fastify can yield x-forwarded-* as an array when duplicated.
    const url = `https://${POD_HOST}/private/data.ttl`;
    const { authHeader } = nip98Authorization({ method: 'GET', url, secretKey: sk });
    const req = makeRequest({ url });
    req.headers.authorization = authHeader;
    req.headers['x-forwarded-proto'] = ['https', 'http'];
    req.headers['x-forwarded-host'] = [POD_HOST, 'internal.lan'];

    const r = await verifyNostrAuth(req);
    assert.strictEqual(r.error, null);
    assert.strictEqual(r.webId, WEBID);
  });

  it('still rejects an invalid signature regardless of the profile', async () => {
    const url = `https://${POD_HOST}/private/data.ttl`;
    const { authHeader } = nip98Authorization({ method: 'GET', url, secretKey: sk });
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
