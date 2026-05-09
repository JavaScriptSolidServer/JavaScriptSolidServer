/**
 * LWS 1.0 Authentication Suite — Self-Signed Identity using Controlled Identifiers
 *
 * Implements the verifier side of the LWS10-CID FPWD (2026-04-23):
 *   https://www.w3.org/TR/2026/WD-lws10-authn-ssi-cid-20260423/
 *
 * The credential is a JWT (RFC7515 / RFC7519) signed with a JWS algorithm.
 * The verifier:
 *
 *   1. Reads `kid` from the JWT header. Per LWS10-CID, `kid` references a
 *      verificationMethod inside the subject's controlled identifier
 *      document — for a Solid pod, that document IS the WebID profile.
 *   2. Validates the FPWD §4 constraints: `sub === iss === client_id`
 *      (all the same WebID URI), `aud` includes the target server, `exp`
 *      not past, `iat` recent.
 *   3. Fetches the WebID profile, locates the verificationMethod by `kid`.
 *   4. Decodes its `publicKeyJwk`.
 *   5. Verifies the JWT signature per RFC7515 §5.2.
 *   6. Confirms the VM's `controller` matches the profile's declared
 *      controller (with fallback to @id) — same self-control rule the
 *      doctor's lws-cid validator uses on the client side.
 *   7. Returns the WebID as the authenticated identity.
 *
 * Design choices:
 *
 * - Detection is unambiguous: LWS-CID JWTs have a `kid` whose value is a
 *   URL with a fragment (the VM's `id`). IDP-issued JWTs (the existing
 *   `verifyJwtFromIdp` path) use opaque fingerprints. We route on shape.
 *
 * - secp256k1 / ES256K is the focus algorithm — same key Nostr users
 *   already have, signed as ECDSA for spec conformance. ES256 / EdDSA /
 *   RS256 also accepted; jose handles those natively.
 */

import * as jose from 'jose';
import { secp256k1 } from '@noble/curves/secp256k1';
import { sha256 } from '@noble/hashes/sha256';
import { fetchCidDocument, _clearProfileCacheForTests } from './cid-doc-fetch.js';

// Re-export for the existing test suite, which already calls this.
export { _clearProfileCacheForTests };

// JWS algorithms we accept. ES256K (RFC8812) is the primary target —
// secp256k1, the same curve as Nostr — but we support the common JWS
// algorithms too so other CID-document key shapes work out of the box.
const ACCEPTED_ALGS = new Set(['ES256K', 'ES256', 'ES384', 'EdDSA', 'RS256']);

// Maximum age for the iat (issued-at) claim, in seconds. JWT-as-HTTP-auth
// tokens are expected to be freshly minted; rejecting stale ones limits
// replay damage.
const MAX_IAT_AGE = 600; // 10 minutes

// Maximum allowed token lifetime (exp − iat). Auth tokens are short-lived
// by design; arbitrarily long-lived JWTs widen the replay window if a
// signed token leaks.
const MAX_LIFETIME = 3600; // 1 hour

// Clock skew tolerance for exp/nbf checks (seconds).
const CLOCK_SKEW = 60;

// Max profile body size — passed to the shared fetcher. CID documents
// are tiny in practice (~1-5 KB); 256 KB leaves plenty of headroom
// while bounding any DoS attempt. The cache itself lives in
// cid-doc-fetch.js so both this module and the NIP-98 path benefit.
const MAX_PROFILE_BYTES = 256 * 1024;

/**
 * Cheap detector — does this request carry an LWS-CID JWT?
 *
 * Routes a Bearer JWT to verifyLwsCidAuth only when it shows the
 * specific LWS-CID shape:
 *   - Authorization: Bearer <token>
 *   - token is a 3-part JWT
 *   - header.alg is one of our accepted JWS algorithms
 *   - header.kid is an http(s) URL with a fragment (which is what an
 *     LWS-CID verificationMethod id always looks like)
 *
 * Other JWS algs / non-URL kids fall through to the existing
 * IdP / simple-token paths in token.js — so this detector is
 * conservative on purpose.
 *
 * @param {object} request
 * @returns {boolean}
 */
export function hasLwsCidAuth(request) {
  const auth = request.headers?.authorization;
  if (!auth || typeof auth !== 'string' || !auth.startsWith('Bearer ')) return false;
  const token = auth.slice(7).trim();
  const parts = token.split('.');
  if (parts.length !== 3) return false;
  try {
    const header = JSON.parse(b64uDecode(parts[0]).toString('utf8'));
    if (!header) return false;
    if (typeof header.alg !== 'string' || !ACCEPTED_ALGS.has(header.alg)) return false;
    if (typeof header.kid !== 'string') return false;
    const u = new URL(header.kid);
    if (u.protocol !== 'https:' && u.protocol !== 'http:') return false;
    return Boolean(u.hash); // LWS-CID kid is always a fragment URI
  } catch {
    return false;
  }
}

/**
 * Verify an LWS-CID JWT and return the authenticated WebID.
 *
 * @param {object} request
 * @returns {Promise<{webId: string|null, error: string|null}>}
 */
export async function verifyLwsCidAuth(request) {
  const auth = request.headers?.authorization;
  if (!auth || !auth.startsWith('Bearer ')) {
    return { webId: null, error: 'missing Bearer token' };
  }
  const token = auth.slice(7).trim();

  // Decode header + payload without verifying so we can pick the key.
  let header, payload;
  try {
    header = jose.decodeProtectedHeader(token);
    payload = jose.decodeJwt(token);
  } catch (err) {
    return { webId: null, error: `malformed JWT: ${err.message}` };
  }

  if (typeof header.alg !== 'string' || header.alg.length === 0) {
    return { webId: null, error: 'JWT header missing alg' };
  }
  if (header.alg === 'none') {
    return { webId: null, error: 'JWT MUST NOT use "none" as the signing algorithm' };
  }
  if (!ACCEPTED_ALGS.has(header.alg)) {
    return { webId: null, error: `unsupported alg: ${header.alg}` };
  }
  if (typeof header.kid !== 'string' || !header.kid) {
    return { webId: null, error: 'missing kid' };
  }
  let kidUrl;
  try {
    kidUrl = new URL(header.kid);
  } catch {
    return { webId: null, error: 'kid is not a URL' };
  }
  if (!kidUrl.hash) {
    return { webId: null, error: 'kid must be a fragment URI within a CID document' };
  }
  // Normalize kid via the URL parser's canonicalization (case-folded
  // scheme/host, default-port stripped, percent-encoded path) so all
  // downstream comparisons against absolutized VM ids and proof-purpose
  // refs operate on canonical strings. Otherwise a semantically
  // equivalent but non-canonical kid in the JWT header would fail to
  // match the profile's id values.
  const kid = kidUrl.toString();

  // Auth credentials over plaintext HTTP are a non-starter — fail loud
  // and early with a clear error rather than letting the request limp
  // along to a generic "could not fetch / SSRF protection" failure
  // downstream. (The SSRF guard still has its own production check as
  // defense-in-depth.)
  if (kidUrl.protocol !== 'https:') {
    return { webId: null, error: 'kid must use https' };
  }

  // FPWD §4: sub === iss === client_id, all the same WebID URI.
  // Compare canonicalized forms so semantically equal but textually
  // different URIs (different case, default ports written out, etc.)
  // pass equality. The canonical form is also what we hand back to
  // callers — WAC and other downstream consumers do string equality on
  // the WebID, so handing them a non-canonical form would fail to
  // match ACL agent entries.
  const { sub, iss, client_id, aud, exp, iat, nbf } = payload;
  if (!sub || !iss || !client_id) {
    return { webId: null, error: 'JWT missing sub/iss/client_id' };
  }
  let webId, canonicalIss, canonicalClientId;
  try {
    webId = new URL(sub).toString();
    canonicalIss = new URL(iss).toString();
    canonicalClientId = new URL(client_id).toString();
  } catch (err) {
    return { webId: null, error: `invalid sub/iss/client_id URI: ${err.message}` };
  }
  if (webId !== canonicalIss || webId !== canonicalClientId) {
    return { webId: null, error: 'sub, iss, and client_id MUST all use the same URI value' };
  }

  // The kid's document URL must match the WebID's document URL — the VM
  // lives inside the subject's CID document.
  const kidDoc = stripHash(kid);
  const webIdDoc = stripHash(webId);
  if (kidDoc !== webIdDoc) {
    return {
      webId: null,
      error: `kid (${kid}) is not in the subject's CID document (${webIdDoc})`,
    };
  }

  // Time-claim validation. The ES256K branch below skips jose.jwtVerify
  // and relies on these checks alone, so each claim's TYPE matters as
  // much as its value — `exp: "9999999999"` (string) must NOT be
  // silently accepted as a number.
  //
  // Per FPWD §4, both iat and exp are MUST; nbf is optional but enforced
  // when present. We additionally cap the lifetime (exp − iat) to bound
  // the replay window if a signed token leaks.
  if (typeof exp !== 'number') {
    return { webId: null, error: 'JWT exp claim is required and must be a number' };
  }
  if (typeof iat !== 'number') {
    return { webId: null, error: 'JWT iat claim is required and must be a number' };
  }
  if (nbf !== undefined && typeof nbf !== 'number') {
    return { webId: null, error: 'JWT nbf claim must be a number' };
  }
  const now = Math.floor(Date.now() / 1000);
  if (now > exp + CLOCK_SKEW) {
    return { webId: null, error: 'JWT expired' };
  }
  if (typeof nbf === 'number' && now + CLOCK_SKEW < nbf) {
    return { webId: null, error: 'JWT not yet valid (nbf in the future)' };
  }
  if (now - iat > MAX_IAT_AGE + CLOCK_SKEW) {
    return { webId: null, error: 'JWT iat too old' };
  }
  if (iat - now > CLOCK_SKEW) {
    return { webId: null, error: 'JWT iat is in the future' };
  }
  if (exp - iat > MAX_LIFETIME) {
    return {
      webId: null,
      error: `JWT lifetime exceeds maximum (${exp - iat}s > ${MAX_LIFETIME}s)`,
    };
  }
  if (exp <= iat) {
    return { webId: null, error: 'JWT exp must be after iat' };
  }

  // Audience check — `aud` is required (FPWD §4: "the aud claim MUST
  // include the target authorization server"), and the request's
  // origin must appear in it.
  const reqOrigin = getRequestOrigin(request);
  const audList = aud === undefined ? [] : Array.isArray(aud) ? aud : [aud];
  if (audList.length === 0) {
    return { webId: null, error: 'JWT aud claim is required' };
  }
  if (!reqOrigin) {
    // We can't determine our own origin, so we can't verify aud. Per
    // FPWD, aud MUST include the target server — failing closed is
    // safer than silently accepting any aud value.
    return {
      webId: null,
      error: 'cannot determine server origin to verify aud',
    };
  }
  const audMatch = audList.some((a) => normalizeOrigin(a) === reqOrigin);
  if (!audMatch) {
    return {
      webId: null,
      error: `aud does not include this server's origin (${reqOrigin})`,
    };
  }

  // Fetch the CID document (= WebID profile) and locate the VM by kid.
  let profile;
  try {
    profile = await fetchProfile(webIdDoc);
  } catch (err) {
    return { webId: null, error: `could not fetch CID document: ${err.message}` };
  }
  if (!profile || typeof profile !== 'object' || Array.isArray(profile)) {
    return { webId: null, error: 'CID document is not a JSON object' };
  }

  // Subject-identity check. The CID document we just fetched MUST
  // actually identify itself as the JWT's `sub`. Without this, a doc
  // hosted at the same URL could declare itself to be a different
  // WebID fragment, but reuse a verificationMethod controlled by
  // another node — and we'd authenticate as `sub` based on the wrong
  // VM's signature.
  const profileSubject = absolutize(profile['@id'] ?? profile.id, webIdDoc);
  if (!profileSubject) {
    return {
      webId: null,
      error: 'CID document declares no subject (@id / id)',
    };
  }
  if (profileSubject !== webId) {
    return {
      webId: null,
      error: `CID document subject (${profileSubject}) does not match JWT sub (${webId})`,
    };
  }

  const vm = findVerificationMethod(profile, kid, webIdDoc);
  if (!vm) {
    return {
      webId: null,
      error: `no verificationMethod with id ${kid} in CID document`,
    };
  }

  // VM must be referenced by `authentication` to be usable as an auth
  // credential. (CID 1.0 §3.3)
  if (!isInProofPurpose(profile, 'authentication', kid, webIdDoc)) {
    return {
      webId: null,
      error: `verificationMethod ${kid} is not listed in authentication`,
    };
  }

  // Confirm the VM's controller agrees with the profile's controller
  // (or with @id on fallback). Self-controlled is the common case. A
  // profile with no controller / @id / id at all is malformed — fail
  // closed rather than letting the VM controller check pass vacuously.
  const expectedCtrls = normalizeControllers(profile.controller ?? profile['@id'] ?? profile.id, webIdDoc);
  if (expectedCtrls.length === 0) {
    return {
      webId: null,
      error: 'CID document has no controller or @id — controller check cannot proceed',
    };
  }
  const vmCtrls = normalizeControllers(vm.controller, webIdDoc);
  const matched = vmCtrls.some((c) => expectedCtrls.includes(c));
  if (!matched) {
    return {
      webId: null,
      error: 'verificationMethod controller does not match profile controller',
    };
  }

  // Decode the JWK and verify the signature.
  if (!vm.publicKeyJwk || typeof vm.publicKeyJwk !== 'object') {
    return {
      webId: null,
      error: 'verificationMethod has no publicKeyJwk (Multikey-only VMs not yet handled here)',
    };
  }
  const jwk = vm.publicKeyJwk;

  try {
    if (header.alg === 'ES256K') {
      // jose's Web Crypto path doesn't support secp256k1 in all
      // environments. Verify with @noble/curves directly — same primitive
      // we already use for Schnorr in the Nostr path.
      await verifyEs256kJwt(token, jwk);
    } else {
      const key = await jose.importJWK(jwk, header.alg);
      await jose.jwtVerify(token, key, {
        algorithms: [header.alg],
        clockTolerance: CLOCK_SKEW,
      });
    }
  } catch (err) {
    return { webId: null, error: `signature verification failed: ${err.message}` };
  }

  return { webId, error: null };
}

// ---------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------

function b64uDecode(s) {
  return Buffer.from(s.replace(/-/g, '+').replace(/_/g, '/'), 'base64');
}

function stripHash(u) {
  if (typeof u !== 'string') return u;
  try {
    const url = new URL(u);
    url.hash = '';
    return url.toString();
  } catch {
    return u.split('#')[0];
  }
}

function getRequestOrigin(request) {
  // Behind a reverse proxy, the front-end forwarded headers are the
  // authoritative source. Match the convention used in src/ap/* and
  // similar code: x-forwarded-* take precedence, fall back to fastify's
  // protocol/hostname.
  //
  // Multi-proxy chains may produce comma-separated lists (e.g.
  // `x-forwarded-host: a.example, b.internal`); the leftmost value is
  // the original client-facing front-end, which is what we want.
  //
  // The result is run through normalizeOrigin so default ports and
  // case folding match the audList comparison side.
  const headers = request.headers || {};
  const proto = firstHeaderValue(headers['x-forwarded-proto']) || request.protocol || 'https';
  const host  = firstHeaderValue(headers['x-forwarded-host']) || headers.host || request.hostname;
  if (!host) return null;
  return normalizeOrigin(`${proto}://${host}`);
}

function firstHeaderValue(v) {
  if (!v) return null;
  // Fastify can yield a string, an array, or undefined.
  const s = Array.isArray(v) ? v[0] : v;
  if (typeof s !== 'string') return null;
  const first = s.split(',')[0].trim();
  return first || null;
}

function normalizeOrigin(s) {
  if (typeof s !== 'string') return null;
  try {
    const u = new URL(s);
    return `${u.protocol}//${u.host}`;
  } catch {
    return s;
  }
}

/**
 * Fetch the CID document. Delegates to the shared `fetchCidDocument`
 * helper which handles SSRF / redirects / body cap AND a bounded TTL
 * cache (see src/auth/cid-doc-fetch.js).
 */
async function fetchProfile(docUrl) {
  return fetchCidDocument(docUrl, { maxBytes: MAX_PROFILE_BYTES });
}

function findVerificationMethod(profile, kid, baseUrl) {
  const vms = asArray(profile.verificationMethod);
  for (const vm of vms) {
    if (!vm || typeof vm !== 'object') continue;
    const vmId = vm.id || vm['@id'];
    if (!vmId) continue;
    if (absolutize(vmId, baseUrl) === kid) return vm;
  }
  return null;
}

function isInProofPurpose(profile, predicate, kid, baseUrl) {
  const entries = asArray(profile[predicate]);
  if (entries.length === 0) return false;
  for (const ent of entries) {
    if (typeof ent === 'string') {
      if (absolutize(ent, baseUrl) === kid) return true;
    } else if (ent && typeof ent === 'object') {
      const id = ent['@id'] ?? ent.id;
      if (id && absolutize(id, baseUrl) === kid) return true;
    }
  }
  return false;
}

function normalizeControllers(value, baseUrl) {
  if (value === undefined || value === null) return [];
  const list = Array.isArray(value) ? value : [value];
  const out = [];
  for (const v of list) {
    let iri;
    if (typeof v === 'string') iri = v;
    else if (v && typeof v === 'object') iri = v['@id'] ?? v.id;
    if (typeof iri !== 'string' || iri.length === 0) continue;
    out.push(absolutize(iri, baseUrl));
  }
  return out;
}

function asArray(v) {
  if (v === undefined || v === null) return [];
  return Array.isArray(v) ? v : [v];
}

function absolutize(u, base) {
  if (!u) return u;
  try {
    return new URL(u, base).toString();
  } catch {
    return u;
  }
}

/**
 * Verify a JWT signed with ES256K (ECDSA over secp256k1) using
 * @noble/curves. Returns on success, throws on failure.
 *
 * Web Crypto / jose lack uniform secp256k1 support across Node versions,
 * and this primitive is already in tree (used by NIP-98 / Nostr). The
 * curve (secp256k1) is the same one Nostr keys live on, so a Nostr
 * private key can sign here without any new key material.
 */
async function verifyEs256kJwt(token, jwk) {
  if (jwk.kty !== 'EC' || (jwk.crv !== 'secp256k1' && jwk.crv !== 'P-256K')) {
    throw new Error(`ES256K requires kty:EC and crv:secp256k1 (or legacy crv:P-256K), got kty:${jwk.kty} crv:${jwk.crv}`);
  }
  if (typeof jwk.x !== 'string' || typeof jwk.y !== 'string') {
    throw new Error('JWK missing x/y coordinates');
  }
  // Build the uncompressed SEC1 public point: 0x04 || x || y
  const x = b64uDecode(jwk.x);
  const y = b64uDecode(jwk.y);
  if (x.length !== 32 || y.length !== 32) {
    throw new Error(`secp256k1 coordinates must be 32 bytes; got x=${x.length} y=${y.length}`);
  }
  const pub = Buffer.concat([Buffer.from([0x04]), x, y]);

  const [headerB64, payloadB64, sigB64] = token.split('.');
  const signingInput = Buffer.from(`${headerB64}.${payloadB64}`, 'utf8');
  const sigRaw = b64uDecode(sigB64);
  if (sigRaw.length !== 64) {
    throw new Error(`ES256K signature must be 64 bytes (r||s); got ${sigRaw.length}`);
  }

  const msgHash = sha256(signingInput);
  const sig = secp256k1.Signature.fromCompact(sigRaw);
  const ok = secp256k1.verify(sig, msgHash, pub);
  if (!ok) throw new Error('signature is not valid');
}
