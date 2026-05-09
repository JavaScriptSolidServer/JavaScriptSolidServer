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

// JWS algorithms we accept. ES256K (RFC8812) is the primary target —
// secp256k1, the same curve as Nostr — but we support the common JWS
// algorithms too so other CID-document key shapes work out of the box.
const ACCEPTED_ALGS = new Set(['ES256K', 'ES256', 'ES384', 'EdDSA', 'RS256']);

// Maximum age for the iat (issued-at) claim, in seconds. JWT-as-HTTP-auth
// tokens are expected to be freshly minted; rejecting stale ones limits
// replay if an exp claim is sloppy or absent.
const MAX_IAT_AGE = 600; // 10 minutes

// Clock skew tolerance for exp/nbf checks (seconds).
const CLOCK_SKEW = 60;

/**
 * Cheap detector — does this request carry an LWS-CID JWT?
 *
 * True when:
 *   - Authorization: Bearer <token>
 *   - token is a 3-part JWT
 *   - header.kid is a URL with a fragment (which is what an LWS-CID
 *     verificationMethod id always looks like)
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
    if (!header || typeof header.kid !== 'string') return false;
    const u = new URL(header.kid);
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

  if (!header.alg || header.alg === 'none') {
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

  // FPWD §4: sub === iss === client_id, all the same WebID URI.
  const { sub, iss, client_id, aud, exp, iat } = payload;
  if (!sub || !iss || !client_id) {
    return { webId: null, error: 'JWT missing sub/iss/client_id' };
  }
  if (sub !== iss || sub !== client_id) {
    return { webId: null, error: 'sub, iss, and client_id MUST all use the same URI value' };
  }
  const webId = sub;

  // The kid's document URL must match the WebID's document URL — the VM
  // lives inside the subject's CID document.
  const kidDoc = stripHash(header.kid);
  const webIdDoc = stripHash(webId);
  if (kidDoc !== webIdDoc) {
    return {
      webId: null,
      error: `kid (${header.kid}) is not in the subject's CID document (${webIdDoc})`,
    };
  }

  // Time checks.
  const now = Math.floor(Date.now() / 1000);
  if (typeof exp === 'number' && now > exp + CLOCK_SKEW) {
    return { webId: null, error: 'JWT expired' };
  }
  if (typeof iat === 'number' && now - iat > MAX_IAT_AGE + CLOCK_SKEW) {
    return { webId: null, error: 'JWT iat too old' };
  }
  if (typeof iat !== 'number' && typeof exp !== 'number') {
    return { webId: null, error: 'JWT missing both iat and exp' };
  }

  // Audience check — the request's origin must be in aud.
  const reqOrigin = getRequestOrigin(request);
  if (reqOrigin) {
    const audList = aud === undefined ? [] : Array.isArray(aud) ? aud : [aud];
    const audMatch = audList.some((a) => normalizeOrigin(a) === reqOrigin);
    if (audList.length > 0 && !audMatch) {
      return {
        webId: null,
        error: `aud does not include this server's origin (${reqOrigin})`,
      };
    }
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

  const vm = findVerificationMethod(profile, header.kid, webIdDoc);
  if (!vm) {
    return {
      webId: null,
      error: `no verificationMethod with id ${header.kid} in CID document`,
    };
  }

  // VM must be referenced by `authentication` to be usable as an auth
  // credential. (CID 1.0 §3.3)
  if (!isInProofPurpose(profile, 'authentication', vm, header.kid, webIdDoc)) {
    return {
      webId: null,
      error: `verificationMethod ${header.kid} is not listed in authentication`,
    };
  }

  // Confirm the VM's controller agrees with the profile's controller (or
  // with @id on fallback). Self-controlled is the common case.
  const expectedCtrls = normalizeControllers(profile.controller ?? profile['@id'] ?? profile.id, webIdDoc);
  const vmCtrls = normalizeControllers(vm.controller, webIdDoc);
  if (expectedCtrls.length > 0) {
    const matched = vmCtrls.some((c) => expectedCtrls.includes(c));
    if (!matched) {
      return {
        webId: null,
        error: `verificationMethod controller does not match profile controller`,
      };
    }
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
  const host = request.headers?.host;
  if (!host) return null;
  const proto = request.protocol || (request.headers?.['x-forwarded-proto']) || 'https';
  return `${proto}://${host}`;
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

async function fetchProfile(docUrl) {
  // 5s timeout — profiles are small static documents.
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 5000);
  try {
    const res = await fetch(docUrl, {
      headers: { Accept: 'application/ld+json' },
      signal: controller.signal,
    });
    if (!res.ok) {
      throw new Error(`HTTP ${res.status}`);
    }
    const text = await res.text();
    return JSON.parse(text);
  } finally {
    clearTimeout(timer);
  }
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

function isInProofPurpose(profile, predicate, vm, kid, baseUrl) {
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
    throw new Error(`ES256K requires kty:EC crv:secp256k1, got kty:${jwk.kty} crv:${jwk.crv}`);
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
