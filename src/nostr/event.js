/**
 * NIP-01 / NIP-98 event utilities — verifier and signer.
 *
 * Pure-JS Nostr event tools using `@noble/curves` (a direct dependency,
 * audited by Trail of Bits) and Node's built-in `crypto` for SHA-256.
 * Replaces the `nostr-tools` dependency tree we previously pulled just
 * for a few functions (#135).
 *
 * Verifier surface (used by production):
 *   - `getEventHash`, `validateEvent`, `verifyEvent`
 *   - consumed by `src/auth/nostr.js` (NIP-98 HTTP auth) and
 *     `src/nostr/relay.js` (in-process relay).
 *
 * Signer surface (used by integration tests + dev scripts):
 *   - `generateSecretKey`, `getPublicKey`, `finalizeEvent`, `nip98Token`
 *   - consumed by `test/*.js` and the repo-root `*.mjs`/`test-*.js`
 *     dev scripts. Living in `src/` rather than `test/helpers/` so
 *     non-test consumers don't reach into test-only code paths.
 */

import { schnorr, secp256k1 } from '@noble/curves/secp256k1';
import { createHash } from 'node:crypto';

// Hex is canonically lowercase in NIP-01/BIP-340 examples, but be lenient
// on input — accepting uppercase keeps interop with implementations that
// happen to emit either case. We normalize to lowercase for the hash
// comparison below.
const HEX_64 = /^[a-fA-F0-9]{64}$/;
const HEX_128 = /^[a-fA-F0-9]{128}$/;

/**
 * Compute the canonical NIP-01 event id.
 * Per NIP-01 the id is `sha256(JSON.stringify([0, pubkey, created_at,
 * kind, tags, content]))` with no whitespace, hex-encoded.
 *
 * `pubkey` is lowercased before serialization so the same id is produced
 * regardless of input case — keeps callers (including the "id missing"
 * branch in src/auth/nostr.js) consistent with `verifyEvent`'s
 * lowercase-normalized hash compare.
 *
 * @param {object} event - Event with pubkey/created_at/kind/tags/content
 * @returns {string} 64-char lowercase hex sha256 digest
 */
export function getEventHash(event) {
  const pubkey = typeof event.pubkey === 'string'
    ? event.pubkey.toLowerCase()
    : event.pubkey;
  const serialized = JSON.stringify([
    0,
    pubkey,
    event.created_at,
    event.kind,
    event.tags,
    event.content
  ]);
  return createHash('sha256').update(serialized, 'utf8').digest('hex');
}

/**
 * Structural validation — does the object have the shape required of a
 * NIP-01 event? Doesn't compute the hash or verify the signature.
 */
export function validateEvent(event) {
  if (!event || typeof event !== 'object' || Array.isArray(event)) return false;
  if (typeof event.id !== 'string' || !HEX_64.test(event.id)) return false;
  if (typeof event.pubkey !== 'string' || !HEX_64.test(event.pubkey)) return false;
  if (typeof event.sig !== 'string' || !HEX_128.test(event.sig)) return false;
  // NIP-01 doesn't cap kinds at 16 bits — many real kinds (10002, 30023,
  // etc.) are above 65535. Accept any non-negative safe integer.
  if (!Number.isSafeInteger(event.kind) || event.kind < 0) return false;
  if (!Number.isInteger(event.created_at) || event.created_at < 0) return false;
  if (typeof event.content !== 'string') return false;
  if (!Array.isArray(event.tags)) return false;
  for (const tag of event.tags) {
    if (!Array.isArray(tag)) return false;
    for (const v of tag) if (typeof v !== 'string') return false;
  }
  return true;
}

/**
 * Full event verification: passes structural validation AND the
 * declared `id` matches the recomputed hash AND the Schnorr signature
 * (BIP-340) is valid for that id under `pubkey`.
 *
 * Returns `true` only on full success; any failure or thrown crypto
 * error becomes `false` so callers don't have to wrap in try/catch.
 */
export function verifyEvent(event) {
  if (!validateEvent(event)) return false;
  // Compare the declared id (normalized to lowercase) against the
  // canonical hash. `getEventHash` itself lowercases pubkey, so the
  // caller's casing doesn't matter for the hash compare.
  if (event.id.toLowerCase() !== getEventHash(event)) return false;
  try {
    return schnorr.verify(event.sig, event.id, event.pubkey);
  } catch {
    return false;
  }
}

// ---------------------------------------------------------------------
// Signer-side helpers
// ---------------------------------------------------------------------

/**
 * Generate a random 32-byte secp256k1 private key.
 *
 * Always uses `secp256k1.utils.randomPrivateKey()` so the result is
 * guaranteed to be in [1, n-1] (a valid secp256k1 scalar). A naive
 * `crypto.randomBytes(32)` fallback would have a vanishing-but-nonzero
 * chance of producing 0 or a value >= curve order, which would manifest
 * as flaky signing/verification.
 */
export function generateSecretKey() {
  if (!secp256k1.utils?.randomPrivateKey) {
    throw new Error('secp256k1.utils.randomPrivateKey is unavailable');
  }
  return secp256k1.utils.randomPrivateKey();
}

/**
 * Derive the BIP-340 x-only public key as 64-char lowercase hex.
 */
export function getPublicKey(secretKey) {
  return Buffer.from(schnorr.getPublicKey(secretKey)).toString('hex');
}

/**
 * Take a partial Nostr event, compute its NIP-01 id, sign it with the
 * given secret key, and return the finalized event.
 *
 * @param {object} template - {kind, tags?, content?, created_at?}
 * @param {Uint8Array|string} secretKey
 */
export function finalizeEvent(template, secretKey) {
  const pubkey = getPublicKey(secretKey);
  const event = {
    pubkey,
    created_at: template.created_at ?? Math.floor(Date.now() / 1000),
    kind: template.kind,
    tags: template.tags ?? [],
    content: template.content ?? ''
  };
  event.id = getEventHash(event);
  event.sig = Buffer.from(schnorr.sign(event.id, secretKey)).toString('hex');
  return event;
}

/**
 * Build a NIP-98 HTTP auth header value (the part after `Nostr `):
 * a kind-27235 event signed with `secretKey`, base64-encoded.
 *
 * @param {string} url - Full request URL (becomes the `u` tag)
 * @param {string} method - HTTP method (becomes the `method` tag, uppercased)
 * @param {Uint8Array|string} secretKey - 32-byte secret key
 * @param {object|string|null} [body] - Optional request body; if present
 *   the SHA-256 hex hash is added as a `payload` tag per NIP-98.
 * @returns {string} base64-encoded signed event
 */
export function nip98Token(url, method, secretKey, body = null) {
  const tags = [
    ['u', url],
    ['method', method.toUpperCase()]
  ];
  if (body !== null && body !== undefined) {
    const bytes = typeof body === 'string'
      ? Buffer.from(body, 'utf8')
      : Buffer.from(JSON.stringify(body), 'utf8');
    const hash = createHash('sha256').update(bytes).digest('hex');
    tags.push(['payload', hash]);
  }
  const event = finalizeEvent({ kind: 27235, tags, content: '' }, secretKey);
  return Buffer.from(JSON.stringify(event)).toString('base64');
}
