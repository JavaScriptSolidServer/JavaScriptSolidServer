/**
 * NIP-01 / NIP-98 event utilities.
 *
 * Pure-JS Nostr event validation and Schnorr verification using
 * `@noble/curves` (already a direct dependency, audited by Trail of
 * Bits) and Node's built-in `crypto` for SHA-256. Replaces the
 * `nostr-tools` dependency tree we previously pulled just for two
 * functions (#135).
 *
 * Exports a minimal, drop-in surface: `getEventHash`, `validateEvent`,
 * `verifyEvent`. Both `src/auth/nostr.js` (NIP-98 HTTP auth) and
 * `src/nostr/relay.js` (in-process relay) consume this module.
 */

import { schnorr } from '@noble/curves/secp256k1';
import { createHash } from 'node:crypto';

const HEX_64 = /^[a-f0-9]{64}$/;
const HEX_128 = /^[a-f0-9]{128}$/;

/**
 * Compute the canonical NIP-01 event id.
 * Per NIP-01 the id is `sha256(JSON.stringify([0, pubkey, created_at,
 * kind, tags, content]))` with no whitespace, hex-encoded.
 *
 * @param {object} event - Event with pubkey/created_at/kind/tags/content
 * @returns {string} 64-char lowercase hex sha256 digest
 */
export function getEventHash(event) {
  const serialized = JSON.stringify([
    0,
    event.pubkey,
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
  if (!Number.isInteger(event.kind) || event.kind < 0 || event.kind > 65535) return false;
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
  if (event.id !== getEventHash(event)) return false;
  try {
    return schnorr.verify(event.sig, event.id, event.pubkey);
  } catch {
    return false;
  }
}
