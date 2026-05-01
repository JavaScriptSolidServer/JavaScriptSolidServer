/**
 * Test-only Nostr event signing/key helpers.
 *
 * Production code only needs to *verify* events (`src/nostr/event.js`).
 * Tests sometimes need to *generate* keys and sign events so they can
 * exercise the verifier with realistic inputs. This file gives them a
 * thin local stand-in for `nostr-tools`'s `generateSecretKey`,
 * `getPublicKey`, and `finalizeEvent`, built on the same audited
 * `@noble/curves` Schnorr that production uses (#135).
 */

import { schnorr, secp256k1 } from '@noble/curves/secp256k1';
import { createHash, randomBytes } from 'node:crypto';
import { getEventHash } from '../../src/nostr/event.js';

/** Generate a random 32-byte secp256k1 private key. */
export function generateSecretKey() {
  // Match the rest of the repo (see src/handlers/pay.js) which uses
  // `secp256k1.utils.randomPrivateKey()`. Fall back to `crypto.randomBytes`
  // only if that surface ever changes in @noble/curves.
  if (secp256k1.utils?.randomPrivateKey) {
    return secp256k1.utils.randomPrivateKey();
  }
  return new Uint8Array(randomBytes(32));
}

/** Derive the BIP-340 x-only public key, returned as 64-char lowercase hex. */
export function getPublicKey(secretKey) {
  return Buffer.from(schnorr.getPublicKey(secretKey)).toString('hex');
}

/**
 * Take a partial Nostr event, compute its NIP-01 id, sign it, and
 * return the finalized event ready to be sent over NIP-98 / a relay.
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
 * Equivalent to `nostr-tools/nip98`'s `getToken()` for our purposes.
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
