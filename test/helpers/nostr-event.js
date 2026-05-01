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
import { randomBytes } from 'node:crypto';
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
