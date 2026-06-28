/**
 * Parity consistency across the two Nostr verification-method decoders
 * (#571).
 *
 * The did:nostr spec (https://nostrcg.github.io/did-nostr/) allows BOTH
 * parity prefixes for the same x-only identity: "Nostr applications may
 * generate keys with either 0x02 or 0x03 prefixes." So:
 *
 *   - the f-form Multikey decoder accepts 02 and 03 (parity discarded,
 *     x is the identity), and
 *   - the JWK path accepts an even-Y *or* odd-Y on-curve point,
 *
 * but both still reject a fabricated/off-curve y. These tests pin that
 * the two paths agree.
 */

import { describe, it } from 'node:test';
import assert from 'node:assert';
import { secp256k1 } from '@noble/curves/secp256k1';
import {
  decodeFFormSecp256k1,
  pubkeyFromValidatedJwk,
  nostrJwkYParities,
  extractNostrPubkeysFromProfile,
} from '../src/auth/nostr-keys.js';

const b64u = (hex) => Buffer.from(hex, 'hex').toString('base64')
  .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

/** A real x-only Nostr pubkey (x with a valid even-Y point). */
const X = '124c0fa99407182ece5a24fad9b7f6674902fc422843d3128d38a0afbee0fdd2';

function jwkFor(xHex, parity) {
  const point = secp256k1.ProjectivePoint.fromHex(parity + xHex).toAffine();
  return {
    kty: 'EC', crv: 'secp256k1', alg: 'ES256K',
    x: b64u(point.x.toString(16).padStart(64, '0')),
    y: b64u(point.y.toString(16).padStart(64, '0')),
  };
}

const fform = (xHex, parity) => 'f' + 'e701' + parity + xHex.toLowerCase();

describe('Nostr key parity consistency (#571)', () => {
  it('f-form Multikey decoder accepts both 02 and 03, returning the same x', () => {
    assert.strictEqual(decodeFFormSecp256k1(fform(X, '02')), X);
    assert.strictEqual(decodeFFormSecp256k1(fform(X, '03')), X);
  });

  it('f-form decoder rejects a non-parity prefix byte', () => {
    assert.strictEqual(decodeFFormSecp256k1(fform(X, '04')), null);
  });

  it('JWK path accepts an even-Y point and returns x', () => {
    assert.strictEqual(pubkeyFromValidatedJwk(jwkFor(X, '02')), X);
  });

  it('JWK path now also accepts an odd-Y point and returns the same x', () => {
    assert.strictEqual(pubkeyFromValidatedJwk(jwkFor(X, '03')), X);
  });

  it('JWK path still rejects a fabricated off-curve y', () => {
    const bad = jwkFor(X, '02');
    // Flip the low bit of y → no longer the genuine even-Y coordinate
    // (and not the odd-Y one either), so it must be rejected.
    const yHex = Buffer.from(bad.y.replace(/-/g, '+').replace(/_/g, '/'), 'base64')
      .toString('hex');
    const flipped = (BigInt('0x' + yHex) ^ 1n).toString(16).padStart(64, '0');
    bad.y = b64u(flipped);
    assert.strictEqual(pubkeyFromValidatedJwk(bad), null);
  });

  it('nostrJwkYParities returns both genuine y values and null for a bad x', () => {
    const ys = nostrJwkYParities(X);
    assert.ok(Array.isArray(ys) && ys.length === 2);
    assert.notStrictEqual(ys[0], ys[1]);
    assert.strictEqual(nostrJwkYParities('zz'), null);
    assert.strictEqual(nostrJwkYParities(42), null);
  });

  it('nostrJwkYParities normalizes uppercase hex (matches the lowercase result)', () => {
    assert.deepStrictEqual(nostrJwkYParities(X.toUpperCase()), nostrJwkYParities(X));
  });

  it('profile extraction maps a 03 Multikey and a 03 JWK to the same identity', () => {
    const profile = {
      verificationMethod: [
        { id: '#mk', type: 'Multikey', publicKeyMultibase: fform(X, '03') },
        { id: '#jwk', type: 'JsonWebKey', publicKeyJwk: jwkFor(X, '03') },
      ],
    };
    const found = extractNostrPubkeysFromProfile(profile);
    assert.strictEqual(found.length, 2);
    assert.ok(found.every((e) => e.pubkey === X));
  });
});
