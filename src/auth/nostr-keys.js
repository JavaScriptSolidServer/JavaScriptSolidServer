/**
 * Shared Nostr-key encoding helpers.
 *
 * Lives in its own module so both the NIP-98 verifier
 * (`src/auth/nostr.js`) and the well-known DID-doc publisher
 * (`src/idp/well-known-did-nostr.js`) can use it without forming a
 * circular import.
 */

import { secp256k1 } from '@noble/curves/secp256k1';

/** Multicodec varint for secp256k1-pub: 0xe7 0x01 → "e701" hex. */
const MULTICODEC_SECP256K1_PUB_HEX = 'e701';

/**
 * The two valid y-coordinates (64-char hex) for a secp256k1 x: the
 * even-parity point and its odd-parity reflection. Returns `null` if
 * `xHex` isn't a valid curve x.
 *
 * Both parities are in-spec for did:nostr: the spec
 * (https://nostrcg.github.io/did-nostr/) states "Nostr applications
 * may generate keys with either 0x02 or 0x03 prefixes" — 0x02 for an
 * even y, 0x03 for an odd y. So a verification method that encodes the
 * same x-only Nostr identity can legitimately carry either parity, and
 * key matching accepts either while still requiring `(x, y)` to be a
 * real on-curve point. See issue #571.
 */
export function nostrJwkYParities(xHex) {
  if (typeof xHex !== 'string') return null;
  const x = xHex.toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(x)) return null;
  try {
    const even = secp256k1.ProjectivePoint.fromHex('02' + x).toAffine().y;
    const odd = secp256k1.ProjectivePoint.fromHex('03' + x).toAffine().y;
    return [
      even.toString(16).padStart(64, '0'),
      odd.toString(16).padStart(64, '0'),
    ];
  } catch {
    return null;
  }
}

/**
 * Validate a secp256k1 JWK as a Nostr key and return its x-only
 * pubkey hex. Returns `null` if the JWK isn't a Nostr-shaped key
 * or its `y` isn't an on-curve point (either parity) for the
 * declared `x`.
 *
 * Why y matters: every secp256k1 x has TWO valid points (even and
 * odd y). Nostr identities are x-only, so the x coordinate IS the
 * identity — but a profile that declares a JWK with the right x and a
 * *fabricated* (off-curve) y is malformed and must be rejected, else
 * an attacker could plant arbitrary key material at someone else's
 * WebID and have the indexer publish it. We therefore require y to be
 * one of the two genuine on-curve y's, accepting either parity per the
 * did:nostr spec (see `nostrJwkYParities` / issue #571).
 *
 * The verifier in src/auth/nostr.js (jwkMatchesNostrPubkey) applies
 * the same rule. Keeping the indexer in sync prevents the
 * "indexed but verifier rejects" inconsistency that would surface
 * as a 401 on a key the well-known endpoint had advertised.
 */
export function pubkeyFromValidatedJwk(jwk) {
  if (!jwk || typeof jwk !== 'object') return null;
  if (jwk.kty !== 'EC') return null;
  if (jwk.crv !== 'secp256k1' && jwk.crv !== 'P-256K') return null;
  if (typeof jwk.x !== 'string' || typeof jwk.y !== 'string') return null;
  let xHex;
  try {
    xHex = Buffer.from(jwk.x.replace(/-/g, '+').replace(/_/g, '/'), 'base64')
      .toString('hex').toLowerCase();
  } catch { return null; }
  if (!/^[0-9a-f]{64}$/.test(xHex)) return null;
  const validY = nostrJwkYParities(xHex);
  if (!validY) return null;
  let jwkYHex;
  try {
    jwkYHex = Buffer.from(jwk.y.replace(/-/g, '+').replace(/_/g, '/'), 'base64')
      .toString('hex').toLowerCase();
  } catch { return null; }
  if (!validY.includes(jwkYHex)) return null;
  return xHex;
}

/**
 * Decode an f-form Multikey for secp256k1-pub back into the 32-byte
 * x-only pubkey hex. Returns null if the input isn't this shape.
 *
 * The f-form recipe (per CCG community#254 / did:nostr): multibase
 * `f` (base16-lower) + multicodec `e701` + parity byte (`02`/`03`)
 * + 32-byte xonly pubkey.
 */
export function decodeFFormSecp256k1(mb) {
  if (typeof mb !== 'string' || !mb.startsWith('f')) return null;
  const hex = mb.slice(1).toLowerCase();
  if (!/^[0-9a-f]+$/.test(hex)) return null;
  if (!hex.startsWith(MULTICODEC_SECP256K1_PUB_HEX)) return null;
  const rest = hex.slice(MULTICODEC_SECP256K1_PUB_HEX.length);
  // Expect parity byte (02/03) + 32-byte xonly = 66 hex chars.
  if (rest.length !== 66) return null;
  const parity = rest.slice(0, 2);
  if (parity !== '02' && parity !== '03') return null;
  return rest.slice(2);
}

/**
 * Enumerate every Nostr pubkey declared in a profile's
 * `verificationMethod` entries. Matches both encodings:
 *   - f-form Multikey (`publicKeyMultibase`)
 *   - JsonWebKey (`kty: EC, crv: secp256k1`) — derives x as the pubkey
 *
 * Returns `[ { pubkey, vm } ]` — the VM is returned alongside so
 * callers can do further checks (`controller`, `authentication`
 * membership, etc.) without re-parsing.
 */
export function extractNostrPubkeysFromProfile(profile) {
  if (!profile || typeof profile !== 'object') return [];
  const out = [];
  const raw = profile.verificationMethod;
  const vms = raw === undefined || raw === null ? []
            : Array.isArray(raw) ? raw : [raw];
  for (const vm of vms) {
    if (!vm || typeof vm !== 'object') continue;
    if (typeof vm.publicKeyMultibase === 'string') {
      const xonly = decodeFFormSecp256k1(vm.publicKeyMultibase);
      if (xonly) out.push({ pubkey: xonly, vm });
    } else if (vm.publicKeyJwk && typeof vm.publicKeyJwk === 'object') {
      // Require y to be a genuine on-curve point for x (either
      // parity, per the did:nostr spec) — the same check the NIP-98
      // verifier applies. Without this, the indexer could publish a
      // JWK that the verifier will then reject, surfacing as a 401 on
      // a key the well-known endpoint had advertised as authentic.
      const xonly = pubkeyFromValidatedJwk(vm.publicKeyJwk);
      if (xonly) out.push({ pubkey: xonly, vm });
    }
  }
  return out;
}
