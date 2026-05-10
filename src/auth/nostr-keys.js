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
 * Validate a secp256k1 JWK as a Nostr key and return its x-only
 * pubkey hex. Returns `null` if the JWK isn't a Nostr-shaped key
 * or its `y` doesn't match the BIP-340 canonical (even-y) point
 * for the declared `x`.
 *
 * Why y matters: every secp256k1 x has TWO valid points (positive
 * and negative y). Nostr uses x-only pubkeys, which by BIP-340
 * convention always pick the even-y point. A profile that declares
 * a JWK with the right x but the wrong y is NOT the user's Nostr
 * key — accepting it would let an attacker plant a JWK at someone
 * else's WebID and have the indexer publish it as theirs.
 *
 * The verifier in src/auth/nostr.js (jwkMatchesNostrPubkey) does
 * the same check. Keeping the indexer in sync prevents the
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
  let canonicalY;
  try {
    // Compressed SEC1 encoding for the EVEN-y point at this x.
    const point = secp256k1.ProjectivePoint.fromHex('02' + xHex);
    canonicalY = point.toAffine().y.toString(16).padStart(64, '0');
  } catch { return null; }
  let jwkYHex;
  try {
    jwkYHex = Buffer.from(jwk.y.replace(/-/g, '+').replace(/_/g, '/'), 'base64')
      .toString('hex').toLowerCase();
  } catch { return null; }
  if (jwkYHex !== canonicalY) return null;
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
      // Require y to match the BIP-340 canonical point — the same
      // check the NIP-98 verifier applies. Without this, the indexer
      // could publish a JWK that the verifier will then reject,
      // surfacing as a 401 on a key the well-known endpoint had
      // advertised as authentic.
      const xonly = pubkeyFromValidatedJwk(vm.publicKeyJwk);
      if (xonly) out.push({ pubkey: xonly, vm });
    }
  }
  return out;
}
