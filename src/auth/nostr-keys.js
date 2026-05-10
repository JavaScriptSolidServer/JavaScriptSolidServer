/**
 * Shared Nostr-key encoding helpers.
 *
 * Lives in its own module so both the NIP-98 verifier
 * (`src/auth/nostr.js`) and the well-known DID-doc publisher
 * (`src/idp/well-known-did-nostr.js`) can use it without forming a
 * circular import.
 */

/** Multicodec varint for secp256k1-pub: 0xe7 0x01 → "e701" hex. */
const MULTICODEC_SECP256K1_PUB_HEX = 'e701';

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
      const jwk = vm.publicKeyJwk;
      if (jwk.kty === 'EC' && (jwk.crv === 'secp256k1' || jwk.crv === 'P-256K') && typeof jwk.x === 'string') {
        try {
          const hex = Buffer.from(jwk.x.replace(/-/g, '+').replace(/_/g, '/'), 'base64')
            .toString('hex').toLowerCase();
          if (/^[0-9a-f]{64}$/.test(hex)) out.push({ pubkey: hex, vm });
        } catch { /* skip */ }
      }
    }
  }
  return out;
}
