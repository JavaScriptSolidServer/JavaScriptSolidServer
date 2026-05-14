/**
 * Owner-key provisioning for new pods.
 *
 * Generates a Schnorr secp256k1 keypair and serialises it as a
 * W3C Controlled Identifiers (CID) v1.0 Multikey document. The same
 * curve serves as a Solid signing identity, a Nostr identity, and a
 * future did:nostr DID controller (Phase 2).
 *
 * Phase 1 of #437 — see the issue for design resolutions:
 *   - controller in Phase 1: the pod owner's WebID (did:nostr in Phase 2)
 *   - secret key on disk: plaintext, owner-only ACL, file mode 0600;
 *     filesystem-level protection (FDE / LUKS / OS keyring) recommended;
 *     wrapped-secret support deferred to Phase 3
 *   - encoding: multibase `f` (base16-lower) + multicodec; matches the
 *     style already used in src/auth/nostr-keys.js for did:nostr
 *     Multikey verification methods. Pure hex with ~5 bytes of
 *     self-describing metadata at the front, no new deps.
 *   - no `nostr` extension block: bech32 npub is a one-line derivation
 *     in any Nostr-aware tool, not worth the additional secret-on-disk
 *     surface area or a new dependency.
 */

import { schnorr } from '@noble/curves/secp256k1';

/**
 * Multicodec varints (lower-hex). The CCG / W3C CID v1.0 Multikey
 * registry uses these to identify the algorithm of a key blob inside
 * a multibase-encoded value.
 *   secp256k1-pub  → 0xe7        → varint "e701"
 *   secp256k1-priv → 0x1301      → varint "8126"
 */
const MULTICODEC_SECP256K1_PUB_HEX = 'e701';
const MULTICODEC_SECP256K1_PRIV_HEX = '8126';

/**
 * Compressed-SEC1 parity byte for the *even-y* canonical point. BIP-340
 * (Schnorr / Nostr) keys are x-only and pick the even-y point at each
 * x; pairing the f-form prefix with `02` makes the Multikey value
 * round-trip with src/auth/nostr-keys.js's decoder.
 */
const EVEN_Y_PARITY_HEX = '02';

/**
 * Generate a fresh secp256k1 keypair suitable for Schnorr signing.
 *
 * @returns {{ secretHex: string, publicHex: string }}
 *   `secretHex` — 32-byte secret scalar, lower-hex.
 *   `publicHex` — 32-byte x-only Schnorr pubkey, lower-hex (BIP-340).
 */
export function generateOwnerKeypair() {
  const secretBytes = schnorr.utils.randomPrivateKey();
  const publicBytes = schnorr.getPublicKey(secretBytes);
  return {
    secretHex: bytesToHex(secretBytes),
    publicHex: bytesToHex(publicBytes)
  };
}

/**
 * Encode a 32-byte hex value as an f-form Multikey value.
 * For pub keys we prepend the parity byte (BIP-340 convention: 02);
 * for priv keys the secret scalar IS the 32-byte payload — no parity.
 */
export function publicKeyMultibase(publicHex) {
  if (!/^[0-9a-f]{64}$/.test(publicHex)) {
    throw new Error('publicKeyMultibase: expected 64-char lower-hex pubkey');
  }
  return 'f' + MULTICODEC_SECP256K1_PUB_HEX + EVEN_Y_PARITY_HEX + publicHex;
}

export function secretKeyMultibase(secretHex) {
  if (!/^[0-9a-f]{64}$/.test(secretHex)) {
    throw new Error('secretKeyMultibase: expected 64-char lower-hex secret');
  }
  return 'f' + MULTICODEC_SECP256K1_PRIV_HEX + secretHex;
}

/**
 * Build the W3C CID v1.0 Multikey JSON-LD document for a fresh pod
 * owner key. The `controller` is the pod owner's WebID — Phase 1
 * keeps the document self-consistent at every phase (Phase 2 will
 * swap in a `did:nostr:` controller once the resolver lands).
 *
 * @param {object} args
 * @param {string} args.controllerWebId - Absolute owner WebID URI.
 * @param {string} args.publicHex - 32-byte x-only Schnorr pubkey hex.
 * @param {string} args.secretHex - 32-byte secret scalar hex.
 * @returns {object} JSON-LD Multikey document, ready for `JSON.stringify`.
 */
export function buildOwnerKeyDocument({ controllerWebId, publicHex, secretHex }) {
  if (typeof controllerWebId !== 'string' || !controllerWebId) {
    throw new Error('buildOwnerKeyDocument: controllerWebId required');
  }
  return {
    '@context': 'https://www.w3.org/ns/cid/v1',
    type: 'Multikey',
    controller: controllerWebId,
    publicKeyMultibase: publicKeyMultibase(publicHex),
    secretKeyMultibase: secretKeyMultibase(secretHex)
  };
}

/**
 * One-shot helper: generate a fresh keypair and produce both the
 * Multikey document and the raw key material (for log lines / CLI
 * output that wants to display the pubkey).
 *
 * The returned `secretHex` should be considered sensitive and not
 * logged; the public `multibase` IS safe to print.
 */
export function provisionOwnerKey({ controllerWebId }) {
  const { publicHex, secretHex } = generateOwnerKeypair();
  const document = buildOwnerKeyDocument({ controllerWebId, publicHex, secretHex });
  return {
    document,
    publicHex,
    secretHex,
    publicMultibase: document.publicKeyMultibase
  };
}

/**
 * Refuse to provision keys when WAC is being bypassed.
 *
 * `--public` (and `request.config.public`) tells JSS to skip WAC and
 * grant unauthenticated access to everything. Combined with
 * `--provision-keys`, it would mean a plaintext secret at
 * `/private/privkey.jsonld` is readable by anyone over HTTP — the
 * exact opposite of what the seeded owner-only ACL is supposed to do.
 *
 * Throws a clear error so the operator hits the contradiction at
 * startup (or pod-creation) rather than discovering it by reading
 * their own server logs after a key leak.
 *
 * @param {object} args
 * @param {boolean} args.provisionKeys
 * @param {boolean} args.isPublic - jss `--public` mode
 * @throws {Error} when both flags are true
 */
export function assertProvisionKeysCompatible({ provisionKeys, isPublic }) {
  if (provisionKeys && isPublic) {
    throw new Error(
      '--provision-keys cannot be combined with --public. --public bypasses ' +
      'WAC, which would make /private/privkey.jsonld readable by anyone over ' +
      'HTTP. Use --provision-keys with WAC enforcement (the default), or drop ' +
      '--public.'
    );
  }
}

function bytesToHex(bytes) {
  let s = '';
  for (let i = 0; i < bytes.length; i++) {
    s += bytes[i].toString(16).padStart(2, '0');
  }
  return s;
}
