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

import { schnorr, secp256k1 } from '@noble/curves/secp256k1';

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
 * The secret is normalized so that `G * secret` has *even* y (BIP-340
 * convention). Without normalization, ECDSA signatures made with the
 * raw secret would verify against the natural y of the public point —
 * even half the time, odd half the time — while the corresponding JWK
 * we publish in the WebID profile is always derived from the even-y
 * x-only Schnorr pubkey. The two would disagree on ~50% of generated
 * secrets, breaking Phase 2's LWS-CID round-trip non-deterministically.
 *
 * Normalizing once at generation time means a single secret-on-disk
 * works under both Schnorr (Nostr) and ECDSA (LWS-CID JWT) without
 * parity gymnastics in either signing path.
 *
 * @returns {{ secretHex: string, publicHex: string }}
 *   `secretHex` — 32-byte secret scalar, lower-hex, normalized so the
 *     corresponding public point has even y.
 *   `publicHex` — 32-byte x-only Schnorr pubkey, lower-hex (BIP-340).
 */
export function generateOwnerKeypair() {
  let secretBytes = schnorr.utils.randomPrivateKey();
  // Compressed SEC1 starts with 02 (even y) or 03 (odd y).
  const compressed = secp256k1.getPublicKey(secretBytes, /*compressed=*/true);
  if (compressed[0] === 0x03) {
    // Negate the secret (mod n) so the resulting point flips to even y.
    const n = secp256k1.CURVE.n;
    const original = BigInt('0x' + bytesToHex(secretBytes));
    const negated = (n - original) % n;
    secretBytes = hexToBytes(negated.toString(16).padStart(64, '0'));
  }
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
 * Compute the canonical did:nostr identifier for a Schnorr secp256k1
 * pubkey. Lower-hex form (matches the rest of jss — see
 * src/idp/well-known-did-nostr.js's resolveDidNostrLocally(pubkeyHex)
 * and src/auth/did-nostr.js's `did:nostr:${pubkey.toLowerCase()}`).
 * Phase 2 of #437 (#443) flips the Multikey document's `controller`
 * field to this form now that jss's resolver round-trips it.
 *
 * @param {string} publicHex - 32-byte x-only Schnorr pubkey hex.
 * @returns {string} `did:nostr:<lower-hex pubkey>`.
 */
export function didNostrFromPublicHex(publicHex) {
  if (!/^[0-9a-f]{64}$/.test(publicHex)) {
    throw new Error('didNostrFromPublicHex: expected 64-char lower-hex pubkey');
  }
  return `did:nostr:${publicHex}`;
}

/**
 * Build the W3C CID v1.0 Multikey JSON-LD document for a fresh pod
 * owner key.
 *
 * Phase 2 default controller: `did:nostr:<hex>`. The previous Phase 1
 * shape used the pod owner's WebID — both are valid CID v1.0
 * controllers, but did:nostr lets the keypair self-identify via jss's
 * existing resolver. Callers can still pass an explicit `controller`
 * (the legacy WebID form is what existing test fixtures use).
 *
 * @param {object} args
 * @param {string} args.publicHex - 32-byte x-only Schnorr pubkey hex.
 * @param {string} args.secretHex - 32-byte secret scalar hex.
 * @param {string} [args.controller] - Override the controller field.
 *   Defaults to `did:nostr:<publicHex>` (Phase 2 of #437 / #443).
 * @returns {object} JSON-LD Multikey document, ready for `JSON.stringify`.
 */
export function buildOwnerKeyDocument({ publicHex, secretHex, controller }) {
  const ctrl = controller ?? didNostrFromPublicHex(publicHex);
  if (typeof ctrl !== 'string' || !ctrl) {
    throw new Error('buildOwnerKeyDocument: controller required');
  }
  return {
    '@context': 'https://www.w3.org/ns/cid/v1',
    type: 'Multikey',
    controller: ctrl,
    publicKeyMultibase: publicKeyMultibase(publicHex),
    secretKeyMultibase: secretKeyMultibase(secretHex)
  };
}

/**
 * Compute the BIP-340 even-y JWK (kty=EC, crv=secp256k1) for an
 * x-only Schnorr pubkey hex. Phase 2 needs this for the VM that
 * lands in the WebID profile — the LWS-CID verifier currently reads
 * `publicKeyJwk` only (Multikey-only VMs aren't yet handled there
 * per `src/auth/lws-cid.js`'s docstring), so the VM ships both
 * `publicKeyMultibase` (CID v1.0 conformance) and `publicKeyJwk`
 * (LWS-CID compat).
 *
 * The y coordinate is computed against the canonical even-y point at
 * `x` — same convention `src/auth/nostr-keys.js`'s
 * `pubkeyFromValidatedJwk` checks against on the verifier side, so
 * the VM we mint round-trips through the existing extractor without
 * being rejected as "wrong y".
 *
 * @param {string} publicHex - 32-byte x-only Schnorr pubkey hex.
 * @returns {{ kty: 'EC', crv: 'secp256k1', x: string, y: string }}
 */
export function publicKeyJwkFromHex(publicHex) {
  if (!/^[0-9a-f]{64}$/.test(publicHex)) {
    throw new Error('publicKeyJwkFromHex: expected 64-char lower-hex pubkey');
  }
  // Compressed SEC1 with parity 02 = the canonical even-y point at x.
  const point = secp256k1.ProjectivePoint.fromHex('02' + publicHex);
  const yHex = point.toAffine().y.toString(16).padStart(64, '0');
  return {
    kty: 'EC',
    crv: 'secp256k1',
    x: hexToBase64Url(publicHex),
    y: hexToBase64Url(yHex)
  };
}

/**
 * Build the verificationMethod entry for the seeded WebID profile.
 *
 * The VM wires the Phase 1 keypair into the existing LWS-CID auth
 * loop: an agent signs a JWT with the on-disk secret + `kid` set to
 * this VM's `id`, the verifier (already merged in `src/auth/lws-cid.js`)
 * fetches the WebID profile, finds this VM, decodes the JWK, verifies
 * the signature, and returns the WebID as the authenticated identity.
 *
 * Both forms are emitted: `publicKeyMultibase` for CID v1.0 readers
 * (and round-trip with `decodeFFormSecp256k1` in `src/auth/nostr-keys.js`),
 * `publicKeyJwk` for the LWS-CID verifier and any tool that prefers JOSE.
 *
 * @param {object} args
 * @param {string} args.webId - Pod owner's WebID; used to derive both
 *   the `controller` and the document URL the VM `id` sits in.
 * @param {string} args.publicHex - 32-byte x-only Schnorr pubkey hex.
 * @param {string} [args.fragment='owner-key'] - Fragment id for the VM;
 *   appended to the WebID document URL to form `vm.id`.
 * @returns {object} JSON-LD verificationMethod entry.
 */
export function buildOwnerVerificationMethod({ webId, publicHex, fragment = 'owner-key' }) {
  if (typeof webId !== 'string' || !webId) {
    throw new Error('buildOwnerVerificationMethod: webId required');
  }
  const docUrl = webId.split('#')[0];
  return {
    '@id': `${docUrl}#${fragment}`,
    '@type': 'Multikey',
    controller: webId,
    publicKeyMultibase: publicKeyMultibase(publicHex),
    publicKeyJwk: publicKeyJwkFromHex(publicHex)
  };
}

/**
 * One-shot helper: generate a fresh keypair and produce the Multikey
 * document, the verificationMethod entry for the WebID profile, and
 * the raw key material (for log lines / CLI output that wants to
 * display the pubkey).
 *
 * The returned `secretHex` should be considered sensitive and not
 * logged; the public `publicMultibase` IS safe to print.
 *
 * @param {object} args
 * @param {string} args.webId - Pod owner's WebID. Used as the
 *   `controller` of the VM and to derive the VM's `@id` fragment.
 *   The Multikey document's `controller` is the `did:nostr:<hex>`
 *   form by default (Phase 2 of #437 / #443).
 * @param {string} [args.controller] - Override the Multikey
 *   document's controller. Defaults to `did:nostr:<publicHex>`.
 * @returns {{
 *   document: object,
 *   vm: object,
 *   publicHex: string,
 *   secretHex: string,
 *   publicMultibase: string,
 *   didNostr: string
 * }}
 */
export function provisionOwnerKey({ webId, controller, controllerWebId }) {
  // Backward-compat: callers from Phase 1 passed `controllerWebId` and
  // expected it to land in both the document's `controller` field and
  // (implicitly) the VM controller. Map it to the new shape.
  const effectiveWebId = webId ?? controllerWebId;
  if (typeof effectiveWebId !== 'string' || !effectiveWebId) {
    throw new Error('provisionOwnerKey: webId required');
  }
  const { publicHex, secretHex } = generateOwnerKeypair();
  const document = buildOwnerKeyDocument({
    publicHex,
    secretHex,
    controller: controller ?? (controllerWebId ?? didNostrFromPublicHex(publicHex))
  });
  const vm = buildOwnerVerificationMethod({ webId: effectiveWebId, publicHex });
  return {
    document,
    vm,
    publicHex,
    secretHex,
    publicMultibase: document.publicKeyMultibase,
    didNostr: didNostrFromPublicHex(publicHex)
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

function hexToBase64Url(hex) {
  if (!/^[0-9a-f]+$/i.test(hex) || hex.length % 2 !== 0) {
    throw new Error('hexToBase64Url: expected even-length hex');
  }
  return Buffer.from(hex, 'hex').toString('base64url');
}

function hexToBytes(hex) {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}
