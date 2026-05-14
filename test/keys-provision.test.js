/**
 * Unit tests for owner-key provisioning (Phase 1 of #437).
 */

import { describe, it } from 'node:test';
import assert from 'node:assert';
import { schnorr, secp256k1 } from '@noble/curves/secp256k1';
import {
  generateOwnerKeypair,
  publicKeyMultibase,
  secretKeyMultibase,
  buildOwnerKeyDocument,
  provisionOwnerKey,
  assertProvisionKeysCompatible
} from '../src/keys/provision.js';
import { decodeFFormSecp256k1 } from '../src/auth/nostr-keys.js';

describe('generateOwnerKeypair', () => {
  it('produces a 32-byte x-only pubkey and a 32-byte secret', () => {
    const { publicHex, secretHex } = generateOwnerKeypair();
    assert.match(publicHex, /^[0-9a-f]{64}$/);
    assert.match(secretHex, /^[0-9a-f]{64}$/);
  });

  it('produces a working Schnorr keypair (sign + verify)', () => {
    const { publicHex, secretHex } = generateOwnerKeypair();
    const message = new TextEncoder().encode('jss provision-keys roundtrip');
    const sig = schnorr.sign(message, hexToBytes(secretHex));
    assert.strictEqual(
      schnorr.verify(sig, message, hexToBytes(publicHex)),
      true,
      'signature must verify under the generated pubkey'
    );
  });

  it('produces a different keypair on every call', () => {
    const a = generateOwnerKeypair();
    const b = generateOwnerKeypair();
    assert.notStrictEqual(a.publicHex, b.publicHex);
    assert.notStrictEqual(a.secretHex, b.secretHex);
  });

  it('always normalizes the secret so G*secret has even y (BIP-340)', () => {
    // Without normalization, ECDSA signatures made with the raw secret
    // would verify against the natural y of G*secret — even/odd ~50/50
    // — while the JWK we publish in the WebID profile is derived from
    // the even-y x-only Schnorr pubkey. Phase 2's LWS-CID round-trip
    // would flake non-deterministically. Generate many keypairs and
    // assert every secret's natural public point is even-y.
    for (let i = 0; i < 64; i++) {
      const { secretHex } = generateOwnerKeypair();
      const compressed = secp256k1.getPublicKey(hexToBytes(secretHex), /*compressed=*/true);
      assert.strictEqual(compressed[0], 0x02,
        `secret #${i} produced odd-y point; normalization is broken`);
    }
  });
});

describe('publicKeyMultibase / secretKeyMultibase', () => {
  // Fixed test vectors so the encoding format is pinned (any change to
  // multicodec/multibase would shift these values and fail the assertion).
  const publicHex = '87a1c6f0e9b3d2456789abcdef0123456789abcdef0123456789abcdef012345';
  const secretHex = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';

  it('encodes a public key as f + e701 + 02 + 64-hex-pubkey', () => {
    const mb = publicKeyMultibase(publicHex);
    // f (multibase) + e701 (multicodec varint for secp256k1-pub) +
    // 02 (BIP-340 even-y parity) + 64-char pubkey hex
    assert.strictEqual(mb, 'fe70102' + publicHex);
  });

  it('encodes a secret key as f + 8126 + 64-hex-secret', () => {
    const mb = secretKeyMultibase(secretHex);
    // f (multibase) + 8126 (multicodec varint for secp256k1-priv) +
    // 64-char secret hex (no parity byte — secret IS the scalar)
    assert.strictEqual(mb, 'f8126' + secretHex);
  });

  it('round-trips through src/auth/nostr-keys decoder for the public side', () => {
    // The Multikey value we write must be readable by jss's existing
    // f-form decoder (used by the did:nostr verifier). This pins the
    // shape so a future change to either side fails loud.
    const mb = publicKeyMultibase(publicHex);
    const decoded = decodeFFormSecp256k1(mb);
    assert.strictEqual(decoded, publicHex);
  });

  it('rejects non-hex / wrong-length inputs', () => {
    assert.throws(() => publicKeyMultibase('not-hex'), /64-char lower-hex/);
    assert.throws(() => publicKeyMultibase(publicHex.slice(0, 63)), /64-char/);
    assert.throws(() => secretKeyMultibase(''), /64-char/);
    assert.throws(() => secretKeyMultibase(publicHex.toUpperCase()), /64-char lower-hex/);
  });
});

describe('buildOwnerKeyDocument', () => {
  const args = {
    controllerWebId: 'https://alice.example/profile/card.jsonld#me',
    publicHex: '87a1c6f0e9b3d2456789abcdef0123456789abcdef0123456789abcdef012345',
    secretHex: '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef'
  };

  it('emits a W3C CID v1.0 Multikey JSON-LD document', () => {
    const doc = buildOwnerKeyDocument(args);
    assert.strictEqual(doc['@context'], 'https://www.w3.org/ns/cid/v1');
    assert.strictEqual(doc.type, 'Multikey');
  });

  it('defaults the controller to did:nostr:<hex> in Phase 2', () => {
    // Phase 2 of #437 (#443) flipped the default controller to
    // `did:nostr:<publicHex>` now that jss's resolver round-trips
    // it. Phase 1 had used the WebID; the swap was anticipated in
    // the Phase 1 design log and ships here.
    const doc = buildOwnerKeyDocument({
      publicHex: args.publicHex,
      secretHex: args.secretHex
    });
    assert.strictEqual(doc.controller, `did:nostr:${args.publicHex}`);
  });

  it('accepts an explicit controller override (e.g. WebID, urn:, custom DID method)', () => {
    // The forward-looking knob — operators or future callers that
    // want to pin the document's controller to something other than
    // did:nostr (a WebID, a urn:, a custom DID method) pass
    // `controller` explicitly. Defaults still fire when omitted.
    const doc = buildOwnerKeyDocument({
      publicHex: args.publicHex,
      secretHex: args.secretHex,
      controller: args.controllerWebId
    });
    assert.strictEqual(doc.controller, args.controllerWebId);
    assert.doesNotMatch(doc.controller, /^did:nostr:/);
  });

  it('embeds both the public and secret Multikey values', () => {
    const doc = buildOwnerKeyDocument(args);
    assert.strictEqual(doc.publicKeyMultibase, publicKeyMultibase(args.publicHex));
    assert.strictEqual(doc.secretKeyMultibase, secretKeyMultibase(args.secretHex));
  });

  it('does NOT include a `nostr` extension block (npub etc.)', () => {
    // Resolution #2 of #437: bech32 npub is derivable from the public
    // multibase value in any Nostr-aware tool. Including it would
    // double the secret-on-disk surface for log/error/dump leaks
    // (the symmetric `nsec` field was originally proposed alongside).
    const doc = buildOwnerKeyDocument(args);
    assert.strictEqual(doc.nostr, undefined);
  });

  it('rejects an explicit empty controller override', () => {
    // The default did:nostr controller is computed from publicHex, so
    // missing inputs are caught upstream (see publicKeyMultibase
    // validation tests). When a caller *explicitly* passes an empty
    // string, that's a misconfiguration we surface loudly.
    assert.throws(
      () => buildOwnerKeyDocument({
        publicHex: args.publicHex,
        secretHex: args.secretHex,
        controller: ''
      }),
      /controller required/
    );
  });
});

describe('provisionOwnerKey', () => {
  const webId = 'https://alice.example/profile/card.jsonld#me';

  it('returns the document together with raw key material for CLI display', () => {
    const out = provisionOwnerKey({ webId });
    assert.match(out.publicHex, /^[0-9a-f]{64}$/);
    assert.match(out.secretHex, /^[0-9a-f]{64}$/);
    assert.strictEqual(out.publicMultibase, out.document.publicKeyMultibase);
    assert.strictEqual(out.document.type, 'Multikey');
    // Phase 2 of #437 (#443): controller defaults to did:nostr:<hex>.
    assert.strictEqual(out.document.controller, `did:nostr:${out.publicHex}`);
    assert.strictEqual(out.didNostr, `did:nostr:${out.publicHex}`);
  });

  it('returns a verificationMethod entry suitable for the WebID profile', () => {
    // Phase 2 wires the public side into the profile's
    // verificationMethod array so the existing LWS-CID verifier
    // (src/auth/lws-cid.js) can authenticate JWTs signed with the
    // matching secret. Both Multikey and JWK forms ship — Multikey
    // for CID v1.0 conformance, JWK for LWS-CID compat.
    const out = provisionOwnerKey({ webId });
    assert.strictEqual(out.vm['@type'], 'Multikey');
    assert.strictEqual(out.vm.controller, webId);
    assert.strictEqual(out.vm['@id'], 'https://alice.example/profile/card.jsonld#owner-key');
    assert.strictEqual(out.vm.publicKeyMultibase, out.publicMultibase);
    assert.strictEqual(out.vm.publicKeyJwk.kty, 'EC');
    assert.strictEqual(out.vm.publicKeyJwk.crv, 'secp256k1');
    assert.match(out.vm.publicKeyJwk.x, /^[A-Za-z0-9_-]+$/);
    assert.match(out.vm.publicKeyJwk.y, /^[A-Za-z0-9_-]+$/);
  });

  it('honours an explicit documentController override', () => {
    // The legacy controllerWebId alias was removed in #443 review —
    // the canonical way to pin the document controller is
    // documentController.
    const out = provisionOwnerKey({ webId, documentController: webId });
    assert.strictEqual(out.document.controller, webId);
    assert.strictEqual(out.vm.controller, webId,
      'VM controller still uses webId regardless of documentController');
  });

  it('keeps document.controller and vm.controller decoupled by design', () => {
    // Asymmetric on purpose: vm.controller lives inside the WebID
    // profile and identifies who in WebID-land can present this VM
    // (always the pod owner = webId). document.controller lives in
    // /private/privkey.jsonld and identifies the key in its own right
    // (defaults to did:nostr, can be overridden to any custom DID
    // method or URI). The two are distinct semantically; the JSDoc
    // on provisionOwnerKey spells this out.
    const out = provisionOwnerKey({ webId, documentController: 'urn:example:custom' });
    assert.strictEqual(out.document.controller, 'urn:example:custom');
    assert.strictEqual(out.vm.controller, webId,
      'vm.controller intentionally tracks webId, not documentController');
  });
});

describe('assertProvisionKeysCompatible', () => {
  // Refuse the provisionKeys + --public combination — public mode
  // bypasses WAC, which would expose the freshly-written secret on
  // /private/privkey.jsonld to anyone over HTTP.
  it('throws when both provisionKeys and isPublic are true', () => {
    assert.throws(
      () => assertProvisionKeysCompatible({ provisionKeys: true, isPublic: true }),
      /cannot be combined with --public/
    );
  });

  it('does NOT throw for provisionKeys alone (the supported case)', () => {
    assert.doesNotThrow(() =>
      assertProvisionKeysCompatible({ provisionKeys: true, isPublic: false })
    );
  });

  it('does NOT throw for --public alone (no secrets being written)', () => {
    assert.doesNotThrow(() =>
      assertProvisionKeysCompatible({ provisionKeys: false, isPublic: true })
    );
  });

  it('does NOT throw when neither flag is set', () => {
    assert.doesNotThrow(() =>
      assertProvisionKeysCompatible({ provisionKeys: false, isPublic: false })
    );
  });
});

function hexToBytes(hex) {
  if (hex.length % 2 !== 0) throw new Error('hex length must be even');
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}
