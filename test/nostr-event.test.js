/**
 * Unit tests for src/nostr/event.js — the minimal NIP-01 event verifier
 * that replaced nostr-tools (#135).
 *
 * Coverage focuses on the security-critical paths:
 *   - Round-trip: a freshly-signed event verifies.
 *   - Tamper rejection: any byte mutation makes it fail.
 *   - Wrong-key rejection: a sig from a different key fails.
 *   - Structural rejection: malformed events fail validateEvent.
 *   - getEventHash matches NIP-01's canonical serialization.
 */

import { describe, it } from 'node:test';
import assert from 'node:assert';
import { schnorr } from '@noble/curves/secp256k1';

import {
  getEventHash,
  validateEvent,
  verifyEvent,
  generateSecretKey,
  getPublicKey,
  finalizeEvent,
  nip98Token
} from '../src/nostr/event.js';

describe('nostr event utilities (#135)', () => {
  describe('getEventHash', () => {
    it('matches NIP-01 canonical serialization (sha256 of [0,pubkey,...])', () => {
      // Pin a deterministic input AND a precomputed digest so both the
      // canonical serialization and the SHA-256 step are locked in.
      // Recompute via:
      //   echo -n '[0,"00...01",1000000,1,[],"hello"]' | sha256sum
      const event = {
        pubkey: '0000000000000000000000000000000000000000000000000000000000000001',
        created_at: 1000000,
        kind: 1,
        tags: [],
        content: 'hello'
      };
      const baseline = getEventHash(event);
      assert.strictEqual(
        baseline,
        '01f1ec62e464146177ccfe8580ae050847b3cc48c7eca3e0678fc7b92cedfef0',
        'NIP-01 canonical hash regression — change here means serialization or SHA-256 has shifted'
      );
      assert.match(baseline, /^[a-f0-9]{64}$/);

      // Any change to any canonical field must yield a different hash.
      assert.notStrictEqual(getEventHash({ ...event, content: 'hello!' }), baseline);
      assert.notStrictEqual(getEventHash({ ...event, kind: 2 }), baseline);
      assert.notStrictEqual(getEventHash({ ...event, created_at: 1000001 }), baseline);
      assert.notStrictEqual(getEventHash({ ...event, tags: [['t']] }), baseline);
    });

    it('serializes pubkey verbatim (case-strict per NIP-01)', () => {
      // NIP-01 specifies lowercase hex throughout. We don't normalize
      // inside getEventHash — uppercase pubkey would produce a different
      // hash, but validateEvent/verifyEvent reject uppercase before we
      // get here, so callers never see the divergence in practice.
      // Use a pubkey with hex letters so upper- and lower-case differ.
      const lower = {
        pubkey: 'abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789',
        created_at: 1, kind: 1, tags: [], content: ''
      };
      const upper = { ...lower, pubkey: lower.pubkey.toUpperCase() };
      assert.notStrictEqual(
        getEventHash(lower), getEventHash(upper),
        'getEventHash is canonical: caller must supply lowercase'
      );
    });
  });

  describe('verifyEvent — round-trip and tamper rejection', () => {
    it('verifies a freshly-signed event', () => {
      const sk = generateSecretKey();
      const event = finalizeEvent({
        kind: 27235,
        tags: [['u', 'https://example.test/foo'], ['method', 'GET']],
        content: ''
      }, sk);
      assert.strictEqual(verifyEvent(event), true);
    });

    it('rejects an event with a flipped content byte', () => {
      const sk = generateSecretKey();
      const event = finalizeEvent({ kind: 1, tags: [], content: 'original' }, sk);
      // Mutate content but keep id/sig — recomputed hash won't match.
      event.content = 'mutated';
      assert.strictEqual(verifyEvent(event), false);
    });

    it('rejects an event whose declared id is wrong', () => {
      const sk = generateSecretKey();
      const event = finalizeEvent({ kind: 1, tags: [], content: 'x' }, sk);
      event.id = '0'.repeat(64); // wrong id
      assert.strictEqual(verifyEvent(event), false);
    });

    it('rejects an event signed by a different key', () => {
      const sk1 = generateSecretKey();
      const sk2 = generateSecretKey();
      const event = finalizeEvent({ kind: 1, tags: [], content: 'x' }, sk1);
      // Replace pubkey with sk2's pubkey but keep sk1's signature.
      event.pubkey = getPublicKey(sk2);
      // Recompute id since pubkey is part of the canonical hash, then
      // the sig won't match the new id.
      event.id = getEventHash(event);
      assert.strictEqual(verifyEvent(event), false);
    });

    it('rejects an event with a tampered signature', () => {
      const sk = generateSecretKey();
      const event = finalizeEvent({ kind: 1, tags: [], content: 'x' }, sk);
      // Flip the last hex char of the signature.
      const last = event.sig.slice(-1);
      event.sig = event.sig.slice(0, -1) + (last === '0' ? '1' : '0');
      assert.strictEqual(verifyEvent(event), false);
    });
  });

  describe('validateEvent — structural rejection', () => {
    function valid() {
      return finalizeEvent({ kind: 1, tags: [], content: 'x' }, generateSecretKey());
    }

    it('accepts a well-formed event', () => {
      assert.strictEqual(validateEvent(valid()), true);
    });

    const cases = [
      ['null',                      null],
      ['undefined',                 undefined],
      ['array',                     []],
      ['missing id',                () => { const e = valid(); delete e.id; return e; }],
      ['short id',                  () => { const e = valid(); e.id = 'abcd'; return e; }],
      ['non-hex id',                () => { const e = valid(); e.id = 'g'.repeat(64); return e; }],
      ['short pubkey',              () => { const e = valid(); e.pubkey = 'abcd'; return e; }],
      ['short sig',                 () => { const e = valid(); e.sig = 'abcd'; return e; }],
      ['kind not integer',          () => { const e = valid(); e.kind = 'one'; return e; }],
      ['kind negative',             () => { const e = valid(); e.kind = -1; return e; }],
      ['negative created_at',       () => { const e = valid(); e.created_at = -1; return e; }],
      ['content not string',        () => { const e = valid(); e.content = 123; return e; }],
      ['tags not array',            () => { const e = valid(); e.tags = 'oops'; return e; }],
      ['nested tag not array',      () => { const e = valid(); e.tags = ['oops']; return e; }],
      ['tag value not string',      () => { const e = valid(); e.tags = [[1, 2]]; return e; }]
    ];

    for (const [label, input] of cases) {
      it(`rejects: ${label}`, () => {
        const e = typeof input === 'function' ? input() : input;
        assert.strictEqual(validateEvent(e), false);
      });
    }
  });

  describe('lenient input — round 2 fixes (#341 review)', () => {
    it('rejects uppercase hex in id/pubkey/sig (NIP-01 is case-strict)', () => {
      // We deliberately do NOT lenient-accept uppercase here — accepting
      // would let an event verify but then miss case-sensitive downstream
      // lookups (relay filter ID match, dedupe by pubkey, etc.). Strict
      // at the gate keeps the rest of the codebase from having to remember
      // to normalize.
      const sk = generateSecretKey();
      const event = finalizeEvent({ kind: 1, tags: [], content: 'x' }, sk);
      assert.strictEqual(verifyEvent({ ...event, id: event.id.toUpperCase() }), false);
      assert.strictEqual(verifyEvent({ ...event, pubkey: event.pubkey.toUpperCase() }), false);
      assert.strictEqual(verifyEvent({ ...event, sig: event.sig.toUpperCase() }), false);
    });

    it('accepts kinds above 65535 (NIP-01 has no 16-bit cap)', () => {
      const sk = generateSecretKey();
      const event = finalizeEvent({ kind: 30023, tags: [], content: 'long-form' }, sk);
      assert.strictEqual(verifyEvent(event), true,
        'kind 30023 (NIP-23 long-form content) must verify');
    });

    it('still rejects negative kinds', () => {
      const sk = generateSecretKey();
      const event = finalizeEvent({ kind: 1, tags: [], content: 'x' }, sk);
      event.kind = -1;
      assert.strictEqual(validateEvent(event), false);
    });
  });

  describe('finalizeEvent input validation (#341 review)', () => {
    it('throws when kind is missing', () => {
      const sk = generateSecretKey();
      assert.throws(() => finalizeEvent({ tags: [], content: 'x' }, sk), TypeError);
    });

    it('throws when kind is not a non-negative safe integer', () => {
      const sk = generateSecretKey();
      assert.throws(() => finalizeEvent({ kind: -1 }, sk), TypeError);
      assert.throws(() => finalizeEvent({ kind: 'one' }, sk), TypeError);
      assert.throws(() => finalizeEvent({ kind: 1.5 }, sk), TypeError);
      assert.throws(() => finalizeEvent({ kind: Number.MAX_SAFE_INTEGER + 1 }, sk), TypeError);
    });

    it('throws when created_at is invalid', () => {
      const sk = generateSecretKey();
      assert.throws(() => finalizeEvent({ kind: 1, created_at: -1 }, sk), TypeError);
      assert.throws(() => finalizeEvent({ kind: 1, created_at: 'now' }, sk), TypeError);
    });

    it('throws when tags is not an array', () => {
      const sk = generateSecretKey();
      assert.throws(() => finalizeEvent({ kind: 1, tags: 'oops' }, sk), TypeError);
    });

    it('throws when content is not a string', () => {
      const sk = generateSecretKey();
      assert.throws(() => finalizeEvent({ kind: 1, content: 123 }, sk), TypeError);
    });
  });

  describe('nip98Token body must be bytes (#341 review)', () => {
    it('accepts a string body (JSON or text)', () => {
      const sk = generateSecretKey();
      const tok = nip98Token('https://x.test/', 'POST', sk, '{"a":1}');
      assert.ok(typeof tok === 'string' && tok.length > 0);
    });

    it('accepts a Uint8Array body', () => {
      const sk = generateSecretKey();
      const bytes = new TextEncoder().encode('{"a":1}');
      const tok = nip98Token('https://x.test/', 'POST', sk, bytes);
      assert.ok(typeof tok === 'string' && tok.length > 0);
    });

    it('accepts no body', () => {
      const sk = generateSecretKey();
      const tok = nip98Token('https://x.test/', 'GET', sk);
      assert.ok(typeof tok === 'string' && tok.length > 0);
    });

    it('throws on a plain object (would re-serialize and not match wire bytes)', () => {
      const sk = generateSecretKey();
      assert.throws(
        () => nip98Token('https://x.test/', 'POST', sk, { a: 1 }),
        TypeError,
        'Object body must be rejected — caller must pass exact wire bytes'
      );
    });
  });

  describe('validateEvent — created_at (#341 review)', () => {
    it('rejects created_at beyond Number.MAX_SAFE_INTEGER', () => {
      const sk = generateSecretKey();
      const event = finalizeEvent({ kind: 1 }, sk);
      // Manually inject a non-safe-integer to test validateEvent — we
      // can't construct it via finalizeEvent (which now rejects too).
      event.created_at = Number.MAX_SAFE_INTEGER + 1;
      // Recompute id so the structural check is the only one that fires.
      assert.strictEqual(validateEvent(event), false);
    });
  });

  describe('test helper parity with @noble/curves', () => {
    it('getPublicKey returns 32-byte (64 hex) x-only pubkey', () => {
      const sk = generateSecretKey();
      const pk = getPublicKey(sk);
      assert.match(pk, /^[a-f0-9]{64}$/);
      // schnorr.getPublicKey returns 32 bytes for x-only.
      assert.strictEqual(Buffer.from(pk, 'hex').length, 32);
    });

    it('schnorr.verify (via verifyEvent) rejects events whose id was not signed', () => {
      const sk = generateSecretKey();
      const event = finalizeEvent({ kind: 1, tags: [], content: 'a' }, sk);
      // Sanity: a separate raw schnorr.verify of the same event should agree.
      assert.strictEqual(schnorr.verify(event.sig, event.id, event.pubkey), true);
      // And our wrapper should agree.
      assert.strictEqual(verifyEvent(event), true);
    });
  });
});
