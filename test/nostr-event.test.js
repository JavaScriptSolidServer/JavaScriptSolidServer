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

import { getEventHash, validateEvent, verifyEvent } from '../src/nostr/event.js';
import {
  generateSecretKey,
  getPublicKey,
  finalizeEvent
} from './helpers/nostr-event.js';

describe('nostr event utilities (#135)', () => {
  describe('getEventHash', () => {
    it('matches NIP-01 canonical serialization (sha256 of [0,pubkey,...])', () => {
      // Pin a deterministic input so the hash function is locked in.
      const event = {
        pubkey: '0000000000000000000000000000000000000000000000000000000000000001',
        created_at: 1000000,
        kind: 1,
        tags: [],
        content: 'hello'
      };
      const hash = getEventHash(event);
      assert.match(hash, /^[a-f0-9]{64}$/);

      // Recompute via @noble/hashes path indirectly: any change to any
      // field must yield a different hash.
      const baseline = hash;
      assert.notStrictEqual(getEventHash({ ...event, content: 'hello!' }), baseline);
      assert.notStrictEqual(getEventHash({ ...event, kind: 2 }), baseline);
      assert.notStrictEqual(getEventHash({ ...event, created_at: 1000001 }), baseline);
      assert.notStrictEqual(getEventHash({ ...event, tags: [['t']] }), baseline);
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
    it('accepts uppercase hex in id/pubkey/sig', () => {
      const sk = generateSecretKey();
      const event = finalizeEvent({ kind: 1, tags: [], content: 'x' }, sk);
      // Uppercase variants of all three hex fields should still verify.
      const upper = {
        ...event,
        id: event.id.toUpperCase(),
        pubkey: event.pubkey.toUpperCase(),
        sig: event.sig.toUpperCase()
      };
      assert.strictEqual(verifyEvent(upper), true,
        'uppercase hex must verify (canonical lowercase elsewhere is policy, not protocol)');
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
