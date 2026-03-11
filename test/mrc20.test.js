/**
 * MRC20 Token Verification tests
 */

import { describe, it } from 'node:test';
import assert from 'node:assert';
import {
  jcs,
  sha256Hex,
  verifyStateLink,
  validateMrc20State,
  extractTransfersTo,
  totalTransferredTo,
  verifyMrc20Deposit
} from '../src/mrc20.js';

const PROFILE = 'mono.mrc20.v0.1';

// Helper: create a valid state chain pair
function createStatePair(ops, toAddress) {
  const prevState = {
    profile: PROFILE,
    prev: '0'.repeat(64),
    seq: 0,
    ticker: 'TEST',
    name: 'Test Token',
    decimals: 0,
    supply: 1000,
    balances: { creator: 1000 },
    ops: []
  };

  const state = {
    profile: PROFILE,
    prev: sha256Hex(jcs(prevState)),
    seq: 1,
    ticker: 'TEST',
    name: 'Test Token',
    decimals: 0,
    supply: 1000,
    balances: { creator: 900, [toAddress]: 100 },
    ops: ops || [{ op: 'urn:mono:op:transfer', from: 'creator', to: toAddress, amt: 100 }]
  };

  return { prevState, state };
}

describe('MRC20 Verification', () => {
  describe('jcs', () => {
    it('should sort keys alphabetically', () => {
      assert.strictEqual(jcs({ b: 1, a: 2 }), '{"a":2,"b":1}');
    });

    it('should handle nested objects', () => {
      assert.strictEqual(jcs({ z: { b: 1, a: 2 }, a: 3 }), '{"a":3,"z":{"a":2,"b":1}}');
    });

    it('should handle arrays', () => {
      assert.strictEqual(jcs([3, 1, 2]), '[3,1,2]');
    });

    it('should handle null and primitives', () => {
      assert.strictEqual(jcs(null), 'null');
      assert.strictEqual(jcs(42), '42');
      assert.strictEqual(jcs('hello'), '"hello"');
      assert.strictEqual(jcs(true), 'true');
    });

    it('should be deterministic', () => {
      const obj = { name: 'TEST', profile: PROFILE, seq: 0, prev: '0'.repeat(64) };
      assert.strictEqual(jcs(obj), jcs(obj));
    });
  });

  describe('sha256Hex', () => {
    it('should return 64-char hex string', () => {
      const hash = sha256Hex('hello');
      assert.strictEqual(hash.length, 64);
      assert.ok(/^[0-9a-f]{64}$/.test(hash));
    });

    it('should be deterministic', () => {
      assert.strictEqual(sha256Hex('test'), sha256Hex('test'));
    });
  });

  describe('verifyStateLink', () => {
    it('should verify valid state chain link', () => {
      const { prevState, state } = createStatePair();
      const result = verifyStateLink(state, prevState);
      assert.strictEqual(result.valid, true);
    });

    it('should reject invalid prev hash', () => {
      const { prevState, state } = createStatePair();
      state.prev = 'bad' + state.prev.slice(3);
      const result = verifyStateLink(state, prevState);
      assert.strictEqual(result.valid, false);
      assert.ok(result.error.includes('State chain break'));
    });

    it('should reject wrong sequence number', () => {
      const { prevState, state } = createStatePair();
      state.seq = 5; // should be 1
      const result = verifyStateLink(state, prevState);
      assert.strictEqual(result.valid, false);
      assert.ok(result.error.includes('Sequence mismatch'));
    });

    it('should reject missing states', () => {
      assert.strictEqual(verifyStateLink(null, {}).valid, false);
      assert.strictEqual(verifyStateLink({}, null).valid, false);
    });
  });

  describe('validateMrc20State', () => {
    it('should accept valid MRC20 state', () => {
      const { state } = createStatePair();
      assert.strictEqual(validateMrc20State(state).valid, true);
    });

    it('should reject wrong profile', () => {
      const { state } = createStatePair();
      state.profile = 'wrong.profile';
      assert.strictEqual(validateMrc20State(state).valid, false);
    });

    it('should reject missing ops', () => {
      const { state } = createStatePair();
      delete state.ops;
      assert.strictEqual(validateMrc20State(state).valid, false);
    });

    it('should reject non-object', () => {
      assert.strictEqual(validateMrc20State(null).valid, false);
      assert.strictEqual(validateMrc20State('string').valid, false);
    });
  });

  describe('extractTransfersTo', () => {
    it('should extract transfers to specific address', () => {
      const { state } = createStatePair(
        [
          { op: 'urn:mono:op:transfer', from: 'alice', to: 'pod', amt: 50 },
          { op: 'urn:mono:op:transfer', from: 'bob', to: 'other', amt: 30 },
          { op: 'urn:mono:op:transfer', from: 'carol', to: 'pod', amt: 25 }
        ],
        'pod'
      );
      const transfers = extractTransfersTo(state, 'pod');
      assert.strictEqual(transfers.length, 2);
      assert.strictEqual(transfers[0].amt, 50);
      assert.strictEqual(transfers[1].amt, 25);
    });

    it('should return empty for no matching transfers', () => {
      const { state } = createStatePair();
      const transfers = extractTransfersTo(state, 'nobody');
      assert.strictEqual(transfers.length, 0);
    });

    it('should ignore non-transfer ops', () => {
      const { state } = createStatePair(
        [{ op: 'urn:mono:op:mint', to: 'pod', amt: 100 }],
        'pod'
      );
      const transfers = extractTransfersTo(state, 'pod');
      assert.strictEqual(transfers.length, 0);
    });
  });

  describe('totalTransferredTo', () => {
    it('should sum all transfers to address', () => {
      const { state } = createStatePair(
        [
          { op: 'urn:mono:op:transfer', from: 'a', to: 'pod', amt: 50 },
          { op: 'urn:mono:op:transfer', from: 'b', to: 'pod', amt: 25 }
        ],
        'pod'
      );
      assert.strictEqual(totalTransferredTo(state, 'pod'), 75);
    });
  });

  describe('verifyMrc20Deposit', () => {
    it('should verify valid deposit', () => {
      const { prevState, state } = createStatePair(
        [{ op: 'urn:mono:op:transfer', from: 'user', to: 'mypod', amt: 200 }],
        'mypod'
      );
      const result = verifyMrc20Deposit({ state, prevState, toAddress: 'mypod' });
      assert.strictEqual(result.valid, true);
      assert.strictEqual(result.amount, 200);
      assert.strictEqual(result.ticker, 'TEST');
    });

    it('should reject broken state chain', () => {
      const { prevState, state } = createStatePair(
        [{ op: 'urn:mono:op:transfer', from: 'user', to: 'pod', amt: 100 }],
        'pod'
      );
      state.prev = 'tampered';
      const result = verifyMrc20Deposit({ state, prevState, toAddress: 'pod' });
      assert.strictEqual(result.valid, false);
    });

    it('should reject deposit to wrong address', () => {
      const { prevState, state } = createStatePair(
        [{ op: 'urn:mono:op:transfer', from: 'user', to: 'other-pod', amt: 100 }],
        'other-pod'
      );
      const result = verifyMrc20Deposit({ state, prevState, toAddress: 'my-pod' });
      assert.strictEqual(result.valid, false);
      assert.ok(result.error.includes('No transfers'));
    });

    it('should reject invalid MRC20 profile', () => {
      const { prevState, state } = createStatePair();
      state.profile = 'wrong';
      const result = verifyMrc20Deposit({ state, prevState, toAddress: 'pod' });
      assert.strictEqual(result.valid, false);
    });

    it('should sum multiple transfers in same state', () => {
      const { prevState, state } = createStatePair(
        [
          { op: 'urn:mono:op:transfer', from: 'a', to: 'pod', amt: 100 },
          { op: 'urn:mono:op:transfer', from: 'b', to: 'pod', amt: 50 }
        ],
        'pod'
      );
      const result = verifyMrc20Deposit({ state, prevState, toAddress: 'pod' });
      assert.strictEqual(result.valid, true);
      assert.strictEqual(result.amount, 150);
    });
  });
});
