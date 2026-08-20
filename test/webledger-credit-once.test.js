/**
 * Regression tests for the deposit double-credit window.
 *
 * The GET /pay/.balance auto-scanner credited the ledger and then, in a
 * separate write, recorded the UTXO as seen. A crash between the two writes
 * lost the seen-record, and because the scanner re-runs on every balance poll
 * the same on-chain UTXO was credited again — minting balance from nothing.
 *
 * creditOnce records the deposit's idempotency key inside the ledger, so the
 * balance and the "already counted" marker commit together. Replaying the same
 * deposit — the exact effect of the crash-then-rescan — is now a no-op. This
 * mirrors the single atomic state.json commit in the solid-pod-rs parity port.
 */

import { describe, it } from 'node:test';
import assert from 'node:assert';
import fs from 'fs-extra';
import os from 'os';
import path from 'path';
import { createLedger, creditOnce, getBalance, readLedger, LEDGER_PATH } from '../src/webledger.js';
import * as storage from '../src/storage/filesystem.js';

const DID = 'did:nostr:npub1example';
const KEY = 'tbtc4:abcd1234:0';

describe('webledger — creditOnce idempotency', () => {
  it('credits once and reports the new balance', () => {
    const ledger = createLedger();
    const r = creditOnce(ledger, KEY, DID, 5000, 'tbtc4');
    assert.strictEqual(r.credited, true);
    assert.strictEqual(r.balance, 5000);
    assert.strictEqual(getBalance(ledger, DID, 'tbtc4'), 5000);
  });

  it('a replayed deposit key is a no-op (no double-credit)', () => {
    const ledger = createLedger();
    creditOnce(ledger, KEY, DID, 5000, 'tbtc4');

    // Simulate the crash-then-rescan: the very same outpoint is seen again.
    const replay = creditOnce(ledger, KEY, DID, 5000, 'tbtc4');
    assert.strictEqual(replay.credited, false, 'replay must not credit');
    assert.strictEqual(replay.balance, 5000, 'balance unchanged on replay');
    assert.strictEqual(getBalance(ledger, DID, 'tbtc4'), 5000);
  });

  it('distinct outpoints each credit exactly once', () => {
    const ledger = createLedger();
    creditOnce(ledger, 'tbtc4:aaaa:0', DID, 1000, 'tbtc4');
    creditOnce(ledger, 'tbtc4:bbbb:1', DID, 2000, 'tbtc4');
    creditOnce(ledger, 'tbtc4:aaaa:0', DID, 1000, 'tbtc4'); // replay of the first
    assert.strictEqual(getBalance(ledger, DID, 'tbtc4'), 3000);
  });

  it('readLedger migrates a legacy ledger to carry a credited array', async () => {
    // A ledger written before creditOnce existed has no `credited` field. The
    // migration in readLedger must add one, otherwise the idempotency guard
    // has nothing to consult for deposits made against pre-existing ledgers.
    // Exercised through real storage so the migration itself is under test —
    // asserting on a hand-built object would only re-test the test.
    const prevRoot = process.env.DATA_ROOT;
    const tmpRoot = await fs.mkdtemp(path.join(os.tmpdir(), 'jss-webledger-'));
    process.env.DATA_ROOT = tmpRoot;
    try {
      const legacy = { '@context': 'https://w3id.org/webledgers', type: 'WebLedger', entries: [] };
      await storage.write(LEDGER_PATH, Buffer.from(JSON.stringify(legacy)));

      const migrated = await readLedger();
      // Assert before any creditOnce call: creditOnce self-heals the field, so
      // checking after one would pass even if the migration were deleted.
      assert.ok(Array.isArray(migrated.credited),
        'readLedger must add a credited array to a legacy ledger');
      assert.strictEqual(migrated.credited.length, 0);

      // And the guard works end-to-end on the migrated ledger.
      assert.strictEqual(creditOnce(migrated, KEY, DID, 100, 'tbtc4').credited, true);
      assert.strictEqual(creditOnce(migrated, KEY, DID, 100, 'tbtc4').credited, false);
      assert.strictEqual(getBalance(migrated, DID, 'tbtc4'), 100);
    } finally {
      if (prevRoot === undefined) delete process.env.DATA_ROOT;
      else process.env.DATA_ROOT = prevRoot;
      await fs.remove(tmpRoot);
    }
  });

  it('a persisted credited marker survives a write/read round trip', async () => {
    const prevRoot = process.env.DATA_ROOT;
    const tmpRoot = await fs.mkdtemp(path.join(os.tmpdir(), 'jss-webledger-'));
    process.env.DATA_ROOT = tmpRoot;
    try {
      const ledger = createLedger();
      creditOnce(ledger, KEY, DID, 5000, 'tbtc4');
      await storage.write(LEDGER_PATH, Buffer.from(JSON.stringify(ledger)));

      // Simulate the crash-then-rescan across a process restart: the marker
      // must come back from disk so the replay is still a no-op.
      const reread = await readLedger();
      assert.ok(reread.credited.includes(KEY), 'credited key must persist');
      assert.strictEqual(creditOnce(reread, KEY, DID, 5000, 'tbtc4').credited, false);
      assert.strictEqual(getBalance(reread, DID, 'tbtc4'), 5000);
    } finally {
      if (prevRoot === undefined) delete process.env.DATA_ROOT;
      else process.env.DATA_ROOT = prevRoot;
      await fs.remove(tmpRoot);
    }
  });
});
