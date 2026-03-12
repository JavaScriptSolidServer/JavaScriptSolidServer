/**
 * Web Ledger module tests
 * Verifies spec compliance with https://webledgers.org/
 */

import { describe, it } from 'node:test';
import assert from 'node:assert';
import {
  createLedger,
  getBalance,
  setBalance,
  credit,
  debit,
  listBalances,
  compact
} from '../src/webledger.js';

const CONTEXT = 'https://w3id.org/webledgers';

describe('Web Ledger', () => {
  describe('createLedger', () => {
    it('should create spec-compliant ledger with required fields', () => {
      const ledger = createLedger();
      assert.strictEqual(ledger['@context'], CONTEXT);
      assert.strictEqual(ledger.type, 'WebLedger');
      assert.strictEqual(ledger.defaultCurrency, 'satoshi');
      assert.ok(Array.isArray(ledger.entries));
      assert.strictEqual(ledger.entries.length, 0);
      assert.ok(typeof ledger.created === 'number');
      assert.ok(typeof ledger.updated === 'number');
    });

    it('should accept custom options', () => {
      const ledger = createLedger({
        name: 'Alice Credits',
        description: 'Pod credits for alice.pod',
        id: 'https://alice.example/.well-known/webledgers/webledgers.json',
        defaultCurrency: 'USD'
      });
      assert.strictEqual(ledger.name, 'Alice Credits');
      assert.strictEqual(ledger.description, 'Pod credits for alice.pod');
      assert.strictEqual(ledger.id, 'https://alice.example/.well-known/webledgers/webledgers.json');
      assert.strictEqual(ledger.defaultCurrency, 'USD');
    });
  });

  describe('getBalance / setBalance', () => {
    it('should return 0 for unknown URI', () => {
      const ledger = createLedger();
      assert.strictEqual(getBalance(ledger, 'did:nostr:abc123'), 0);
    });

    it('should set and get balance', () => {
      const ledger = createLedger();
      setBalance(ledger, 'did:nostr:abc123', 5000);
      assert.strictEqual(getBalance(ledger, 'did:nostr:abc123'), 5000);
    });

    it('should create spec-compliant Entry', () => {
      const ledger = createLedger();
      setBalance(ledger, 'did:nostr:abc123', 100);
      const entry = ledger.entries[0];
      assert.strictEqual(entry.type, 'Entry');
      assert.strictEqual(entry.url, 'did:nostr:abc123');
      assert.strictEqual(entry.amount, '100');
    });

    it('should update existing entry', () => {
      const ledger = createLedger();
      setBalance(ledger, 'did:nostr:abc123', 100);
      setBalance(ledger, 'did:nostr:abc123', 200);
      assert.strictEqual(ledger.entries.length, 1);
      assert.strictEqual(getBalance(ledger, 'did:nostr:abc123'), 200);
    });

    it('should handle array amount format', () => {
      const ledger = createLedger();
      ledger.entries.push({
        type: 'Entry',
        url: 'did:nostr:multi',
        amount: [
          { currency: 'satoshi', value: '50000' },
          { currency: 'USD', value: '25.00' }
        ]
      });
      assert.strictEqual(getBalance(ledger, 'did:nostr:multi'), 50000);
    });
  });

  describe('credit / debit', () => {
    it('should credit a new URI', () => {
      const ledger = createLedger();
      const bal = credit(ledger, 'did:nostr:user1', 1000);
      assert.strictEqual(bal, 1000);
      assert.strictEqual(getBalance(ledger, 'did:nostr:user1'), 1000);
    });

    it('should accumulate credits', () => {
      const ledger = createLedger();
      credit(ledger, 'did:nostr:user1', 1000);
      const bal = credit(ledger, 'did:nostr:user1', 500);
      assert.strictEqual(bal, 1500);
    });

    it('should debit when sufficient balance', () => {
      const ledger = createLedger();
      credit(ledger, 'did:nostr:user1', 1000);
      const result = debit(ledger, 'did:nostr:user1', 300);
      assert.strictEqual(result.success, true);
      assert.strictEqual(result.balance, 700);
    });

    it('should fail debit when insufficient balance', () => {
      const ledger = createLedger();
      credit(ledger, 'did:nostr:user1', 100);
      const result = debit(ledger, 'did:nostr:user1', 200);
      assert.strictEqual(result.success, false);
      assert.strictEqual(result.balance, 100);
      // Balance unchanged
      assert.strictEqual(getBalance(ledger, 'did:nostr:user1'), 100);
    });

    it('should fail debit on zero balance', () => {
      const ledger = createLedger();
      const result = debit(ledger, 'did:nostr:nobody', 1);
      assert.strictEqual(result.success, false);
      assert.strictEqual(result.balance, 0);
    });
  });

  describe('listBalances / compact', () => {
    it('should list non-zero balances', () => {
      const ledger = createLedger();
      credit(ledger, 'did:nostr:a', 100);
      credit(ledger, 'did:nostr:b', 0);
      credit(ledger, 'did:nostr:c', 50);
      const list = listBalances(ledger);
      assert.strictEqual(list.length, 2);
      assert.ok(list.find(e => e.url === 'did:nostr:a' && e.amount === 100));
      assert.ok(list.find(e => e.url === 'did:nostr:c' && e.amount === 50));
    });

    it('should compact zero-balance entries', () => {
      const ledger = createLedger();
      credit(ledger, 'did:nostr:a', 100);
      credit(ledger, 'did:nostr:b', 50);
      debit(ledger, 'did:nostr:b', 50);
      assert.strictEqual(ledger.entries.length, 2);
      compact(ledger);
      assert.strictEqual(ledger.entries.length, 1);
      assert.strictEqual(ledger.entries[0].url, 'did:nostr:a');
    });
  });

  describe('multi-currency', () => {
    it('should credit and debit with specific currency', () => {
      const ledger = createLedger();
      const bal = credit(ledger, 'did:nostr:user1', 1000, 'tbtc3');
      assert.strictEqual(bal, 1000);
      assert.strictEqual(getBalance(ledger, 'did:nostr:user1', 'tbtc3'), 1000);
      // Default balance should be 0 (no satoshi credits)
      assert.strictEqual(getBalance(ledger, 'did:nostr:user1'), 0);
    });

    it('should track multiple currencies independently', () => {
      const ledger = createLedger();
      credit(ledger, 'did:nostr:user1', 1000, 'tbtc3');
      credit(ledger, 'did:nostr:user1', 5000, 'tbtc4');
      assert.strictEqual(getBalance(ledger, 'did:nostr:user1', 'tbtc3'), 1000);
      assert.strictEqual(getBalance(ledger, 'did:nostr:user1', 'tbtc4'), 5000);
    });

    it('should debit specific currency', () => {
      const ledger = createLedger();
      credit(ledger, 'did:nostr:user1', 1000, 'tbtc3');
      credit(ledger, 'did:nostr:user1', 5000, 'tbtc4');
      const result = debit(ledger, 'did:nostr:user1', 300, 'tbtc3');
      assert.strictEqual(result.success, true);
      assert.strictEqual(result.balance, 700);
      // tbtc4 unchanged
      assert.strictEqual(getBalance(ledger, 'did:nostr:user1', 'tbtc4'), 5000);
    });

    it('should fail debit when currency balance insufficient', () => {
      const ledger = createLedger();
      credit(ledger, 'did:nostr:user1', 100, 'tbtc3');
      const result = debit(ledger, 'did:nostr:user1', 200, 'tbtc3');
      assert.strictEqual(result.success, false);
      assert.strictEqual(result.balance, 100);
    });

    it('should migrate simple string to array on currency credit', () => {
      const ledger = createLedger();
      // First set a simple balance
      setBalance(ledger, 'did:nostr:user1', 500);
      assert.strictEqual(getBalance(ledger, 'did:nostr:user1'), 500);
      // Now add a currency-specific balance — should migrate to array
      credit(ledger, 'did:nostr:user1', 1000, 'tbtc3');
      assert.strictEqual(getBalance(ledger, 'did:nostr:user1', 'tbtc3'), 1000);
      // Old satoshi balance should be preserved in array
      const entry = ledger.entries.find(e => e.url === 'did:nostr:user1');
      assert.ok(Array.isArray(entry.amount));
      const satEntry = entry.amount.find(a => a.currency === 'satoshi');
      assert.strictEqual(parseInt(satEntry.value), 500);
    });

    it('should use array format in entries', () => {
      const ledger = createLedger();
      credit(ledger, 'did:nostr:user1', 1000, 'tbtc3');
      const entry = ledger.entries.find(e => e.url === 'did:nostr:user1');
      assert.ok(Array.isArray(entry.amount));
      assert.strictEqual(entry.amount[0].currency, 'tbtc3');
      assert.strictEqual(entry.amount[0].value, '1000');
    });
  });

  describe('URI format support', () => {
    it('should work with did:nostr URIs', () => {
      const ledger = createLedger();
      credit(ledger, 'did:nostr:de7ecd1e2976a6adb2ffa5f4db81a7d812c8bb6698aa00dcf1e76adb55efd645', 100);
      assert.strictEqual(getBalance(ledger, 'did:nostr:de7ecd1e2976a6adb2ffa5f4db81a7d812c8bb6698aa00dcf1e76adb55efd645'), 100);
    });

    it('should work with WebID URIs', () => {
      const ledger = createLedger();
      credit(ledger, 'https://alice.example/profile/card#me', 500);
      assert.strictEqual(getBalance(ledger, 'https://alice.example/profile/card#me'), 500);
    });

    it('should work with mailto URIs', () => {
      const ledger = createLedger();
      credit(ledger, 'mailto:alice@example.com', 200);
      assert.strictEqual(getBalance(ledger, 'mailto:alice@example.com'), 200);
    });
  });
});
