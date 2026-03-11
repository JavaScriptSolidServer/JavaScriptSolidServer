/**
 * HTTP 402 Payment Required tests
 */

import { describe, it, before, after } from 'node:test';
import assert from 'node:assert';
import crypto from 'crypto';
import { schnorr } from '@noble/curves/secp256k1';
import {
  startTestServer,
  stopTestServer,
  getBaseUrl,
  assertStatus
} from './helpers.js';
import { jcs, sha256Hex } from '../src/mrc20.js';

// Generate a test keypair for NIP-98 auth
const privkey = crypto.randomBytes(32);
const pubkey = Buffer.from(schnorr.getPublicKey(privkey)).toString('hex');

/**
 * Create a NIP-98 auth header for a request
 */
function createNip98Header(url, method = 'GET') {
  const event = {
    pubkey,
    created_at: Math.floor(Date.now() / 1000),
    kind: 27235,
    tags: [
      ['u', url],
      ['method', method]
    ],
    content: ''
  };

  // Compute event id
  const serialized = JSON.stringify([0, event.pubkey, event.created_at, event.kind, event.tags, event.content]);
  event.id = crypto.createHash('sha256').update(serialized).digest('hex');

  // Sign with schnorr
  const sig = schnorr.sign(event.id, privkey);
  event.sig = Buffer.from(sig).toString('hex');

  const token = Buffer.from(JSON.stringify(event)).toString('base64');
  return `Nostr ${token}`;
}

describe('HTTP 402 Pay Middleware', () => {
  const POD_ADDRESS = 'test-pod-address';

  before(async () => {
    await startTestServer({ pay: true, payCost: 10, payAddress: POD_ADDRESS });
  });

  after(async () => {
    await stopTestServer();
  });

  describe('GET /pay/.balance', () => {
    it('should return 401 without auth', async () => {
      const res = await fetch(`${getBaseUrl()}/pay/.balance`);
      assertStatus(res, 401);
    });

    it('should return zero balance for new user', async () => {
      const url = `${getBaseUrl()}/pay/.balance`;
      const res = await fetch(url, {
        headers: { 'Authorization': createNip98Header(url) }
      });
      assertStatus(res, 200);
      const body = await res.json();
      assert.strictEqual(body.balance, 0);
      assert.strictEqual(body.cost, 10);
      assert.strictEqual(body.unit, 'sat');
      assert.ok(body.did.startsWith('did:nostr:'));
    });
  });

  describe('GET /pay/* (paid access)', () => {
    it('should return 401 without auth', async () => {
      const res = await fetch(`${getBaseUrl()}/pay/test-resource`);
      assertStatus(res, 401);
    });

    it('should return 402 with zero balance', async () => {
      const url = `${getBaseUrl()}/pay/test-resource`;
      const res = await fetch(url, {
        headers: { 'Authorization': createNip98Header(url) }
      });
      assertStatus(res, 402);
      const body = await res.json();
      assert.strictEqual(body.error, 'Payment Required');
      assert.strictEqual(body.balance, 0);
      assert.strictEqual(body.cost, 10);
      assert.strictEqual(body.deposit, '/pay/.deposit');
    });
  });

  describe('POST /pay/.deposit', () => {
    it('should return 401 without auth', async () => {
      const url = `${getBaseUrl()}/pay/.deposit`;
      const res = await fetch(url, { method: 'POST', body: 'test' });
      assertStatus(res, 401);
    });

    it('should return 400 without TXO URI', async () => {
      const url = `${getBaseUrl()}/pay/.deposit`;
      const res = await fetch(url, {
        method: 'POST',
        headers: { 'Authorization': createNip98Header(url, 'POST') }
      });
      assertStatus(res, 400);
    });

    it('should return 400 for invalid TXO URI', async () => {
      const url = `${getBaseUrl()}/pay/.deposit`;
      const res = await fetch(url, {
        method: 'POST',
        headers: { 'Authorization': createNip98Header(url, 'POST') },
        body: 'not-a-valid-txo'
      });
      assertStatus(res, 400);
      const body = await res.json();
      assert.ok(body.error.includes('Invalid TXO URI'));
    });
  });

  describe('POST /pay/.deposit (MRC20)', () => {
    function makeStatePair(toAddress, amt = 100) {
      const prevState = {
        profile: 'mono.mrc20.v0.1',
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
        profile: 'mono.mrc20.v0.1',
        prev: sha256Hex(jcs(prevState)),
        seq: 1,
        ticker: 'TEST',
        name: 'Test Token',
        decimals: 0,
        supply: 1000,
        balances: { creator: 1000 - amt, [toAddress]: amt },
        ops: [{ op: 'urn:mono:op:transfer', from: 'creator', to: toAddress, amt }]
      };
      return { prevState, state };
    }

    it('should accept valid MRC20 deposit', async () => {
      const { prevState, state } = makeStatePair(POD_ADDRESS, 500);
      const url = `${getBaseUrl()}/pay/.deposit`;
      const res = await fetch(url, {
        method: 'POST',
        headers: {
          'Authorization': createNip98Header(url, 'POST'),
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ type: 'mrc20', state, prevState })
      });
      assertStatus(res, 200);
      const body = await res.json();
      assert.strictEqual(body.deposited, 500);
      assert.strictEqual(body.ticker, 'TEST');
      assert.strictEqual(body.unit, 'token');
      assert.ok(body.balance >= 500);
    });

    it('should reject MRC20 deposit with broken chain', async () => {
      const { prevState, state } = makeStatePair(POD_ADDRESS);
      state.prev = 'tampered';
      const url = `${getBaseUrl()}/pay/.deposit`;
      const res = await fetch(url, {
        method: 'POST',
        headers: {
          'Authorization': createNip98Header(url, 'POST'),
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ type: 'mrc20', state, prevState })
      });
      assertStatus(res, 400);
      const body = await res.json();
      assert.ok(body.error.includes('State chain break'));
    });

    it('should reject MRC20 deposit to wrong address', async () => {
      const { prevState, state } = makeStatePair('wrong-address');
      const url = `${getBaseUrl()}/pay/.deposit`;
      const res = await fetch(url, {
        method: 'POST',
        headers: {
          'Authorization': createNip98Header(url, 'POST'),
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ type: 'mrc20', state, prevState })
      });
      assertStatus(res, 400);
      const body = await res.json();
      assert.ok(body.error.includes('No transfers'));
    });
  });

  describe('Pay disabled', () => {
    let noPayServer;
    let noPayUrl;

    before(async () => {
      // Start a separate server without pay enabled
      const { createServer } = await import('../src/server.js');
      noPayServer = createServer({ logger: false, forceCloseConnections: true, pay: false });
      await noPayServer.listen({ port: 0, host: '127.0.0.1' });
      const addr = noPayServer.server.address();
      noPayUrl = `http://127.0.0.1:${addr.port}`;
    });

    after(async () => {
      if (noPayServer) await noPayServer.close();
    });

    it('should not intercept /pay/ when disabled', async () => {
      const res = await fetch(`${noPayUrl}/pay/.balance`);
      // Without pay enabled, dotfile security blocks .balance with 403
      assert.ok(res.status === 401 || res.status === 403 || res.status === 404);
    });
  });
});
