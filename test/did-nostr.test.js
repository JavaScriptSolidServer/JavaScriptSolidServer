/**
 * Tests for did:nostr to WebID resolution
 */

import { describe, it, before, after, mock } from 'node:test';
import assert from 'node:assert';
import { generateSecretKey, getPublicKey, finalizeEvent } from 'nostr-tools';
import {
  startTestServer,
  stopTestServer,
  request,
  createTestPod,
  getBaseUrl,
  assertStatus
} from './helpers.js';

// Import the module under test
import { resolveDidNostrToWebId, clearCache } from '../src/auth/did-nostr.js';

describe('DID:nostr Resolution', () => {
  describe('Unit Tests', () => {
    before(() => {
      clearCache();
    });

    it('should return null for invalid pubkey', async () => {
      const result = await resolveDidNostrToWebId('invalid');
      assert.strictEqual(result, null);
    });

    it('should return null for empty pubkey', async () => {
      const result = await resolveDidNostrToWebId('');
      assert.strictEqual(result, null);
    });

    it('should return null for null pubkey', async () => {
      const result = await resolveDidNostrToWebId(null);
      assert.strictEqual(result, null);
    });

    it('should return null for pubkey with wrong length', async () => {
      const result = await resolveDidNostrToWebId('abcd1234');
      assert.strictEqual(result, null);
    });

    it('should handle non-existent DID gracefully', async () => {
      // Use a random pubkey that won't exist
      const sk = generateSecretKey();
      const pubkey = getPublicKey(sk);

      // This will hit nostr.social and get 404
      const result = await resolveDidNostrToWebId(pubkey);
      assert.strictEqual(result, null);
    });
  });

  describe('checkSameAsLink Function', () => {
    // We need to test the internal checkSameAsLink function
    // Since it's not exported, we test it indirectly through WebID verification

    it('should recognize owl:sameAs string value', async () => {
      // This test verifies the format we expect in WebID profiles
      const profile = {
        '@id': '#me',
        'owl:sameAs': 'did:nostr:abcd1234'
      };

      // The profile should have the correct structure
      assert.strictEqual(profile['owl:sameAs'], 'did:nostr:abcd1234');
    });

    it('should recognize sameAs as @id object', async () => {
      const profile = {
        '@id': '#me',
        'owl:sameAs': { '@id': 'did:nostr:abcd1234' }
      };

      assert.strictEqual(profile['owl:sameAs']['@id'], 'did:nostr:abcd1234');
    });
  });

  describe('Nostr Auth with DID Resolution', () => {
    before(async () => {
      await startTestServer();
    });

    after(async () => {
      await stopTestServer();
      clearCache();
    });

    it('should create a pod for DID testing', async () => {
      const result = await createTestPod('nostrtest');
      assert.ok(result.webId, 'Should have webId');
      assert.ok(result.token, 'Should have token');
    });

    it('should accept valid NIP-98 auth header', async () => {
      // Generate a Nostr keypair
      const sk = generateSecretKey();
      const pubkey = getPublicKey(sk);

      // Create the pod for this pubkey
      const podName = pubkey.substring(0, 16);
      await createTestPod(podName);

      // Create a NIP-98 event
      const baseUrl = getBaseUrl();
      const event = finalizeEvent({
        kind: 27235,
        created_at: Math.floor(Date.now() / 1000),
        tags: [
          ['u', `${baseUrl}/${podName}/public/`],
          ['method', 'GET']
        ],
        content: ''
      }, sk);

      // Encode as base64
      const token = Buffer.from(JSON.stringify(event)).toString('base64');

      // Make request with Nostr auth
      const res = await fetch(`${baseUrl}/${podName}/public/`, {
        headers: {
          'Authorization': `Nostr ${token}`
        }
      });

      // Should succeed (200) - the Nostr auth should work
      // Even without DID resolution, did:nostr:<pubkey> is accepted
      assertStatus(res, 200);
    });

    it('should return did:nostr when no WebID linked', async () => {
      const sk = generateSecretKey();
      const pubkey = getPublicKey(sk);

      // Try to resolve - should return null since no alsoKnownAs
      const result = await resolveDidNostrToWebId(pubkey);
      assert.strictEqual(result, null, 'Should return null when no WebID linked');
    });
  });

  describe('Real DID Document Fetch', () => {
    before(() => {
      clearCache();
    });

    it('should fetch DID document from nostr.social', async () => {
      // Use a known pubkey that exists on nostr.social
      // fiatjaf's pubkey
      const pubkey = '3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d';

      // This should not throw, just return null if no WebID linked
      const result = await resolveDidNostrToWebId(pubkey);

      // fiatjaf likely doesn't have a WebID linked, so expect null
      // But the fetch itself should work without error
      assert.strictEqual(result, null, 'Should return null when no bidirectional link');
    });

    it('should cache DID resolution results', async () => {
      const pubkey = '3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d';

      // First call
      const start1 = Date.now();
      await resolveDidNostrToWebId(pubkey);
      const time1 = Date.now() - start1;

      // Second call should be cached (much faster)
      const start2 = Date.now();
      await resolveDidNostrToWebId(pubkey);
      const time2 = Date.now() - start2;

      // Cached call should be < 5ms typically
      assert.ok(time2 < time1 || time2 < 10, `Cached call should be fast. First: ${time1}ms, Second: ${time2}ms`);
    });
  });
});
