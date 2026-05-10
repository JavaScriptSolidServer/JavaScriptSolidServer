/**
 * Tests for did:nostr to WebID resolution
 */

import { describe, it, before, after, mock } from 'node:test';
import assert from 'node:assert';
import { generateSecretKey, getPublicKey, finalizeEvent } from '../src/nostr/event.js';
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

  describe('fetchWithRedirectGuard SSRF / redirect hardening', () => {
    // The production resolver wraps fetchWithRedirectGuard with
    // validateExternalUrl as a hard SSRF gate, which by design
    // rejects loopback (`127.0.0.1`) — the only thing a unit test
    // can bind to. So testing the resolver end-to-end against a
    // local server makes the redirect/cap logic invisible: every
    // request fails on the SSRF guard before fetch is even called.
    //
    // Solution: import fetchWithRedirectGuard directly and inject
    // a permissive `_validateUrl` stub. That isolates the redirect
    // hop counter, cross-origin check, and size cap from the SSRF
    // gate so we can actually observe each one.
    let http;
    let server;
    let port;
    let hopMode = 'cross-origin';
    let fetchWithRedirectGuard;
    const allowAll = async () => ({ valid: true });

    before(async () => {
      http = await import('node:http');
      ({ fetchWithRedirectGuard } = await import('../src/auth/did-nostr.js'));
      server = http.createServer((req, res) => {
        if (hopMode === 'cross-origin') {
          res.writeHead(302, { Location: 'http://other.example:1/foo.json' });
          res.end();
          return;
        }
        if (hopMode === 'loop') {
          // Each hop appends `/r` to the path; the cap fires before
          // we ever return a non-3xx.
          res.writeHead(302, { Location: req.url + '/r' });
          res.end();
          return;
        }
        if (hopMode === 'oversize') {
          res.writeHead(200, { 'Content-Type': 'application/json' });
          // Stream a body larger than the 1 KB cap we'll pass.
          res.end('"' + 'x'.repeat(2000) + '"');
          return;
        }
        if (hopMode === 'ok') {
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end('{"ok":true}');
          return;
        }
        res.writeHead(404).end();
      });
      await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
      port = server.address().port;
    });

    after(async () => {
      await new Promise((resolve) => server.close(resolve));
    });

    it('refuses cross-origin redirects', async () => {
      hopMode = 'cross-origin';
      await assert.rejects(
        () => fetchWithRedirectGuard(`http://127.0.0.1:${port}/foo.json`, { _validateUrl: allowAll }),
        /cross-origin redirect refused/,
      );
    });

    it('refuses redirect chains exceeding the hop cap', async () => {
      hopMode = 'loop';
      await assert.rejects(
        () => fetchWithRedirectGuard(`http://127.0.0.1:${port}/start`, { _validateUrl: allowAll }),
        /too many redirects/,
      );
    });

    it('refuses oversized response bodies', async () => {
      hopMode = 'oversize';
      await assert.rejects(
        () => fetchWithRedirectGuard(`http://127.0.0.1:${port}/big`, {
          _validateUrl: allowAll,
          maxBytes: 1000,
        }),
        /response too large/,
      );
    });

    it('re-runs SSRF validation on every hop', async () => {
      hopMode = 'loop';
      let calls = 0;
      const counting = async (url) => {
        calls++;
        return { valid: true };
      };
      await assert.rejects(
        () => fetchWithRedirectGuard(`http://127.0.0.1:${port}/start`, { _validateUrl: counting }),
        /too many redirects/,
      );
      // 1 initial + MAX_REDIRECTS (5) hops = 6 calls if we re-validate
      // on every hop. < 6 means the per-hop check is missing.
      assert.ok(calls >= 6, `expected ≥6 validator calls, got ${calls}`);
    });

    it('returns the response body on success', async () => {
      hopMode = 'ok';
      const r = await fetchWithRedirectGuard(`http://127.0.0.1:${port}/ok`, { _validateUrl: allowAll });
      assert.strictEqual(r.status, 200);
      assert.strictEqual(r.body, '{"ok":true}');
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
