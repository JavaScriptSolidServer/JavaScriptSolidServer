/**
 * Authentication and Authorization tests
 */

import { describe, it, before, after } from 'node:test';
import assert from 'node:assert';
import {
  startTestServer,
  stopTestServer,
  request,
  createTestPod,
  getPodToken,
  getBaseUrl,
  assertStatus,
  assertHeader
} from './helpers.js';

describe('Authentication', () => {
  before(async () => {
    await startTestServer();
  });

  after(async () => {
    await stopTestServer();
  });

  describe('Token Authentication', () => {
    it('should return token on pod creation', async () => {
      const result = await createTestPod('authtest');

      assert.ok(result.token, 'Should return a token');
      assert.ok(result.token.includes('.'), 'Token should have signature');
    });

    it('should allow authenticated access to private resources', async () => {
      await createTestPod('privatetest');

      // Should succeed with auth
      const res = await request('/privatetest/private/', { auth: 'privatetest' });
      assertStatus(res, 200);
    });

    it('should deny unauthenticated access to private resources', async () => {
      await createTestPod('denytest');

      // Should fail without auth
      const res = await request('/denytest/private/');
      assertStatus(res, 401);
    });

    it('should return 403 for wrong user accessing private resources', async () => {
      await createTestPod('user1');
      await createTestPod('user2');

      // User2 trying to access User1's private folder
      const res = await request('/user1/private/', { auth: 'user2' });
      assertStatus(res, 403);
    });

    it('should accept Bearer token format', async () => {
      await createTestPod('bearertest');
      const token = getPodToken('bearertest');

      const res = await fetch(`${getBaseUrl()}/bearertest/private/`, {
        headers: { 'Authorization': `Bearer ${token}` }
      });
      assertStatus(res, 200);
    });

    it('should reject invalid tokens', async () => {
      await createTestPod('invalidtest');

      const res = await fetch(`${getBaseUrl()}/invalidtest/private/`, {
        headers: { 'Authorization': 'Bearer invalid.token' }
      });
      assertStatus(res, 401);
    });
  });

  describe('WAC Enforcement', () => {
    it('should allow public read on pod root', async () => {
      await createTestPod('publicread');

      // Public folder should be readable without auth
      const res = await request('/publicread/public/');
      assertStatus(res, 200);
    });

    it('should allow public read on explicit public folders', async () => {
      await createTestPod('explicitpublic');

      // Root ACL has public read default
      const res = await request('/explicitpublic/');
      assertStatus(res, 200);
    });

    it('should allow authenticated write to owned resources', async () => {
      await createTestPod('writetest');

      const res = await request('/writetest/public/test.txt', {
        method: 'PUT',
        body: 'test content',
        auth: 'writetest'
      });
      assertStatus(res, 201);
    });

    it('should deny unauthenticated write', async () => {
      await createTestPod('nowrite');

      const res = await request('/nowrite/public/test.txt', {
        method: 'PUT',
        body: 'test content'
      });
      assertStatus(res, 401);
    });

    it('should deny other user write to owned resources', async () => {
      await createTestPod('owner1');
      await createTestPod('attacker');

      const res = await request('/owner1/public/test.txt', {
        method: 'PUT',
        body: 'malicious content',
        auth: 'attacker'
      });
      assertStatus(res, 403);
    });

    it('should allow public append to inbox', async () => {
      await createTestPod('inboxtest');

      // POST to inbox should work for anyone (public append)
      const res = await request('/inboxtest/inbox/', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Slug': 'notification'
        },
        body: JSON.stringify({ type: 'notification' })
      });
      assertStatus(res, 201);
    });

    it('should deny public read on inbox', async () => {
      await createTestPod('inboxread');

      // GET inbox should fail for unauthenticated
      const res = await request('/inboxread/inbox/');
      assertStatus(res, 401);
    });
  });

  describe('WAC-Allow Header', () => {
    it('should include user permissions for authenticated requests', async () => {
      await createTestPod('wacallow');

      const res = await request('/wacallow/public/', { auth: 'wacallow' });
      const wacAllow = res.headers.get('WAC-Allow');

      assert.ok(wacAllow, 'Should have WAC-Allow header');
      assert.ok(wacAllow.includes('user='), 'Should include user permissions');
    });

    it('should include public permissions', async () => {
      await createTestPod('wacpublic');

      const res = await request('/wacpublic/public/');
      const wacAllow = res.headers.get('WAC-Allow');

      assert.ok(wacAllow, 'Should have WAC-Allow header');
      assert.ok(wacAllow.includes('public='), 'Should include public permissions');
    });
  });
});
