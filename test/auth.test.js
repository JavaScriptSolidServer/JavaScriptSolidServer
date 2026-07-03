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

    it('should allow any authenticated user with acl:AuthenticatedAgent', async () => {
      await createTestPod('authuser1');
      await createTestPod('authuser2');

      // Create a test resource with acl:AuthenticatedAgent ACL
      const baseUrl = getBaseUrl();

      // First, create a resource (this will create parent containers)
      await request('/authuser1/authenticated-only/test.txt', {
        method: 'PUT',
        headers: { 'Content-Type': 'text/plain' },
        body: 'authenticated content',
        auth: 'authuser1'
      });

      // Now create a custom ACL for the container with acl:AuthenticatedAgent
      // Include owner with Control so they can manage the ACL
      const acl = {
        '@context': { 'acl': 'http://www.w3.org/ns/auth/acl#' },
        '@graph': [
          {
            '@id': '#owner',
            '@type': 'acl:Authorization',
            'acl:agent': { '@id': `${baseUrl}/authuser1/profile/card.jsonld#me` },
            'acl:accessTo': { '@id': `${baseUrl}/authuser1/authenticated-only/` },
            'acl:default': { '@id': `${baseUrl}/authuser1/authenticated-only/` },
            'acl:mode': [
              { '@id': 'acl:Read' },
              { '@id': 'acl:Write' },
              { '@id': 'acl:Control' }
            ]
          },
          {
            '@id': '#authenticated',
            '@type': 'acl:Authorization',
            'acl:agentClass': { '@id': 'acl:AuthenticatedAgent' },
            'acl:accessTo': { '@id': `${baseUrl}/authuser1/authenticated-only/` },
            'acl:default': { '@id': `${baseUrl}/authuser1/authenticated-only/` },
            'acl:mode': [{ '@id': 'acl:Read' }]
          }
        ]
      };

      await request('/authuser1/authenticated-only/.acl', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(acl),
        auth: 'authuser1'
      });

      // Test 1: Anonymous access should be denied
      const res1 = await request('/authuser1/authenticated-only/test.txt');
      assertStatus(res1, 401);

      // Test 2: Owner should have access
      const res2 = await request('/authuser1/authenticated-only/test.txt', { auth: 'authuser1' });
      assertStatus(res2, 200);

      // Test 3: Different authenticated user should also have access (key test!)
      const res3 = await request('/authuser1/authenticated-only/test.txt', { auth: 'authuser2' });
      assertStatus(res3, 200);
    });

    it('should deny POST-created .acl/.meta sidecars without Control on the protected resource', async () => {
      // Regression for the POST .acl sidecar injection: an agent holding only
      // acl:Append on a container (here, the public-append inbox) must not be
      // able to plant an .acl sidecar, which the WAC checker would then treat
      // as the authorization policy for the sibling resource. .meta is not a
      // WAC input, but is gated the same way as a protected Solid sidecar.
      await createTestPod('sidecarvictim');

      const aclBody = JSON.stringify({
        '@context': { acl: 'http://www.w3.org/ns/auth/acl#' },
        '@graph': []
      });

      // Append-only (unauthenticated public append) agent tries to plant victim.acl
      const attackAcl = await request('/sidecarvictim/inbox/', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Slug': 'victim.acl' },
        body: aclBody
      });
      assertStatus(attackAcl, 403);

      // The same trick with a .meta sidecar must also be blocked
      const attackMeta = await request('/sidecarvictim/inbox/', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Slug': 'victim.meta' },
        body: aclBody
      });
      assertStatus(attackMeta, 403);

      // A normal (non-sidecar) POST to the public inbox still works
      const legit = await request('/sidecarvictim/inbox/', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Slug': 'note' },
        body: JSON.stringify({ type: 'note' })
      });
      assertStatus(legit, 201);
    });

    it('should allow the owner (Control) to POST an .acl sidecar', async () => {
      // Owners hold acl:Control, so the sidecar guard must not block them.
      await createTestPod('sidecarowner');

      const res = await request('/sidecarowner/', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Slug': 'owned.acl' },
        body: JSON.stringify({
          '@context': { acl: 'http://www.w3.org/ns/auth/acl#' },
          '@graph': []
        }),
        auth: 'sidecarowner'
      });
      assertStatus(res, 201);
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
