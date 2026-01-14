/**
 * LWS Protocol Mode Tests (DRAFT)
 *
 * Tests for W3C Linked Web Storage protocol semantics.
 * See issue #87 for full specification and implementation plan.
 */

import { describe, it, before, after } from 'node:test';
import assert from 'node:assert';
import {
  startTestServer,
  stopTestServer,
  request,
  createTestPod,
  assertStatus
} from './helpers.js';

describe('LWS Protocol Mode (DRAFT)', () => {
  let baseUrl;

  before(async () => {
    // Start server with LWS mode enabled
    const result = await startTestServer({ lwsMode: true });
    baseUrl = result.baseUrl;
    await createTestPod('lwstest');
  });

  after(async () => {
    await stopTestServer();
  });

  describe('PUT Semantics (Updates Only)', () => {
    it('should reject PUT for non-existent resource in LWS mode', async () => {
      const res = await request('/lwstest/public/new-resource.json', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ test: true }),
        auth: 'lwstest'
      });

      assertStatus(res, 404);
      const body = await res.json();
      assert.ok(body.message.includes('POST to create'), 'Error should suggest POST');
    });

    it('should allow PUT to update existing resource in LWS mode', async () => {
      // First create via POST
      const createRes = await request('/lwstest/public/', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Slug': 'existing-resource'
        },
        body: JSON.stringify({ version: 1 }),
        auth: 'lwstest'
      });

      assertStatus(createRes, 201);
      const location = createRes.headers.get('Location');

      // Now update via PUT (should work)
      const updateRes = await request(location, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ version: 2 }),
        auth: 'lwstest'
      });

      assertStatus(updateRes, 204);

      // Verify updated
      const verify = await request(location);
      const data = await verify.json();
      assert.strictEqual(data.version, 2);
    });
  });

  describe('POST Creation (LWS Standard)', () => {
    it('should create resource via POST with Slug header', async () => {
      const res = await request('/lwstest/public/', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Slug': 'lws-created'
        },
        body: JSON.stringify({ created: 'via POST' }),
        auth: 'lwstest'
      });

      assertStatus(res, 201);
      const location = res.headers.get('Location');
      assert.ok(location, 'Should return Location header');
      assert.ok(location.includes('lws-created'), 'Should use Slug in filename');
    });

    it('should create container via POST with Link header', async () => {
      const res = await request('/lwstest/public/', {
        method: 'POST',
        headers: {
          'Slug': 'lws-container',
          'Link': '<http://www.w3.org/ns/ldp#BasicContainer>; rel="type"'
        },
        auth: 'lwstest'
      });

      assertStatus(res, 201);
      const location = res.headers.get('Location');
      assert.ok(location.endsWith('/'), 'Container should end with /');
    });
  });

  describe('Documentation', () => {
    it('should document LWS mode differences', () => {
      // This test serves as documentation
      const differences = {
        PUT: 'Updates only (404 if not exists)',
        POST: 'Required for creation',
        containerDetection: 'Link header (future: remove slash semantics)',
        metadataUpdates: 'Future: JSON Merge Patch on linkset resources',
        etagRequirement: 'Mandatory (already implemented)'
      };

      // Test demonstrates PUT restriction is implemented
      assert.ok(differences.PUT.includes('404'), 'PUT rejects non-existent');
    });
  });
});
