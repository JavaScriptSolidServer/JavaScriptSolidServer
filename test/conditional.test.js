/**
 * Conditional Request Tests
 *
 * Tests If-Match and If-None-Match header support.
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

describe('Conditional Requests', () => {
  before(async () => {
    await startTestServer();
    await createTestPod('condtest');
  });

  after(async () => {
    await stopTestServer();
  });

  describe('If-None-Match on GET', () => {
    it('should return 304 Not Modified when ETag matches', async () => {
      // Create a resource
      await request('/condtest/public/etag-test.json', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/ld+json' },
        body: JSON.stringify({ '@id': '#test', 'http://example.org/value': 1 }),
        auth: 'condtest'
      });

      // Get the ETag
      const res1 = await request('/condtest/public/etag-test.json');
      const etag = res1.headers.get('ETag');
      assert.ok(etag, 'Response should have ETag');

      // Request with matching If-None-Match
      const res2 = await request('/condtest/public/etag-test.json', {
        headers: { 'If-None-Match': etag }
      });
      assertStatus(res2, 304);
    });

    it('should return 200 when ETag does not match', async () => {
      const res = await request('/condtest/public/etag-test.json', {
        headers: { 'If-None-Match': '"different-etag"' }
      });
      assertStatus(res, 200);
    });

    it('should return 304 with If-None-Match: *', async () => {
      const res = await request('/condtest/public/etag-test.json', {
        headers: { 'If-None-Match': '*' }
      });
      assertStatus(res, 304);
    });
  });

  describe('If-Match on PUT', () => {
    it('should succeed when ETag matches', async () => {
      // Create resource
      await request('/condtest/public/match-test.json', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/ld+json' },
        body: JSON.stringify({ '@id': '#test', 'http://example.org/v': 1 }),
        auth: 'condtest'
      });

      // Get ETag
      const res1 = await request('/condtest/public/match-test.json');
      const etag = res1.headers.get('ETag');

      // Update with matching If-Match
      const res2 = await request('/condtest/public/match-test.json', {
        method: 'PUT',
        headers: {
          'Content-Type': 'application/ld+json',
          'If-Match': etag
        },
        body: JSON.stringify({ '@id': '#test', 'http://example.org/v': 2 }),
        auth: 'condtest'
      });
      assertStatus(res2, 204);
    });

    it('should return 412 when ETag does not match', async () => {
      const res = await request('/condtest/public/match-test.json', {
        method: 'PUT',
        headers: {
          'Content-Type': 'application/ld+json',
          'If-Match': '"wrong-etag"'
        },
        body: JSON.stringify({ '@id': '#test', 'http://example.org/v': 3 }),
        auth: 'condtest'
      });
      assertStatus(res, 412);
    });

    it('should succeed with If-Match: * on existing resource', async () => {
      const res = await request('/condtest/public/match-test.json', {
        method: 'PUT',
        headers: {
          'Content-Type': 'application/ld+json',
          'If-Match': '*'
        },
        body: JSON.stringify({ '@id': '#test', 'http://example.org/v': 4 }),
        auth: 'condtest'
      });
      assertStatus(res, 204);
    });

    it('should return 412 with If-Match: * on non-existent resource', async () => {
      const res = await request('/condtest/public/nonexistent.json', {
        method: 'PUT',
        headers: {
          'Content-Type': 'application/ld+json',
          'If-Match': '*'
        },
        body: JSON.stringify({ '@id': '#new' }),
        auth: 'condtest'
      });
      assertStatus(res, 412);
    });
  });

  describe('If-None-Match on PUT', () => {
    it('should succeed with If-None-Match: * on new resource', async () => {
      const res = await request('/condtest/public/create-only.json', {
        method: 'PUT',
        headers: {
          'Content-Type': 'application/ld+json',
          'If-None-Match': '*'
        },
        body: JSON.stringify({ '@id': '#new' }),
        auth: 'condtest'
      });
      assertStatus(res, 201);
    });

    it('should return 412 with If-None-Match: * on existing resource', async () => {
      const res = await request('/condtest/public/create-only.json', {
        method: 'PUT',
        headers: {
          'Content-Type': 'application/ld+json',
          'If-None-Match': '*'
        },
        body: JSON.stringify({ '@id': '#update' }),
        auth: 'condtest'
      });
      assertStatus(res, 412);
    });
  });

  describe('If-Match on DELETE', () => {
    it('should succeed when ETag matches', async () => {
      // Create resource
      await request('/condtest/public/delete-match.json', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/ld+json' },
        body: JSON.stringify({ '@id': '#delete' }),
        auth: 'condtest'
      });

      // Get ETag
      const res1 = await request('/condtest/public/delete-match.json');
      const etag = res1.headers.get('ETag');

      // Delete with matching If-Match
      const res2 = await request('/condtest/public/delete-match.json', {
        method: 'DELETE',
        headers: { 'If-Match': etag },
        auth: 'condtest'
      });
      assertStatus(res2, 204);
    });

    it('should return 412 when ETag does not match', async () => {
      // Create resource
      await request('/condtest/public/delete-nomatch.json', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/ld+json' },
        body: JSON.stringify({ '@id': '#delete' }),
        auth: 'condtest'
      });

      const res = await request('/condtest/public/delete-nomatch.json', {
        method: 'DELETE',
        headers: { 'If-Match': '"wrong-etag"' },
        auth: 'condtest'
      });
      assertStatus(res, 412);
    });
  });

  describe('If-Match on PATCH', () => {
    it('should succeed when ETag matches', async () => {
      // Create resource
      await request('/condtest/public/patch-match.json', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/ld+json' },
        body: JSON.stringify({ '@id': '#test', 'http://example.org/name': 'Original' }),
        auth: 'condtest'
      });

      // Get ETag
      const res1 = await request('/condtest/public/patch-match.json');
      const etag = res1.headers.get('ETag');

      // Patch with matching If-Match
      const patch = `
        @prefix solid: <http://www.w3.org/ns/solid/terms#>.
        _:patch a solid:InsertDeletePatch;
          solid:inserts { <#test> <http://example.org/updated> "true" }.
      `;
      const res2 = await request('/condtest/public/patch-match.json', {
        method: 'PATCH',
        headers: {
          'Content-Type': 'text/n3',
          'If-Match': etag
        },
        body: patch,
        auth: 'condtest'
      });
      assertStatus(res2, 204);
    });

    it('should return 412 when ETag does not match', async () => {
      const patch = `
        @prefix solid: <http://www.w3.org/ns/solid/terms#>.
        _:patch a solid:InsertDeletePatch;
          solid:inserts { <#test> <http://example.org/bad> "true" }.
      `;
      const res = await request('/condtest/public/patch-match.json', {
        method: 'PATCH',
        headers: {
          'Content-Type': 'text/n3',
          'If-Match': '"wrong-etag"'
        },
        body: patch,
        auth: 'condtest'
      });
      assertStatus(res, 412);
    });
  });
});
