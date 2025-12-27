/**
 * LDP (Linked Data Platform) CRUD tests
 */

import { describe, it, before, after, beforeEach } from 'node:test';
import assert from 'node:assert';
import {
  startTestServer,
  stopTestServer,
  request,
  createTestPod,
  assertStatus,
  assertHeader,
  assertHeaderContains
} from './helpers.js';

describe('LDP CRUD Operations', () => {
  let baseUrl;

  before(async () => {
    const result = await startTestServer();
    baseUrl = result.baseUrl;
    await createTestPod('ldptest');
  });

  after(async () => {
    await stopTestServer();
  });

  describe('GET', () => {
    it('should return 404 for non-existent resource', async () => {
      // Must use /public/ path for unauthenticated access
      const res = await request('/ldptest/public/nonexistent.json');
      assertStatus(res, 404);
    });

    it('should return container listing for empty container', async () => {
      const res = await request('/ldptest/public/');

      assertStatus(res, 200);
      assertHeaderContains(res, 'Link', 'Container');
    });

    it('should return resource content', async () => {
      // Create resource first (authenticated)
      await request('/ldptest/public/test.json', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ hello: 'world' }),
        auth: 'ldptest'
      });

      const res = await request('/ldptest/public/test.json');

      assertStatus(res, 200);
      const data = await res.json();
      assert.strictEqual(data.hello, 'world');
    });

    it('should return ETag header', async () => {
      await request('/ldptest/public/etag-test.txt', {
        method: 'PUT',
        body: 'test content',
        auth: 'ldptest'
      });

      const res = await request('/ldptest/public/etag-test.txt');

      assertStatus(res, 200);
      assertHeader(res, 'ETag');
    });
  });

  describe('HEAD', () => {
    it('should return headers without body', async () => {
      await request('/ldptest/public/head-test.txt', {
        method: 'PUT',
        body: 'test content',
        auth: 'ldptest'
      });

      const res = await request('/ldptest/public/head-test.txt', {
        method: 'HEAD'
      });

      assertStatus(res, 200);
      assertHeader(res, 'Content-Type');
      assertHeader(res, 'ETag');

      const body = await res.text();
      assert.strictEqual(body, '');
    });

    it('should return 404 for non-existent', async () => {
      const res = await request('/ldptest/public/no-such-file.txt', {
        method: 'HEAD'
      });

      assertStatus(res, 404);
    });
  });

  describe('PUT', () => {
    it('should create new resource', async () => {
      const res = await request('/ldptest/public/new-resource.json', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ created: true }),
        auth: 'ldptest'
      });

      assertStatus(res, 201);
      assertHeader(res, 'Location');
    });

    it('should update existing resource', async () => {
      // Create
      await request('/ldptest/public/update-me.txt', {
        method: 'PUT',
        body: 'original',
        auth: 'ldptest'
      });

      // Update
      const res = await request('/ldptest/public/update-me.txt', {
        method: 'PUT',
        body: 'updated',
        auth: 'ldptest'
      });

      assertStatus(res, 204);

      // Verify
      const verify = await request('/ldptest/public/update-me.txt');
      const content = await verify.text();
      assert.strictEqual(content, 'updated');
    });

    it('should create parent containers', async () => {
      const res = await request('/ldptest/public/nested/deep/file.txt', {
        method: 'PUT',
        body: 'nested content',
        auth: 'ldptest'
      });

      assertStatus(res, 201);

      // Verify parent exists
      const parent = await request('/ldptest/public/nested/deep/');
      assertStatus(parent, 200);
    });

    it('should create container with PUT to path ending in slash', async () => {
      // Solid spec: PUT to path with trailing / creates container
      const res = await request('/ldptest/public/new-container/', {
        method: 'PUT',
        auth: 'ldptest'
      });

      assertStatus(res, 201);

      // Verify it's a container
      const verify = await request('/ldptest/public/new-container/');
      assertHeaderContains(verify, 'Link', 'Container');
    });
  });

  describe('POST', () => {
    it('should create resource in container', async () => {
      const res = await request('/ldptest/public/', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Slug': 'posted-resource'
        },
        body: JSON.stringify({ posted: true }),
        auth: 'ldptest'
      });

      assertStatus(res, 201);
      assertHeader(res, 'Location');

      // Verify created
      const location = res.headers.get('Location');
      const verify = await request(location);
      assertStatus(verify, 200);
    });

    it('should use Slug header for filename', async () => {
      const res = await request('/ldptest/public/', {
        method: 'POST',
        headers: {
          'Content-Type': 'text/plain',
          'Slug': 'my-custom-name.txt'
        },
        body: 'slug test',
        auth: 'ldptest'
      });

      const location = res.headers.get('Location');
      assert.ok(location.includes('my-custom-name'), 'Should use slug in filename');
    });

    it('should create container with Link header', async () => {
      const res = await request('/ldptest/public/', {
        method: 'POST',
        headers: {
          'Slug': 'new-container',
          'Link': '<http://www.w3.org/ns/ldp#BasicContainer>; rel="type"'
        },
        auth: 'ldptest'
      });

      assertStatus(res, 201);

      const location = res.headers.get('Location');
      assert.ok(location.endsWith('/'), 'Container location should end with /');

      // Verify it's a container
      const verify = await request(location);
      assertHeaderContains(verify, 'Link', 'Container');
    });

    it('should reject POST to non-container', async () => {
      await request('/ldptest/public/file-not-container.txt', {
        method: 'PUT',
        body: 'just a file',
        auth: 'ldptest'
      });

      const res = await request('/ldptest/public/file-not-container.txt', {
        method: 'POST',
        body: 'trying to post',
        auth: 'ldptest'
      });

      assertStatus(res, 405);
    });
  });

  describe('DELETE', () => {
    it('should delete resource', async () => {
      await request('/ldptest/public/to-delete.txt', {
        method: 'PUT',
        body: 'delete me',
        auth: 'ldptest'
      });

      const res = await request('/ldptest/public/to-delete.txt', {
        method: 'DELETE',
        auth: 'ldptest'
      });

      assertStatus(res, 204);

      // Verify deleted
      const verify = await request('/ldptest/public/to-delete.txt');
      assertStatus(verify, 404);
    });

    it('should return 404 for non-existent', async () => {
      const res = await request('/ldptest/public/never-existed.txt', {
        method: 'DELETE',
        auth: 'ldptest'
      });

      assertStatus(res, 404);
    });

    it('should delete container', async () => {
      // Create container
      await request('/ldptest/public/', {
        method: 'POST',
        headers: {
          'Slug': 'container-to-delete',
          'Link': '<http://www.w3.org/ns/ldp#BasicContainer>; rel="type"'
        },
        auth: 'ldptest'
      });

      const res = await request('/ldptest/public/container-to-delete/', {
        method: 'DELETE',
        auth: 'ldptest'
      });

      assertStatus(res, 204);
    });
  });

  describe('OPTIONS', () => {
    it('should return allowed methods', async () => {
      const res = await request('/ldptest/public/', {
        method: 'OPTIONS'
      });

      assertStatus(res, 204);
      const allow = assertHeader(res, 'Allow');
      assert.ok(allow.includes('GET'), 'Should allow GET');
      assert.ok(allow.includes('POST'), 'Should allow POST');
    });

    it('should return CORS headers', async () => {
      const res = await request('/ldptest/public/', {
        method: 'OPTIONS',
        headers: { 'Origin': 'https://app.example.com' }
      });

      assertHeader(res, 'Access-Control-Allow-Origin');
      assertHeader(res, 'Access-Control-Allow-Methods');
    });
  });

  describe('LDP Headers', () => {
    it('should return Link type header for resource', async () => {
      await request('/ldptest/public/resource-link.txt', {
        method: 'PUT',
        body: 'test',
        auth: 'ldptest'
      });

      const res = await request('/ldptest/public/resource-link.txt');

      assertHeaderContains(res, 'Link', 'ldp#Resource');
    });

    it('should return Link type headers for container', async () => {
      const res = await request('/ldptest/public/');

      const link = res.headers.get('Link');
      assert.ok(link.includes('ldp#Resource'), 'Should be LDP Resource');
      assert.ok(link.includes('ldp#Container'), 'Should be LDP Container');
    });

    it('should return WAC-Allow header', async () => {
      const res = await request('/ldptest/public/');

      assertHeader(res, 'WAC-Allow');
    });

    it('should return Accept-Post for containers', async () => {
      const res = await request('/ldptest/public/');

      assertHeader(res, 'Accept-Post');
    });

    it('should return acl Link header for resource', async () => {
      await request('/ldptest/public/acl-test.txt', {
        method: 'PUT',
        body: 'test',
        auth: 'ldptest'
      });

      const res = await request('/ldptest/public/acl-test.txt');
      const link = res.headers.get('Link');

      assert.ok(link.includes('rel="acl"'), 'Should have acl link relation');
      assert.ok(link.includes('acl-test.txt.acl'), 'ACL should be resource.acl');
    });

    it('should return acl Link header for container', async () => {
      const res = await request('/ldptest/public/');
      const link = res.headers.get('Link');

      assert.ok(link.includes('rel="acl"'), 'Should have acl link relation');
      assert.ok(link.includes('.acl'), 'Should link to .acl');
    });
  });
});
