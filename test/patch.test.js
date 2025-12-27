/**
 * PATCH (N3 Patch) tests
 */

import { describe, it, before, after } from 'node:test';
import assert from 'node:assert';
import {
  startTestServer,
  stopTestServer,
  request,
  createTestPod,
  getBaseUrl,
  assertStatus,
  assertHeader
} from './helpers.js';

describe('PATCH Operations', () => {
  before(async () => {
    await startTestServer();
    await createTestPod('patchtest');
  });

  after(async () => {
    await stopTestServer();
  });

  describe('N3 Patch', () => {
    it('should insert a triple into a JSON-LD resource', async () => {
      // Create initial resource
      const initial = {
        '@context': { 'foaf': 'http://xmlns.com/foaf/0.1/' },
        '@id': '#me',
        'foaf:name': 'Alice'
      };

      await request('/patchtest/public/patch-insert.json', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/ld+json' },
        body: JSON.stringify(initial),
        auth: 'patchtest'
      });

      // Apply N3 Patch to insert a new triple
      const patch = `
        @prefix solid: <http://www.w3.org/ns/solid/terms#>.
        @prefix foaf: <http://xmlns.com/foaf/0.1/>.
        _:patch a solid:InsertDeletePatch;
          solid:inserts { <#me> foaf:mbox <mailto:alice@example.org> }.
      `;

      const res = await request('/patchtest/public/patch-insert.json', {
        method: 'PATCH',
        headers: { 'Content-Type': 'text/n3' },
        body: patch,
        auth: 'patchtest'
      });

      assertStatus(res, 204);

      // Verify the change
      const verify = await request('/patchtest/public/patch-insert.json');
      const data = await verify.json();

      assert.ok(data['foaf:mbox'], 'Should have new mbox property');
    });

    it('should delete a triple from a JSON-LD resource', async () => {
      // Create initial resource with multiple properties
      const initial = {
        '@context': { 'foaf': 'http://xmlns.com/foaf/0.1/' },
        '@id': '#me',
        'foaf:name': 'Bob',
        'foaf:age': 30
      };

      await request('/patchtest/public/patch-delete.json', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/ld+json' },
        body: JSON.stringify(initial),
        auth: 'patchtest'
      });

      // Apply N3 Patch to delete the age property
      const patch = `
        @prefix solid: <http://www.w3.org/ns/solid/terms#>.
        @prefix foaf: <http://xmlns.com/foaf/0.1/>.
        _:patch a solid:InsertDeletePatch;
          solid:deletes { <#me> foaf:age 30 }.
      `;

      const res = await request('/patchtest/public/patch-delete.json', {
        method: 'PATCH',
        headers: { 'Content-Type': 'text/n3' },
        body: patch,
        auth: 'patchtest'
      });

      assertStatus(res, 204);

      // Verify the change
      const verify = await request('/patchtest/public/patch-delete.json');
      const data = await verify.json();

      assert.ok(!data['foaf:age'], 'Should not have age property');
      assert.strictEqual(data['foaf:name'], 'Bob', 'Should still have name');
    });

    it('should insert and delete in same patch', async () => {
      // Create initial resource
      const initial = {
        '@context': { 'foaf': 'http://xmlns.com/foaf/0.1/' },
        '@id': '#me',
        'foaf:name': 'Charlie'
      };

      await request('/patchtest/public/patch-both.json', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/ld+json' },
        body: JSON.stringify(initial),
        auth: 'patchtest'
      });

      // Apply N3 Patch to change name
      const patch = `
        @prefix solid: <http://www.w3.org/ns/solid/terms#>.
        @prefix foaf: <http://xmlns.com/foaf/0.1/>.
        _:patch a solid:InsertDeletePatch;
          solid:deletes { <#me> foaf:name "Charlie" };
          solid:inserts { <#me> foaf:name "Charles" }.
      `;

      const res = await request('/patchtest/public/patch-both.json', {
        method: 'PATCH',
        headers: { 'Content-Type': 'text/n3' },
        body: patch,
        auth: 'patchtest'
      });

      assertStatus(res, 204);

      // Verify the change
      const verify = await request('/patchtest/public/patch-both.json');
      const data = await verify.json();

      assert.strictEqual(data['foaf:name'], 'Charles', 'Name should be updated');
    });

    it('should add a new subject node', async () => {
      // Create initial resource with @graph
      const initial = {
        '@context': { 'foaf': 'http://xmlns.com/foaf/0.1/' },
        '@graph': [
          { '@id': '#alice', 'foaf:name': 'Alice' }
        ]
      };

      await request('/patchtest/public/patch-newnode.json', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/ld+json' },
        body: JSON.stringify(initial),
        auth: 'patchtest'
      });

      // Add a new person
      const patch = `
        @prefix solid: <http://www.w3.org/ns/solid/terms#>.
        @prefix foaf: <http://xmlns.com/foaf/0.1/>.
        _:patch a solid:InsertDeletePatch;
          solid:inserts { <#bob> foaf:name "Bob" }.
      `;

      const res = await request('/patchtest/public/patch-newnode.json', {
        method: 'PATCH',
        headers: { 'Content-Type': 'text/n3' },
        body: patch,
        auth: 'patchtest'
      });

      assertStatus(res, 204);

      // Verify the change
      const verify = await request('/patchtest/public/patch-newnode.json');
      const data = await verify.json();

      assert.ok(data['@graph'], 'Should have @graph');
      assert.strictEqual(data['@graph'].length, 2, 'Should have 2 nodes');
    });
  });

  describe('PATCH Error Handling', () => {
    it('should return 415 for unsupported content type', async () => {
      // Create a resource first
      await request('/patchtest/public/patch-error.json', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ test: true }),
        auth: 'patchtest'
      });

      const res = await request('/patchtest/public/patch-error.json', {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ op: 'add' }),
        auth: 'patchtest'
      });

      assertStatus(res, 415);
    });

    it('should create resource if it does not exist', async () => {
      const patch = `
        @prefix solid: <http://www.w3.org/ns/solid/terms#>.
        _:patch a solid:InsertDeletePatch;
          solid:inserts { <#me> <http://example.org/p> "test" }.
      `;

      const res = await request('/patchtest/public/patch-created.json', {
        method: 'PATCH',
        headers: { 'Content-Type': 'text/n3' },
        body: patch,
        auth: 'patchtest'
      });

      // PATCH creates resources in Solid
      assertStatus(res, 201);

      // Verify resource was created with the inserted data
      const getRes = await request('/patchtest/public/patch-created.json');
      assertStatus(getRes, 200);
    });

    it('should return 409 when patching non-JSON-LD resource', async () => {
      // Create a plain text resource
      await request('/patchtest/public/plain.txt', {
        method: 'PUT',
        headers: { 'Content-Type': 'text/plain' },
        body: 'Hello World',
        auth: 'patchtest'
      });

      const patch = `
        @prefix solid: <http://www.w3.org/ns/solid/terms#>.
        _:patch a solid:InsertDeletePatch;
          solid:inserts { <#me> <http://example.org/p> "test" }.
      `;

      const res = await request('/patchtest/public/plain.txt', {
        method: 'PATCH',
        headers: { 'Content-Type': 'text/n3' },
        body: patch,
        auth: 'patchtest'
      });

      assertStatus(res, 409);
    });

    it('should return 409 for PATCH to container', async () => {
      const patch = `
        @prefix solid: <http://www.w3.org/ns/solid/terms#>.
        _:patch a solid:InsertDeletePatch;
          solid:inserts { <#me> <http://example.org/p> "test" }.
      `;

      const res = await request('/patchtest/public/', {
        method: 'PATCH',
        headers: { 'Content-Type': 'text/n3' },
        body: patch,
        auth: 'patchtest'
      });

      assertStatus(res, 409);
    });

    it('should require authentication for PATCH', async () => {
      // Create a resource first
      await request('/patchtest/public/patch-auth.json', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ test: true }),
        auth: 'patchtest'
      });

      const patch = `
        @prefix solid: <http://www.w3.org/ns/solid/terms#>.
        _:patch a solid:InsertDeletePatch;
          solid:inserts { <#me> <http://example.org/p> "test" }.
      `;

      // Try without auth
      const res = await request('/patchtest/public/patch-auth.json', {
        method: 'PATCH',
        headers: { 'Content-Type': 'text/n3' },
        body: patch
        // No auth
      });

      assertStatus(res, 401);
    });
  });
});
