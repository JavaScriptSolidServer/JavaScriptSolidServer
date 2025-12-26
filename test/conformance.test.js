/**
 * Solid Conformance Tests (Simplified)
 *
 * Tests based on solid/solid-crud-tests but using Bearer token auth.
 * Covers the same MUST requirements from the Solid Protocol spec.
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

describe('Solid Protocol Conformance', () => {
  let token;

  before(async () => {
    // Enable conneg for full Turtle support (required for Solid conformance)
    await startTestServer({ conneg: true });
    const pod = await createTestPod('conformance');
    token = pod.token;
  });

  after(async () => {
    await stopTestServer();
  });

  describe('MUST: Create non-container using POST', () => {
    it('creates the resource and returns 201', async () => {
      const res = await request('/conformance/public/', {
        method: 'POST',
        headers: {
          'Content-Type': 'text/turtle',
          'Slug': 'post-created.ttl'
        },
        body: '<#hello> <#linked> <#world> .',
        auth: 'conformance'
      });
      assertStatus(res, 201);
      assert.ok(res.headers.get('Location'), 'Should return Location header');
    });

    it('adds the resource to container listing', async () => {
      const res = await request('/conformance/public/');
      const body = await res.text();
      assert.ok(body.includes('post-created.ttl'), 'Container should list the resource');
    });
  });

  describe('MUST: Create non-container using PUT', () => {
    it('creates the resource', async () => {
      const res = await request('/conformance/public/put-created.ttl', {
        method: 'PUT',
        headers: { 'Content-Type': 'text/turtle' },
        body: '<#hello> <#linked> <#world> .',
        auth: 'conformance'
      });
      assert.ok([200, 201, 204].includes(res.status), `Expected 2xx, got ${res.status}`);
    });

    it('adds the resource to container listing', async () => {
      const res = await request('/conformance/public/');
      const body = await res.text();
      assert.ok(body.includes('put-created.ttl'), 'Container should list the resource');
    });
  });

  describe('MUST: Create container using PUT', () => {
    it('creates container with trailing slash', async () => {
      // First create a resource inside the new container (creates container implicitly)
      const res = await request('/conformance/public/new-container/test.ttl', {
        method: 'PUT',
        headers: { 'Content-Type': 'text/turtle' },
        body: '<#test> <#is> <#here> .',
        auth: 'conformance'
      });
      assert.ok([200, 201, 204].includes(res.status));

      // Container should exist
      const containerRes = await request('/conformance/public/new-container/');
      assertStatus(containerRes, 200);
    });
  });

  describe('MUST: Update using PUT', () => {
    it('overwrites existing resource', async () => {
      // Create
      await request('/conformance/public/update-test.ttl', {
        method: 'PUT',
        headers: { 'Content-Type': 'text/turtle' },
        body: '<#v> <#is> "1" .',
        auth: 'conformance'
      });

      // Update
      const res = await request('/conformance/public/update-test.ttl', {
        method: 'PUT',
        headers: { 'Content-Type': 'text/turtle' },
        body: '<#v> <#is> "2" .',
        auth: 'conformance'
      });
      assertStatus(res, 204);

      // Verify
      const getRes = await request('/conformance/public/update-test.ttl');
      const body = await getRes.text();
      assert.ok(body.includes('"2"'), 'Resource should be updated');
    });
  });

  describe('MUST: Update using PATCH (N3)', () => {
    it('adds triple to existing resource', async () => {
      // Create resource with context for cleaner patch matching
      await request('/conformance/public/patch-test.json', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/ld+json' },
        body: JSON.stringify({
          '@context': { 'ex': 'http://example.org/' },
          '@id': '#me',
          'ex:name': 'Test'
        }),
        auth: 'conformance'
      });

      const patch = `
        @prefix solid: <http://www.w3.org/ns/solid/terms#>.
        @prefix ex: <http://example.org/>.
        _:patch a solid:InsertDeletePatch;
          solid:inserts { <#me> ex:added "yes" }.
      `;
      const res = await request('/conformance/public/patch-test.json', {
        method: 'PATCH',
        headers: { 'Content-Type': 'text/n3' },
        body: patch,
        auth: 'conformance'
      });
      assertStatus(res, 204);

      const getRes = await request('/conformance/public/patch-test.json', {
        headers: { 'Accept': 'application/ld+json' }
      });
      const data = await getRes.json();
      // Check for either prefixed or full URI form
      const added = data['ex:added'] || data['http://example.org/added'];
      assert.strictEqual(added, 'yes');
    });
  });

  describe('MUST: Update using PATCH (SPARQL Update)', () => {
    it('modifies resource with INSERT DATA', async () => {
      await request('/conformance/public/sparql-test.json', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/ld+json' },
        body: JSON.stringify({ '@id': '#item' }),
        auth: 'conformance'
      });

      const sparql = `
        PREFIX ex: <http://example.org/>
        INSERT DATA { <#item> ex:status "active" }
      `;
      const res = await request('/conformance/public/sparql-test.json', {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/sparql-update' },
        body: sparql,
        auth: 'conformance'
      });
      assertStatus(res, 204);
    });
  });

  describe('MUST: Delete resource', () => {
    it('deletes and returns 204', async () => {
      await request('/conformance/public/to-delete.ttl', {
        method: 'PUT',
        headers: { 'Content-Type': 'text/turtle' },
        body: '<#x> <#y> <#z> .',
        auth: 'conformance'
      });

      const res = await request('/conformance/public/to-delete.ttl', {
        method: 'DELETE',
        auth: 'conformance'
      });
      assertStatus(res, 204);

      const getRes = await request('/conformance/public/to-delete.ttl');
      assertStatus(getRes, 404);
    });

    it('removes from container listing', async () => {
      const res = await request('/conformance/public/');
      const body = await res.text();
      assert.ok(!body.includes('to-delete.ttl'), 'Should not be in listing');
    });
  });

  describe('MUST: LDP Headers', () => {
    it('includes Link rel=type for containers', async () => {
      const res = await request('/conformance/public/');
      const link = res.headers.get('Link');
      assert.ok(link.includes('ldp#BasicContainer'), 'Should have BasicContainer type');
      assert.ok(link.includes('ldp#Container'), 'Should have Container type');
    });

    it('includes Link rel=type for resources', async () => {
      const res = await request('/conformance/public/put-created.ttl');
      const link = res.headers.get('Link');
      assert.ok(link.includes('ldp#Resource'), 'Should have Resource type');
    });

    it('includes Link rel=acl', async () => {
      const res = await request('/conformance/public/put-created.ttl');
      const link = res.headers.get('Link');
      assert.ok(link.includes('rel="acl"'), 'Should have acl link');
    });

    it('includes ETag header', async () => {
      const res = await request('/conformance/public/put-created.ttl');
      assert.ok(res.headers.get('ETag'), 'Should have ETag');
    });

    it('includes Allow header on OPTIONS', async () => {
      const res = await request('/conformance/public/', { method: 'OPTIONS' });
      const allow = res.headers.get('Allow');
      assert.ok(allow.includes('GET'), 'Should allow GET');
      assert.ok(allow.includes('POST'), 'Should allow POST');
    });

    it('includes Accept-Post for containers', async () => {
      const res = await request('/conformance/public/', { method: 'OPTIONS' });
      assert.ok(res.headers.get('Accept-Post'), 'Should have Accept-Post');
    });

    it('includes Accept-Put for resources', async () => {
      const res = await request('/conformance/public/put-created.ttl', { method: 'OPTIONS' });
      assert.ok(res.headers.get('Accept-Put'), 'Should have Accept-Put');
    });

    it('includes Accept-Patch for resources', async () => {
      const res = await request('/conformance/public/put-created.ttl', { method: 'OPTIONS' });
      const acceptPatch = res.headers.get('Accept-Patch');
      assert.ok(acceptPatch, 'Should have Accept-Patch');
      assert.ok(acceptPatch.includes('text/n3'), 'Should accept N3');
    });
  });

  describe('MUST: WAC Headers', () => {
    it('includes WAC-Allow header', async () => {
      const res = await request('/conformance/public/');
      assert.ok(res.headers.get('WAC-Allow'), 'Should have WAC-Allow');
    });
  });

  describe('MUST: Conditional Requests', () => {
    it('returns 304 for If-None-Match on GET', async () => {
      const res1 = await request('/conformance/public/put-created.ttl');
      const etag = res1.headers.get('ETag');

      const res2 = await request('/conformance/public/put-created.ttl', {
        headers: { 'If-None-Match': etag }
      });
      assertStatus(res2, 304);
    });

    it('returns 412 for If-Match mismatch on PUT', async () => {
      const res = await request('/conformance/public/put-created.ttl', {
        method: 'PUT',
        headers: {
          'Content-Type': 'text/turtle',
          'If-Match': '"wrong-etag"'
        },
        body: '<#new> <#data> <#here> .',
        auth: 'conformance'
      });
      assertStatus(res, 412);
    });

    it('returns 412 for If-None-Match: * on existing resource', async () => {
      const res = await request('/conformance/public/put-created.ttl', {
        method: 'PUT',
        headers: {
          'Content-Type': 'text/turtle',
          'If-None-Match': '*'
        },
        body: '<#new> <#data> <#here> .',
        auth: 'conformance'
      });
      assertStatus(res, 412);
    });
  });

  describe('MUST: CORS Headers', () => {
    it('includes Access-Control-Allow-Origin', async () => {
      const res = await request('/conformance/public/', {
        headers: { 'Origin': 'https://example.com' }
      });
      const acao = res.headers.get('Access-Control-Allow-Origin');
      assert.ok(acao, 'Should have ACAO header');
    });

    it('includes Access-Control-Expose-Headers', async () => {
      const res = await request('/conformance/public/', {
        headers: { 'Origin': 'https://example.com' }
      });
      const expose = res.headers.get('Access-Control-Expose-Headers');
      assert.ok(expose, 'Should expose headers');
      assert.ok(expose.includes('Location'), 'Should expose Location');
      assert.ok(expose.includes('Link'), 'Should expose Link');
    });

    it('handles preflight OPTIONS', async () => {
      const res = await request('/conformance/public/', {
        method: 'OPTIONS',
        headers: {
          'Origin': 'https://example.com',
          'Access-Control-Request-Method': 'PUT'
        }
      });
      assertStatus(res, 204);
      assert.ok(res.headers.get('Access-Control-Allow-Methods'), 'Should have Allow-Methods');
    });
  });

  describe('MUST: Content Negotiation', () => {
    it('returns JSON-LD by default for RDF resources', async () => {
      const res = await request('/conformance/public/patch-test.json');
      const ct = res.headers.get('Content-Type');
      assert.ok(ct.includes('application/ld+json') || ct.includes('application/json'));
    });
  });

  describe('SHOULD: WebSocket Notifications', () => {
    it('includes Updates-Via header when enabled', async () => {
      // Note: requires server started with notifications: true
      // This test documents the expected behavior
      const res = await request('/conformance/', { method: 'OPTIONS' });
      // Updates-Via may or may not be present depending on server config
      const updatesVia = res.headers.get('Updates-Via');
      if (updatesVia) {
        assert.ok(updatesVia.includes('ws'), 'Should be WebSocket URL');
      }
    });
  });
});
