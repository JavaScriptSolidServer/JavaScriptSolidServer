/**
 * SPARQL Update Tests
 *
 * Tests SPARQL Update support via PATCH method.
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

describe('SPARQL Update', () => {
  before(async () => {
    await startTestServer();
    await createTestPod('sparqltest');
  });

  after(async () => {
    await stopTestServer();
  });

  describe('INSERT DATA', () => {
    it('should insert a triple into existing resource', async () => {
      // Create a resource
      await request('/sparqltest/public/insert-test.json', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/ld+json' },
        body: JSON.stringify({ '@id': '#item', 'http://example.org/name': 'Original' }),
        auth: 'sparqltest'
      });

      // Insert new data via SPARQL Update
      const sparql = `
        PREFIX ex: <http://example.org/>
        INSERT DATA {
          <#item> ex:status "active" .
        }
      `;

      const res = await request('/sparqltest/public/insert-test.json', {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/sparql-update' },
        body: sparql,
        auth: 'sparqltest'
      });
      assertStatus(res, 204);

      // Verify the data was inserted
      const getRes = await request('/sparqltest/public/insert-test.json');
      const data = await getRes.json();
      assert.strictEqual(data['http://example.org/status'], 'active');
      assert.strictEqual(data['http://example.org/name'], 'Original');
    });

    it('should insert multiple triples', async () => {
      await request('/sparqltest/public/multi-insert.json', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/ld+json' },
        body: JSON.stringify({ '@id': '#thing' }),
        auth: 'sparqltest'
      });

      const sparql = `
        PREFIX ex: <http://example.org/>
        INSERT DATA {
          <#thing> ex:prop1 "value1" .
          <#thing> ex:prop2 "value2" .
        }
      `;

      const res = await request('/sparqltest/public/multi-insert.json', {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/sparql-update' },
        body: sparql,
        auth: 'sparqltest'
      });
      assertStatus(res, 204);

      const getRes = await request('/sparqltest/public/multi-insert.json');
      const data = await getRes.json();
      assert.strictEqual(data['http://example.org/prop1'], 'value1');
      assert.strictEqual(data['http://example.org/prop2'], 'value2');
    });
  });

  describe('DELETE DATA', () => {
    it('should delete a triple from existing resource', async () => {
      await request('/sparqltest/public/delete-test.json', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/ld+json' },
        body: JSON.stringify({
          '@id': '#item',
          'http://example.org/keep': 'yes',
          'http://example.org/remove': 'this'
        }),
        auth: 'sparqltest'
      });

      const sparql = `
        PREFIX ex: <http://example.org/>
        DELETE DATA {
          <#item> ex:remove "this" .
        }
      `;

      const res = await request('/sparqltest/public/delete-test.json', {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/sparql-update' },
        body: sparql,
        auth: 'sparqltest'
      });
      assertStatus(res, 204);

      const getRes = await request('/sparqltest/public/delete-test.json');
      const data = await getRes.json();
      assert.strictEqual(data['http://example.org/keep'], 'yes');
      assert.strictEqual(data['http://example.org/remove'], undefined);
    });
  });

  describe('DELETE/INSERT WHERE', () => {
    it('should delete and insert in single operation', async () => {
      await request('/sparqltest/public/update-test.json', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/ld+json' },
        body: JSON.stringify({
          '@id': '#item',
          'http://example.org/version': '1'
        }),
        auth: 'sparqltest'
      });

      const sparql = `
        PREFIX ex: <http://example.org/>
        DELETE { <#item> ex:version "1" }
        INSERT { <#item> ex:version "2" }
        WHERE { <#item> ex:version "1" }
      `;

      const res = await request('/sparqltest/public/update-test.json', {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/sparql-update' },
        body: sparql,
        auth: 'sparqltest'
      });
      assertStatus(res, 204);

      const getRes = await request('/sparqltest/public/update-test.json');
      const data = await getRes.json();
      assert.strictEqual(data['http://example.org/version'], '2');
    });
  });

  describe('Error handling', () => {
    it('should create resource if it does not exist', async () => {
      const sparql = `INSERT DATA { <#x> <http://example.org/p> "v" }`;
      const res = await request('/sparqltest/public/sparql-created.json', {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/sparql-update' },
        body: sparql,
        auth: 'sparqltest'
      });
      // PATCH creates resources in Solid
      assertStatus(res, 201);

      // Verify resource was created
      const getRes = await request('/sparqltest/public/sparql-created.json');
      assertStatus(getRes, 200);
    });

    it('should return 415 for unsupported content type', async () => {
      await request('/sparqltest/public/content-type-test.json', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/ld+json' },
        body: JSON.stringify({ '@id': '#test' }),
        auth: 'sparqltest'
      });

      const res = await request('/sparqltest/public/content-type-test.json', {
        method: 'PATCH',
        headers: { 'Content-Type': 'text/plain' },
        body: 'not a valid patch',
        auth: 'sparqltest'
      });
      assertStatus(res, 415);
    });
  });

  describe('Typed literals', () => {
    it('should handle integer literals', async () => {
      await request('/sparqltest/public/typed-test.json', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/ld+json' },
        body: JSON.stringify({ '@id': '#data' }),
        auth: 'sparqltest'
      });

      const sparql = `
        PREFIX ex: <http://example.org/>
        PREFIX xsd: <http://www.w3.org/2001/XMLSchema#>
        INSERT DATA {
          <#data> ex:count "42"^^xsd:integer .
        }
      `;

      const res = await request('/sparqltest/public/typed-test.json', {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/sparql-update' },
        body: sparql,
        auth: 'sparqltest'
      });
      assertStatus(res, 204);

      const getRes = await request('/sparqltest/public/typed-test.json');
      const data = await getRes.json();
      assert.ok(data['http://example.org/count']);
    });
  });
});
