/**
 * PATCH (N3 Patch) tests
 */

import { describe, it, before, after } from 'node:test';
import assert from 'node:assert';
import fs from 'fs-extra';
import path from 'path';
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

    it('should handle semicolon shorthand and rdf:type "a" keyword', async () => {
      // Create initial resource with @graph
      const initial = {
        '@context': { 'solid': 'http://www.w3.org/ns/solid/terms#' },
        '@graph': []
      };

      await request('/patchtest/public/patch-semicolon.json', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/ld+json' },
        body: JSON.stringify(initial),
        auth: 'patchtest'
      });

      // Use semicolons and 'a' keyword (Turtle shorthand)
      const patch = `
        @prefix solid: <http://www.w3.org/ns/solid/terms#>.
        @prefix wf: <http://www.w3.org/2005/01/wf/flow#>.
        _:patch a solid:InsertDeletePatch;
          solid:inserts {
            <#reg1> a solid:TypeRegistration;
              solid:forClass wf:Tracker;
              solid:instance <https://example.com/todo/data.jsonld#this>.
          }.
      `;

      const res = await request('/patchtest/public/patch-semicolon.json', {
        method: 'PATCH',
        headers: { 'Content-Type': 'text/n3' },
        body: patch,
        auth: 'patchtest'
      });

      assertStatus(res, 204);

      // Verify all three triples were inserted
      const verify = await request('/patchtest/public/patch-semicolon.json');
      const data = await verify.json();
      const node = data['@graph'].find(n => n['@id'] && n['@id'].includes('#reg1'));
      assert.ok(node, 'Should have the reg1 node');

      // Check rdf:type value (from 'a' keyword)
      const rdfType = node['@type'] || node['rdf:type'] || node['http://www.w3.org/1999/02/22-rdf-syntax-ns#type'];
      assert.ok(rdfType, 'Should have rdf:type (from "a" keyword)');
      const typeId = rdfType['@id'] || rdfType;
      assert.ok(String(typeId).includes('TypeRegistration'), `rdf:type should be TypeRegistration, got ${typeId}`);

      // Check solid:forClass value
      const forClass = node['solid:forClass'];
      assert.ok(forClass, 'Should have solid:forClass');
      const forClassId = forClass['@id'] || forClass;
      assert.ok(String(forClassId).includes('Tracker'), `solid:forClass should be Tracker, got ${forClassId}`);

      // Check solid:instance value (contains a dot in the IRI - tests IRI splitting)
      const instance = node['solid:instance'];
      assert.ok(instance, 'Should have solid:instance');
      const instanceId = instance['@id'] || instance;
      assert.strictEqual(instanceId, 'https://example.com/todo/data.jsonld#this',
        'solid:instance should have full IRI preserved');
    });
  });

  describe('Quad-based patching (chat files)', () => {
    const base = () => `${getBaseUrl()}/patchtest/public/chat.ttl`;

    it('creates a resource with typed literals, prefixed names and multi-line strings intact', async () => {
      const patch = `
        @prefix solid: <http://www.w3.org/ns/solid/terms#>.
        @prefix dct: <http://purl.org/dc/terms/>.
        @prefix sioc: <http://rdfs.org/sioc/ns#>.
        @prefix foaf: <http://xmlns.com/foaf/0.1/>.
        @prefix wf: <http://www.w3.org/2005/01/wf/flow#>.
        @prefix xsd: <http://www.w3.org/2001/XMLSchema#>.
        _:p a solid:InsertDeletePatch; solid:inserts {
          <index.ttl#this> wf:message <#m1>.
          <#m1> dct:created "2026-10-22T10:00:00Z"^^xsd:dateTime;
            sioc:content \"\"\"two lines; with a dot.
and a "quote" end\"\"\";
            foaf:maker <did:nostr:5a3f1927662535ffee11f2457200f0fe6ea3fcd7b00aee4771855eda74944ede>.
        }.`;
      const res = await request('/patchtest/public/chat.ttl', {
        method: 'PATCH', headers: { 'Content-Type': 'text/n3' }, body: patch, auth: 'patchtest'
      });
      assertStatus(res, 201);

      // The test server runs without conneg, so read the stored JSON-LD.
      const json = await (await request('/patchtest/public/chat.ttl')).json();
      const nodes = json['@graph'] || [json];
      const node = nodes.find(n => String(n['@id']).includes('#m1'));
      assert.ok(node, 'message node stored');
      assert.deepStrictEqual(node['dc:created'], { '@value': '2026-10-22T10:00:00Z', '@type': 'xsd:dateTime' }, 'typed literal kept');
      assert.strictEqual(node['http://rdfs.org/sioc/ns#content'], 'two lines; with a dot.\nand a "quote" end', 'multi-line content kept');
      assert.strictEqual(node['foaf:maker']['@id'], 'did:nostr:5a3f1927662535ffee11f2457200f0fe6ea3fcd7b00aee4771855eda74944ede', 'maker kept');
      const chat = nodes.find(n => String(n['@id']).includes('index.ttl#this'));
      assert.ok(chat && chat['http://www.w3.org/2005/01/wf/flow#message'], 'relative IRI resolved against the resource and link kept');
    });

    it('appends to an existing day file without touching other messages', async () => {
      const patch = `
        @prefix solid: <http://www.w3.org/ns/solid/terms#>.
        @prefix sioc: <http://rdfs.org/sioc/ns#>.
        _:p a solid:InsertDeletePatch; solid:inserts { <#m2> sioc:content "second" }.`;
      const res = await request('/patchtest/public/chat.ttl', {
        method: 'PATCH', headers: { 'Content-Type': 'text/n3' }, body: patch, auth: 'patchtest'
      });
      assertStatus(res, 204);
      const text = JSON.stringify(await (await request('/patchtest/public/chat.ttl')).json());
      assert.ok(text.includes('"second"'), 'new message present');
      assert.ok(text.includes('2026-10-22T10:00:00Z'), 'earlier message still present');
    });

    it('applies a where clause once and rejects a non-matching one with 409', async () => {
      const edit = (old, text) => `
        @prefix solid: <http://www.w3.org/ns/solid/terms#>.
        @prefix sioc: <http://rdfs.org/sioc/ns#>.
        _:p a solid:InsertDeletePatch;
          solid:where { <#m2> sioc:content ?old };
          solid:deletes { <#m2> sioc:content ?old };
          solid:inserts { <#m2> sioc:content "${text}" }.`;
      const res = await request('/patchtest/public/chat.ttl', {
        method: 'PATCH', headers: { 'Content-Type': 'text/n3' }, body: edit('second', 'second, edited'), auth: 'patchtest'
      });
      assertStatus(res, 204);
      const text = JSON.stringify(await (await request('/patchtest/public/chat.ttl')).json());
      assert.ok(text.includes('"second, edited"') && !text.includes('"second"'), 'content replaced');

      const miss = `
        @prefix solid: <http://www.w3.org/ns/solid/terms#>.
        @prefix sioc: <http://rdfs.org/sioc/ns#>.
        _:p a solid:InsertDeletePatch;
          solid:where { <#nope> sioc:content ?old };
          solid:deletes { <#nope> sioc:content ?old }.`;
      const bad = await request('/patchtest/public/chat.ttl', {
        method: 'PATCH', headers: { 'Content-Type': 'text/n3' }, body: miss, auth: 'patchtest'
      });
      assertStatus(bad, 409);
    });

    it('rejects a delete of a triple that is not there with 409', async () => {
      const patch = `
        @prefix solid: <http://www.w3.org/ns/solid/terms#>.
        @prefix sioc: <http://rdfs.org/sioc/ns#>.
        _:p a solid:InsertDeletePatch; solid:deletes { <#m2> sioc:content "never" }.`;
      const res = await request('/patchtest/public/chat.ttl', {
        method: 'PATCH', headers: { 'Content-Type': 'text/n3' }, body: patch, auth: 'patchtest'
      });
      assertStatus(res, 409);
    });

    it('lets the public append (insert-only) under acl:Append but not delete', async () => {
      const acl = {
        '@context': { acl: 'http://www.w3.org/ns/auth/acl#', foaf: 'http://xmlns.com/foaf/0.1/' },
        '@graph': [
          { '@id': '#owner', '@type': 'acl:Authorization', 'acl:agent': { '@id': `${getBaseUrl()}/patchtest/profile/card.jsonld#me` },
            'acl:accessTo': { '@id': './' }, 'acl:default': { '@id': './' },
            'acl:mode': [{ '@id': 'acl:Read' }, { '@id': 'acl:Write' }, { '@id': 'acl:Control' }] },
          { '@id': '#public', '@type': 'acl:Authorization', 'acl:agentClass': { '@id': 'foaf:Agent' },
            'acl:accessTo': { '@id': './' }, 'acl:default': { '@id': './' },
            'acl:mode': [{ '@id': 'acl:Read' }, { '@id': 'acl:Append' }] }
        ]
      };
      let res = await request('/patchtest/public/room/.acl', {
        method: 'PUT', headers: { 'Content-Type': 'application/ld+json' }, body: JSON.stringify(acl), auth: 'patchtest'
      });
      assert.ok([200, 201, 204].includes(res.status), `acl stored: ${res.status}`);

      const insert = `
        @prefix solid: <http://www.w3.org/ns/solid/terms#>.
        @prefix sioc: <http://rdfs.org/sioc/ns#>.
        _:p a solid:InsertDeletePatch; solid:inserts { <#a1> sioc:content "anonymous append" }.`;
      res = await request('/patchtest/public/room/2026/10/22/chat.ttl', {
        method: 'PATCH', headers: { 'Content-Type': 'text/n3' }, body: insert
      });
      assertStatus(res, 201, 'public append creates the day file');
      res = await request('/patchtest/public/room/2026/10/22/chat.ttl', {
        method: 'PATCH', headers: { 'Content-Type': 'text/n3' }, body: insert.replace('#a1', '#a2')
      });
      assertStatus(res, 204, 'public append to an existing day file');

      const remove = `
        @prefix solid: <http://www.w3.org/ns/solid/terms#>.
        @prefix sioc: <http://rdfs.org/sioc/ns#>.
        _:p a solid:InsertDeletePatch; solid:deletes { <#a1> sioc:content "anonymous append" }.`;
      res = await request('/patchtest/public/room/2026/10/22/chat.ttl', {
        method: 'PATCH', headers: { 'Content-Type': 'text/n3' }, body: remove
      });
      assertStatus(res, 401, 'deleting needs Write');
      const text = JSON.stringify(await (await request('/patchtest/public/room/2026/10/22/chat.ttl')).json());
      assert.ok(text.includes('#a1') && text.includes('#a2'), 'both appends kept');
    });
  });

  describe('Concurrent patches', () => {
    it('applies simultaneous appends to one resource without losing any', async () => {
      const patch = (i) => `
        @prefix solid: <http://www.w3.org/ns/solid/terms#>.
        @prefix sioc: <http://rdfs.org/sioc/ns#>.
        _:p a solid:InsertDeletePatch; solid:inserts { <#c${i}> sioc:content "message ${i}" }.`;
      const results = await Promise.all(Array.from({ length: 12 }, (_, i) => request('/patchtest/public/concurrent.ttl', {
        method: 'PATCH', headers: { 'Content-Type': 'text/n3' }, body: patch(i), auth: 'patchtest'
      })));
      for (const res of results) assert.ok([201, 204].includes(res.status), `status ${res.status}`);
      const text = await (await request('/patchtest/public/concurrent.ttl')).text();
      const doc = JSON.parse(text); // a half-overwritten file would not parse
      const ids = (doc['@graph'] || [doc]).map(n => n['@id']);
      for (let i = 0; i < 12; i++) assert.ok(ids.some(id => id.endsWith(`#c${i}`)), `message ${i} kept`);
    });
  });

  describe('Empty formulas', () => {
    it('treats an empty solid:deletes block as a no-op instead of failing', async () => {
      const patch = `
        @prefix solid: <http://www.w3.org/ns/solid/terms#>.
        _:p a solid:InsertDeletePatch; solid:deletes { } ; solid:inserts { <#e1> <http://example.org/p> "x" }.`;
      const res = await request('/patchtest/public/empty-formula.ttl', {
        method: 'PATCH', headers: { 'Content-Type': 'text/n3' }, body: patch, auth: 'patchtest'
      });
      assertStatus(res, 201);
      const empty = `
        @prefix solid: <http://www.w3.org/ns/solid/terms#>.
        _:p a solid:InsertDeletePatch; solid:deletes {
        }.`;
      const again = await request('/patchtest/public/empty-formula.ttl', {
        method: 'PATCH', headers: { 'Content-Type': 'text/n3' }, body: empty, auth: 'patchtest'
      });
      assertStatus(again, 204);
    });
  });

  describe('Cross-process lock file', () => {
    const lockFile = path.join('./data', 'patchtest', 'public', '.locked.ttl.lock');
    const patch = (i) => `
      @prefix solid: <http://www.w3.org/ns/solid/terms#>.
      _:p a solid:InsertDeletePatch; solid:inserts { <#l${i}> <http://example.org/p> "x" }.`;
    const send = (i) => request('/patchtest/public/locked.ttl', {
      method: 'PATCH', headers: { 'Content-Type': 'text/n3' }, body: patch(i), auth: 'patchtest'
    });

    it('waits for a lock held by another writer and proceeds once it is released', async () => {
      await fs.ensureFile(lockFile);
      const pending = send(1).then(res => ({ res }));
      const early = await Promise.race([pending, new Promise(r => setTimeout(() => r('still waiting'), 400))]);
      assert.strictEqual(early, 'still waiting', 'the patch does not run while the lock is held');
      await fs.remove(lockFile);
      const { res } = await pending;
      assertStatus(res, 201);
      await new Promise(r => setTimeout(r, 100)); // the handler releases just after replying
      assert.ok(!(await fs.pathExists(lockFile)), 'the lock is released afterwards');
    });

    it('breaks a stale lock left by a crashed process', async () => {
      await fs.ensureFile(lockFile);
      const old = new Date(Date.now() - 60000);
      await fs.utimes(lockFile, old, old);
      const res = await send(2);
      assertStatus(res, 204);
      await new Promise(r => setTimeout(r, 100));
      assert.ok(!(await fs.pathExists(lockFile)), 'the stale lock is gone');
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
