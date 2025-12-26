/**
 * Content Negotiation Tests
 *
 * Tests Turtle <-> JSON-LD conversion with conneg enabled.
 * Note: Content negotiation is OFF by default (JSON-LD native server).
 */

import { describe, it, before, after } from 'node:test';
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

describe('Content Negotiation (conneg enabled)', () => {
  before(async () => {
    // Start server with conneg ENABLED
    await startTestServer({ conneg: true });
    await createTestPod('connegtest');
  });

  after(async () => {
    await stopTestServer();
  });

  describe('GET with Accept header', () => {
    it('should return JSON-LD when Accept: application/ld+json', async () => {
      // Create a JSON-LD resource
      const data = {
        '@context': { 'foaf': 'http://xmlns.com/foaf/0.1/' },
        '@id': '#me',
        'foaf:name': 'Alice'
      };

      await request('/connegtest/public/alice.json', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/ld+json' },
        body: JSON.stringify(data),
        auth: 'connegtest'
      });

      const res = await request('/connegtest/public/alice.json', {
        headers: { 'Accept': 'application/ld+json' }
      });

      assertStatus(res, 200);
      assertHeaderContains(res, 'Content-Type', 'application/ld+json');

      const body = await res.json();
      assert.strictEqual(body['foaf:name'], 'Alice');
    });

    it('should return Turtle when Accept: text/turtle', async () => {
      // Create a JSON-LD resource
      const data = {
        '@context': { 'foaf': 'http://xmlns.com/foaf/0.1/' },
        '@id': '#me',
        'foaf:name': 'Bob'
      };

      await request('/connegtest/public/bob.json', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/ld+json' },
        body: JSON.stringify(data),
        auth: 'connegtest'
      });

      const res = await request('/connegtest/public/bob.json', {
        headers: { 'Accept': 'text/turtle' }
      });

      assertStatus(res, 200);
      assertHeaderContains(res, 'Content-Type', 'text/turtle');

      const turtle = await res.text();
      // Should contain foaf prefix and name
      assert.ok(turtle.includes('foaf:') || turtle.includes('http://xmlns.com/foaf/0.1/'),
        'Turtle should contain foaf prefix or URI');
      assert.ok(turtle.includes('Bob'), 'Turtle should contain the name');
    });

    it('should default to JSON-LD for */* Accept', async () => {
      const res = await request('/connegtest/public/alice.json', {
        headers: { 'Accept': '*/*' }
      });

      assertStatus(res, 200);
      assertHeaderContains(res, 'Content-Type', 'application/ld+json');
    });

    it('should include Vary header with Accept', async () => {
      const res = await request('/connegtest/public/alice.json');
      const vary = res.headers.get('Vary');
      assert.ok(vary && vary.includes('Accept'), 'Should have Vary: Accept');
    });
  });

  describe('PUT with Content-Type', () => {
    it('should accept Turtle input and store as JSON-LD', async () => {
      const turtle = `
        @prefix foaf: <http://xmlns.com/foaf/0.1/>.
        <#me> foaf:name "Charlie".
      `;

      const res = await request('/connegtest/public/charlie.json', {
        method: 'PUT',
        headers: { 'Content-Type': 'text/turtle' },
        body: turtle,
        auth: 'connegtest'
      });

      assertStatus(res, 201);

      // Verify it's stored as JSON-LD
      const getRes = await request('/connegtest/public/charlie.json', {
        headers: { 'Accept': 'application/ld+json' }
      });

      assertStatus(getRes, 200);
      const data = await getRes.json();
      assert.ok(data['@context'], 'Should have @context');
    });

    it('should accept N3 input', async () => {
      const n3 = `
        @prefix schema: <http://schema.org/>.
        <#item> schema:name "Widget".
      `;

      const res = await request('/connegtest/public/widget.json', {
        method: 'PUT',
        headers: { 'Content-Type': 'text/n3' },
        body: n3,
        auth: 'connegtest'
      });

      assertStatus(res, 201);
    });

    it('should return 400 for invalid Turtle', async () => {
      const invalidTurtle = 'this is not valid turtle {{{';

      const res = await request('/connegtest/public/invalid.json', {
        method: 'PUT',
        headers: { 'Content-Type': 'text/turtle' },
        body: invalidTurtle,
        auth: 'connegtest'
      });

      assertStatus(res, 400);
    });
  });

  describe('POST with Content-Type', () => {
    it('should accept Turtle input in POST', async () => {
      const turtle = `
        @prefix dc: <http://purl.org/dc/terms/>.
        <#doc> dc:title "My Document".
      `;

      const res = await request('/connegtest/public/', {
        method: 'POST',
        headers: {
          'Content-Type': 'text/turtle',
          'Slug': 'turtle-doc.json'
        },
        body: turtle,
        auth: 'connegtest'
      });

      assertStatus(res, 201);
      const location = res.headers.get('Location');
      assert.ok(location, 'Should have Location header');
    });
  });

  describe('Accept-* Headers', () => {
    it('should advertise Turtle support in Accept-Put', async () => {
      const res = await request('/connegtest/public/alice.json');
      const acceptPut = res.headers.get('Accept-Put');
      assert.ok(acceptPut && acceptPut.includes('text/turtle'),
        'Accept-Put should include text/turtle');
    });

    it('should advertise Turtle support in Accept-Post for containers', async () => {
      const res = await request('/connegtest/public/');
      const acceptPost = res.headers.get('Accept-Post');
      assert.ok(acceptPost && acceptPost.includes('text/turtle'),
        'Accept-Post should include text/turtle');
    });
  });
});

describe('Content Negotiation (conneg disabled - default)', () => {
  before(async () => {
    // Start server with conneg DISABLED (default)
    await startTestServer({ conneg: false });
    await createTestPod('noconneg');
  });

  after(async () => {
    await stopTestServer();
  });

  describe('Default JSON-LD behavior', () => {
    it('should always return JSON-LD regardless of Accept header', async () => {
      // Create resource
      const data = {
        '@context': { 'foaf': 'http://xmlns.com/foaf/0.1/' },
        '@id': '#me',
        'foaf:name': 'DefaultUser'
      };

      await request('/noconneg/public/user.json', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/ld+json' },
        body: JSON.stringify(data),
        auth: 'noconneg'
      });

      // Request Turtle
      const res = await request('/noconneg/public/user.json', {
        headers: { 'Accept': 'text/turtle' }
      });

      assertStatus(res, 200);
      // Should still return JSON-LD when conneg disabled
      const body = await res.json();
      assert.strictEqual(body['foaf:name'], 'DefaultUser');
    });

    it('should accept JSON-LD input', async () => {
      const data = { '@id': '#test', 'http://example.org/p': 'value' };

      const res = await request('/noconneg/public/test.json', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/ld+json' },
        body: JSON.stringify(data),
        auth: 'noconneg'
      });

      assertStatus(res, 201);
    });

    it('should accept plain JSON input', async () => {
      const data = { foo: 'bar' };

      const res = await request('/noconneg/public/plain.json', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(data),
        auth: 'noconneg'
      });

      assertStatus(res, 201);
    });

    it('should accept non-RDF content types', async () => {
      const res = await request('/noconneg/public/readme.txt', {
        method: 'PUT',
        headers: { 'Content-Type': 'text/plain' },
        body: 'Hello World',
        auth: 'noconneg'
      });

      assertStatus(res, 201);

      const getRes = await request('/noconneg/public/readme.txt');
      assertStatus(getRes, 200);
      const text = await getRes.text();
      assert.strictEqual(text, 'Hello World');
    });

    it('should not advertise Turtle in Accept-Put when conneg disabled', async () => {
      const res = await request('/noconneg/public/');
      const acceptPut = res.headers.get('Accept-Put');
      // Should only advertise JSON-LD, not Turtle
      assert.ok(acceptPut && acceptPut.includes('application/ld+json'),
        'Accept-Put should include application/ld+json');
      assert.ok(!acceptPut || !acceptPut.includes('text/turtle'),
        'Accept-Put should NOT include text/turtle when conneg disabled');
    });
  });
});
