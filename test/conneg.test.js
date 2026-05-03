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

    it('should advertise N3 support in Accept-Put when conneg enabled', async () => {
      const res = await request('/connegtest/public/alice.json');
      const acceptPut = res.headers.get('Accept-Put');
      assert.ok(acceptPut && acceptPut.includes('text/n3'),
        'Accept-Put should include text/n3 (canAcceptInput accepts it under conneg)');
    });

    it('should advertise N3 support in Accept-Post for containers when conneg enabled', async () => {
      const res = await request('/connegtest/public/');
      const acceptPost = res.headers.get('Accept-Post');
      assert.ok(acceptPost && acceptPost.includes('text/n3'),
        'Accept-Post should include text/n3 (canAcceptInput accepts it under conneg)');
    });

    it('should advertise application/json in Accept-Put', async () => {
      const res = await request('/connegtest/public/alice.json');
      const acceptPut = res.headers.get('Accept-Put');
      assert.ok(acceptPut && acceptPut.includes('application/json'),
        'Accept-Put should include application/json (canAcceptInput treats it as a JSON-LD alias)');
    });

    it('should advertise application/json in Accept-Post for containers', async () => {
      const res = await request('/connegtest/public/');
      const acceptPost = res.headers.get('Accept-Post');
      assert.ok(acceptPost && acceptPost.includes('application/json'),
        'Accept-Post should include application/json (canAcceptInput treats it as a JSON-LD alias)');
    });
  });

  // Regression coverage for #294 — Solid convention dotfiles (.acl, .meta)
  // were excluded from conneg because getContentType() returned
  // application/octet-stream for them. Turtle-native clients (umai etc.)
  // fetching <container>/.meta got JSON-LD back and errored on parse.
  describe('Solid convention dotfiles (#294)', () => {
    const metaData = {
      '@context': { 'ldp': 'http://www.w3.org/ns/ldp#' },
      '@id': '',
      '@type': 'ldp:BasicContainer'
    };

    before(async () => {
      // Write a JSON-LD .meta file (the format JSS writes internally).
      await request('/connegtest/public/.meta', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/ld+json' },
        body: JSON.stringify(metaData),
        auth: 'connegtest'
      });
    });

    it('serves .meta as JSON-LD by default', async () => {
      const res = await request('/connegtest/public/.meta', { auth: 'connegtest' });
      assertStatus(res, 200);
      assertHeaderContains(res, 'Content-Type', 'application/ld+json');
    });

    it('serves .meta as Turtle when Accept: text/turtle (the umai case)', async () => {
      const res = await request('/connegtest/public/.meta', {
        headers: { 'Accept': 'text/turtle' },
        auth: 'connegtest'
      });
      assertStatus(res, 200);
      assertHeaderContains(res, 'Content-Type', 'text/turtle');
      const turtle = await res.text();
      // First byte after the `@prefix` block must parse as Turtle,
      // not '{' (the bug signature umai hit).
      assert.ok(!turtle.trimStart().startsWith('{'),
        `response looks like JSON, not Turtle: ${turtle.slice(0, 60)}`);
    });

    it('accepts Turtle PUT to .meta and round-trips to JSON-LD', async () => {
      const turtle = `
        @prefix ldp: <http://www.w3.org/ns/ldp#>.
        <> a ldp:BasicContainer.
      `;
      const putRes = await request('/connegtest/public/.meta', {
        method: 'PUT',
        headers: { 'Content-Type': 'text/turtle' },
        body: turtle,
        auth: 'connegtest'
      });
      assert.ok(putRes.status < 300, `PUT turtle should succeed, got ${putRes.status}`);

      // Default GET now serves the converted-and-stored JSON-LD.
      const getRes = await request('/connegtest/public/.meta', {
        headers: { 'Accept': 'application/ld+json' },
        auth: 'connegtest'
      });
      assertStatus(getRes, 200);
      assertHeaderContains(getRes, 'Content-Type', 'application/ld+json');
      const body = await getRes.json();
      assert.ok(body['@context'] || body['@graph'] || body['@type'] || body['@id'],
        'round-tripped JSON-LD should have at least one @-keyword');
    });
  });

  // ACL resources require a JSON-LD payload (application/ld+json or
  // application/json) on PUT regardless of conneg setting: round-trip
  // serialization between JSON-LD and Turtle has known limitations
  // that can cause data loss. See #295.
  describe('ACL content-type guard (#295)', () => {
    const aclJsonLd = {
      '@context': { acl: 'http://www.w3.org/ns/auth/acl#' },
      '@graph': [
        {
          '@id': '#owner',
          '@type': 'acl:Authorization',
          'acl:agent': { '@id': '#me' },
          'acl:accessTo': { '@id': './' },
          'acl:mode': [{ '@id': 'acl:Read' }, { '@id': 'acl:Write' }, { '@id': 'acl:Control' }]
        }
      ]
    };

    it('rejects text/turtle PUT to .acl with 415', async () => {
      const turtle = `
        @prefix acl: <http://www.w3.org/ns/auth/acl#>.
        <#owner> a acl:Authorization;
          acl:mode acl:Read.
      `;
      const res = await request('/connegtest/public/turtle-reject.acl', {
        method: 'PUT',
        headers: { 'Content-Type': 'text/turtle' },
        body: turtle,
        auth: 'connegtest'
      });
      assertStatus(res, 415);
      assertHeaderContains(res, 'Accept', 'application/ld+json');
      assertHeaderContains(res, 'Accept', 'application/json');
      assertHeaderContains(res, 'Accept-Put', 'application/ld+json');
      assertHeaderContains(res, 'Accept-Put', 'application/json');
    });

    it('rejects text/n3 PUT to .acl with 415', async () => {
      const res = await request('/connegtest/public/n3-reject.acl', {
        method: 'PUT',
        headers: { 'Content-Type': 'text/n3' },
        body: '@prefix acl: <http://www.w3.org/ns/auth/acl#>. <#x> a acl:Authorization.',
        auth: 'connegtest'
      });
      assertStatus(res, 415);
      assertHeaderContains(res, 'Accept', 'application/ld+json');
      assertHeaderContains(res, 'Accept', 'application/json');
      assertHeaderContains(res, 'Accept-Put', 'application/ld+json');
      assertHeaderContains(res, 'Accept-Put', 'application/json');
    });

    it('rejects text/plain PUT to .acl with 415 (URL-extension protection)', async () => {
      const res = await request('/connegtest/public/plain-reject.acl', {
        method: 'PUT',
        headers: { 'Content-Type': 'text/plain' },
        body: 'arbitrary text',
        auth: 'connegtest'
      });
      assertStatus(res, 415);
      assertHeaderContains(res, 'Accept', 'application/ld+json');
      assertHeaderContains(res, 'Accept', 'application/json');
      assertHeaderContains(res, 'Accept-Put', 'application/ld+json');
      assertHeaderContains(res, 'Accept-Put', 'application/json');
    });

    it('rejects PUT to .acl with no Content-Type with 415', async () => {
      // Use Uint8Array body so fetch() doesn't auto-set Content-Type
      // (which it does for string bodies: text/plain;charset=UTF-8).
      const res = await request('/connegtest/public/no-ct-reject.acl', {
        method: 'PUT',
        body: new Uint8Array([1, 2, 3, 4]),
        auth: 'connegtest'
      });
      assertStatus(res, 415);
      assertHeaderContains(res, 'Accept', 'application/ld+json');
      assertHeaderContains(res, 'Accept', 'application/json');
      assertHeaderContains(res, 'Accept-Put', 'application/ld+json');
      assertHeaderContains(res, 'Accept-Put', 'application/json');
    });

    it('accepts application/ld+json PUT to .acl', async () => {
      const res = await request('/connegtest/public/jsonld-accept.acl', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/ld+json' },
        body: JSON.stringify(aclJsonLd),
        auth: 'connegtest'
      });
      assert.ok(res.status < 300, `JSON-LD PUT to .acl should succeed, got ${res.status}`);
    });

    it('accepts application/json PUT to .acl', async () => {
      const res = await request('/connegtest/public/json-accept.acl', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(aclJsonLd),
        auth: 'connegtest'
      });
      assert.ok(res.status < 300, `application/json PUT to .acl should succeed, got ${res.status}`);
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

    it('should advertise application/json in Accept-Put when conneg disabled', async () => {
      const res = await request('/noconneg/public/');
      const acceptPut = res.headers.get('Accept-Put');
      assert.ok(acceptPut && acceptPut.includes('application/json'),
        'Accept-Put should include application/json (canAcceptInput treats it as a JSON-LD alias)');
    });

    it('should advertise application/json in Accept-Post when conneg disabled', async () => {
      const res = await request('/noconneg/public/');
      const acceptPost = res.headers.get('Accept-Post');
      assert.ok(acceptPost && acceptPost.includes('application/json'),
        'Accept-Post should include application/json (canAcceptInput treats it as a JSON-LD alias)');
    });

    it('should not advertise text/n3 in Accept-Put when conneg disabled', async () => {
      const res = await request('/noconneg/public/');
      const acceptPut = res.headers.get('Accept-Put');
      assert.ok(!acceptPut || !acceptPut.includes('text/n3'),
        'Accept-Put should NOT include text/n3 when conneg disabled');
    });
  });

  // The .acl content-type guard applies regardless of conneg setting (#295).
  // The default deployment configuration is conneg disabled, so ensure the
  // guard fires there too.
  describe('ACL content-type guard (#295) — conneg disabled', () => {
    const aclJsonLd = {
      '@context': { acl: 'http://www.w3.org/ns/auth/acl#' },
      '@graph': [
        {
          '@id': '#owner',
          '@type': 'acl:Authorization',
          'acl:agent': { '@id': '#me' },
          'acl:accessTo': { '@id': './' },
          'acl:mode': [{ '@id': 'acl:Read' }, { '@id': 'acl:Write' }, { '@id': 'acl:Control' }]
        }
      ]
    };

    it('rejects text/turtle PUT to .acl with 415', async () => {
      const turtle = `@prefix acl: <http://www.w3.org/ns/auth/acl#>. <#x> a acl:Authorization.`;
      const res = await request('/noconneg/public/turtle-reject.acl', {
        method: 'PUT',
        headers: { 'Content-Type': 'text/turtle' },
        body: turtle,
        auth: 'noconneg'
      });
      assertStatus(res, 415);
      assertHeaderContains(res, 'Accept', 'application/ld+json');
      assertHeaderContains(res, 'Accept', 'application/json');
      assertHeaderContains(res, 'Accept-Put', 'application/ld+json');
      assertHeaderContains(res, 'Accept-Put', 'application/json');
    });

    it('rejects text/plain PUT to .acl with 415', async () => {
      const res = await request('/noconneg/public/plain-reject.acl', {
        method: 'PUT',
        headers: { 'Content-Type': 'text/plain' },
        body: 'arbitrary text',
        auth: 'noconneg'
      });
      assertStatus(res, 415);
      assertHeaderContains(res, 'Accept', 'application/ld+json');
      assertHeaderContains(res, 'Accept', 'application/json');
      assertHeaderContains(res, 'Accept-Put', 'application/ld+json');
      assertHeaderContains(res, 'Accept-Put', 'application/json');
    });

    it('rejects PUT to .acl with no Content-Type with 415', async () => {
      // Use Uint8Array body so fetch() doesn't auto-set Content-Type
      // (which it does for string bodies: text/plain;charset=UTF-8).
      const res = await request('/noconneg/public/no-ct-reject.acl', {
        method: 'PUT',
        body: new Uint8Array([1, 2, 3, 4]),
        auth: 'noconneg'
      });
      assertStatus(res, 415);
      assertHeaderContains(res, 'Accept', 'application/ld+json');
      assertHeaderContains(res, 'Accept', 'application/json');
      assertHeaderContains(res, 'Accept-Put', 'application/ld+json');
      assertHeaderContains(res, 'Accept-Put', 'application/json');
    });

    it('accepts application/ld+json PUT to .acl', async () => {
      const res = await request('/noconneg/public/jsonld-accept.acl', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/ld+json' },
        body: JSON.stringify(aclJsonLd),
        auth: 'noconneg'
      });
      assert.ok(res.status < 300, `JSON-LD PUT to .acl should succeed, got ${res.status}`);
    });

    it('accepts application/json PUT to .acl', async () => {
      const res = await request('/noconneg/public/json-accept.acl', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(aclJsonLd),
        auth: 'noconneg'
      });
      assert.ok(res.status < 300, `application/json PUT to .acl should succeed, got ${res.status}`);
    });
  });
});

// Regression coverage for #325 — q-weighted Accept and HEAD/GET parity.
// Previously the conneg dispatcher used naive substring matching on the
// Accept header, so any Accept that mentioned text/turtle (even at q=0.1
// alongside q=1.0 application/ld+json) returned Turtle. Separately, HEAD
// on a container without an index.html hard-coded application/ld+json,
// so HEAD and GET disagreed on content-type for the same URL.
describe('Content Negotiation — q-weights and HEAD/GET parity (#325)', () => {
  before(async () => {
    await startTestServer({ conneg: true });
    await createTestPod('qwtest');
  });
  after(async () => { await stopTestServer(); });

  function ct(res) {
    return (res.headers.get('content-type') || '').split(';')[0].trim();
  }

  describe('container — q-weight respected', () => {
    it('Accept: jsonld q=1.0, turtle q=0.1 → JSON-LD', async () => {
      const res = await request('/qwtest/', {
        headers: { Accept: 'application/ld+json;q=1.0, text/turtle;q=0.1' }
      });
      assertStatus(res, 200);
      assert.strictEqual(ct(res), 'application/ld+json');
      const body = await res.text();
      assert.ok(body.trimStart().startsWith('{'),
        `body should be JSON, got: ${body.slice(0, 80)}`);
    });

    it('Accept: jsonld, turtle;q=0.5 → JSON-LD wins (downstream repro)', async () => {
      const res = await request('/qwtest/', {
        headers: { Accept: 'application/ld+json, text/turtle;q=0.5' }
      });
      assert.strictEqual(ct(res), 'application/ld+json');
      const body = await res.text();
      assert.ok(body.trimStart().startsWith('{'),
        `body should be JSON, got: ${body.slice(0, 80)}`);
    });

    it('Accept: turtle (explicit) → Turtle', async () => {
      const res = await request('/qwtest/', { headers: { Accept: 'text/turtle' } });
      assert.strictEqual(ct(res), 'text/turtle');
      const body = await res.text();
      assert.ok(body.trimStart().startsWith('@prefix'),
        `body should be Turtle, got: ${body.slice(0, 80)}`);
    });

    it('no Accept → JSON-LD (native default)', async () => {
      const res = await request('/qwtest/');
      assert.strictEqual(ct(res), 'application/ld+json');
    });
  });

  describe('container — HEAD content-type matches GET', () => {
    const cases = [
      ['no Accept',         {}],
      ['jsonld preferred',  { Accept: 'application/ld+json;q=1.0, text/turtle;q=0.1' }],
      ['turtle preferred',  { Accept: 'text/turtle' }],
      ['mixed (q=0.5)',     { Accept: 'application/ld+json, text/turtle;q=0.5' }]
    ];
    for (const [label, headers] of cases) {
      it(`HEAD === GET content-type — ${label}`, async () => {
        const get = await request('/qwtest/', { headers });
        const head = await request('/qwtest/', { method: 'HEAD', headers });
        assert.strictEqual(get.status, 200);
        assert.strictEqual(head.status, 200);
        assert.strictEqual(ct(head), ct(get),
          `HEAD ct (${ct(head)}) must equal GET ct (${ct(get)}) for ${label}`);
      });
    }
  });

  describe('container — auth path matches anonymous', () => {
    it('GET with auth returns same content-type as without auth (turtle case)', async () => {
      const headers = { Accept: 'text/turtle' };
      const anon = await request('/qwtest/', { headers });
      const authed = await request('/qwtest/', { headers, auth: 'qwtest' });
      assert.strictEqual(ct(anon), 'text/turtle');
      assert.strictEqual(ct(authed), ct(anon),
        'authenticated GET must report the same content-type as anonymous');
    });

    it('GET with auth returns same content-type as without auth (jsonld case)', async () => {
      const headers = { Accept: 'application/ld+json;q=1.0, text/turtle;q=0.1' };
      const anon = await request('/qwtest/', { headers });
      const authed = await request('/qwtest/', { headers, auth: 'qwtest' });
      assert.strictEqual(ct(anon), 'application/ld+json');
      assert.strictEqual(ct(authed), ct(anon));
    });
  });
});
