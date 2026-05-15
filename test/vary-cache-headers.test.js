/**
 * Regression tests for #315 — inconsistent Vary / Cache-Control across
 * conneg variants caused stale-render races on browser reload.
 *
 * What we guarantee now:
 *  - Every variant of the same URL returns an *identical* Vary header.
 *  - RDF data variants carry Cache-Control that forces revalidation via
 *    ETag, so a cached body cannot silently serve across auth changes or
 *    be picked up on a top-level navigation by mistake.
 *  - The mashlib HTML wrapper keeps `no-store` (it's a bootstrap template).
 */

import { describe, it, before, after } from 'node:test';
import assert from 'node:assert';
import {
  startTestServer,
  stopTestServer,
  request,
  createTestPod
} from './helpers.js';

describe('Vary / Cache-Control consistency (#315)', () => {
  before(async () => {
    await startTestServer({ conneg: true, mashlibCdn: true });
    await createTestPod('varytest');
    // Create a JSON-LD resource to exercise all variants.
    await request('/varytest/public/card.jsonld', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/ld+json' },
      body: JSON.stringify({
        '@context': { foaf: 'http://xmlns.com/foaf/0.1/' },
        '@id': '#me',
        'foaf:name': 'Vary Test'
      }),
      auth: 'varytest'
    });
  });

  after(async () => { await stopTestServer(); });

  it('Vary header is identical across all conneg variants of the same URL', async () => {
    const accepts = [
      'text/html,*/*;q=0.8',              // mashlib HTML wrapper
      'text/turtle',                        // Turtle conversion
      'application/ld+json'                 // native JSON-LD
    ];
    const varyValues = [];
    for (const accept of accepts) {
      const res = await request('/varytest/public/card.jsonld', { headers: { Accept: accept } });
      varyValues.push({ accept, vary: res.headers.get('vary') });
    }
    // All three variants must carry the same Vary — inconsistent Vary is
    // what confused browser caches into serving the wrong variant.
    const uniqueVaryValues = new Set(varyValues.map((v) => v.vary));
    assert.strictEqual(uniqueVaryValues.size, 1,
      `expected identical Vary across variants, got: ${JSON.stringify(varyValues)}`);
    const vary = [...uniqueVaryValues][0];
    assert.ok(vary, `expected Vary header across variants, got: ${JSON.stringify(varyValues)}`);
    assert.match(vary, /Accept/, 'Vary must include Accept (conneg active)');
    assert.match(vary, /Authorization/, 'Vary must include Authorization (WAC)');
    assert.match(vary, /Origin/, 'Vary must include Origin (CORS)');
  });

  it('mashlib HTML wrapper uses Cache-Control: no-store', async () => {
    const res = await request('/varytest/public/card.jsonld', {
      headers: { Accept: 'text/html,*/*;q=0.8' }
    });
    assert.match(res.headers.get('content-type') || '', /text\/html/);
    assert.strictEqual(res.headers.get('cache-control'), 'no-store');
  });

  it('RDF data variants force revalidation (no stale bodies across auth changes)', async () => {
    // Full expected policy — pinning every directive so a regression that
    // drops `private` or `must-revalidate` (both needed to prevent auth-state
    // leakage and force freshness) fails the test.
    const expected = 'private, no-cache, must-revalidate';
    for (const accept of ['text/turtle', 'application/ld+json']) {
      const res = await request('/varytest/public/card.jsonld', { headers: { Accept: accept } });
      assert.strictEqual(res.headers.get('cache-control'), expected,
        `Cache-Control mismatch on Accept: ${accept}`);
      // ETag is preserved so revalidation is cheap (304).
      assert.ok(res.headers.get('etag'), `expected ETag on ${accept} variant`);
    }
  });

  it('mashlib HTML ETag differs from raw RDF ETag (#456)', async () => {
    const htmlRes = await request('/varytest/public/card.jsonld', {
      headers: { Accept: 'text/html,*/*;q=0.8' }
    });
    const jsonRes = await request('/varytest/public/card.jsonld', {
      headers: { Accept: 'application/ld+json' }
    });
    const htmlEtag = htmlRes.headers.get('etag');
    const jsonEtag = jsonRes.headers.get('etag');
    assert.ok(htmlEtag, 'HTML variant should have ETag');
    assert.ok(jsonEtag, 'JSON-LD variant should have ETag');
    assert.notStrictEqual(htmlEtag, jsonEtag,
      'mashlib HTML and raw JSON-LD must have different ETags');
    assert.ok(htmlEtag.endsWith('-html"'),
      `HTML ETag should end with -html", got: ${htmlEtag}`);
    assert.ok(!jsonEtag.includes('-html'),
      `JSON-LD ETag should not contain -html, got: ${jsonEtag}`);
  });

  it('If-None-Match with HTML ETag does not 304 the JSON-LD variant (#456)', async () => {
    const htmlRes = await request('/varytest/public/card.jsonld', {
      headers: { Accept: 'text/html,*/*;q=0.8' }
    });
    const htmlEtag = htmlRes.headers.get('etag');
    // Use the HTML ETag to request JSON-LD — should NOT get 304
    const jsonRes = await request('/varytest/public/card.jsonld', {
      headers: { Accept: 'application/ld+json', 'If-None-Match': htmlEtag }
    });
    assert.strictEqual(jsonRes.status, 200,
      'JSON-LD request with HTML ETag should get 200, not 304');
  });

  it('If-None-Match with JSON-LD ETag does not 304 the HTML variant (#456)', async () => {
    const jsonRes = await request('/varytest/public/card.jsonld', {
      headers: { Accept: 'application/ld+json' }
    });
    const jsonEtag = jsonRes.headers.get('etag');
    // Use the JSON-LD ETag to request HTML — should NOT get 304
    const htmlRes = await request('/varytest/public/card.jsonld', {
      headers: { Accept: 'text/html,*/*;q=0.8', 'If-None-Match': jsonEtag }
    });
    assert.strictEqual(htmlRes.status, 200,
      'HTML request with JSON-LD ETag should get 200, not 304');
  });

  it('HEAD returns same ETag as GET for each variant (#456)', async () => {
    for (const accept of ['text/html,*/*;q=0.8', 'application/ld+json']) {
      const getRes = await request('/varytest/public/card.jsonld', {
        headers: { Accept: accept }
      });
      const headRes = await request('/varytest/public/card.jsonld', {
        method: 'HEAD',
        headers: { Accept: accept }
      });
      assert.strictEqual(headRes.headers.get('etag'), getRes.headers.get('etag'),
        `HEAD and GET ETags must match for Accept: ${accept}`);
    }
  });

  it('container index.html data-island variants also carry revalidating Cache-Control', async () => {
    // Publish an index.html with a JSON-LD data island; conneg should extract
    // and serve it as Turtle/JSON-LD. Those variants were missing
    // Cache-Control pre-#315.
    const html = [
      '<!doctype html><html><head>',
      '<script type="application/ld+json">',
      JSON.stringify({
        '@context': { foaf: 'http://xmlns.com/foaf/0.1/' },
        '@id': '#this',
        'foaf:name': 'Island'
      }),
      '</script></head><body>hi</body></html>'
    ].join('');
    await request('/varytest/public/index.html', {
      method: 'PUT',
      headers: { 'Content-Type': 'text/html' },
      body: html,
      auth: 'varytest'
    });

    const expected = 'private, no-cache, must-revalidate';
    for (const accept of ['text/turtle', 'application/ld+json']) {
      const res = await request('/varytest/public/', { headers: { Accept: accept } });
      assert.strictEqual(res.headers.get('cache-control'), expected,
        `Cache-Control mismatch on island variant (Accept: ${accept})`);
    }
  });
});
