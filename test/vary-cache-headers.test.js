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
    const varys = [];
    for (const accept of accepts) {
      const res = await request('/varytest/public/card.jsonld', { headers: { Accept: accept } });
      varys.push({ accept, vary: res.headers.get('vary') });
    }
    // All three variants must carry the same Vary — inconsistent Vary is
    // what confused browser caches into serving the wrong variant.
    const unique = new Set(varys.map((v) => v.vary));
    assert.strictEqual(unique.size, 1,
      `expected identical Vary across variants, got: ${JSON.stringify(varys)}`);
    const vary = [...unique][0];
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
    for (const accept of ['text/turtle', 'application/ld+json']) {
      const res = await request('/varytest/public/card.jsonld', { headers: { Accept: accept } });
      const cc = res.headers.get('cache-control');
      assert.ok(cc, `expected Cache-Control on ${accept} variant`);
      assert.match(cc, /no-cache|no-store/, `Cache-Control "${cc}" must prevent stale reuse (Accept: ${accept})`);
      // ETag is preserved so revalidation is cheap (304).
      assert.ok(res.headers.get('etag'), `expected ETag on ${accept} variant`);
    }
  });
});
