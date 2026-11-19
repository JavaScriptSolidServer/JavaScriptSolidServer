/**
 * A container with an index.html serves three representations at one URL:
 * the HTML page, and its JSON-LD data island as Turtle or JSON-LD. They must
 * carry different ETags. With a shared tag, a browser that cached the page
 * revalidates with it when rdflib/SolidOS asks for Turtle, gets a 304, and
 * hands the cached HTML to the data client, which then finds no triples
 * (a pod's profile shows no name or photo in SolidOS).
 */

import { describe, it, before, after } from 'node:test';
import assert from 'node:assert';
import {
  startTestServer,
  stopTestServer,
  request,
  createTestPod
} from './helpers.js';

const PAGE = `<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Profile</title>
<script type="application/ld+json">
{ "@context": { "foaf": "http://xmlns.com/foaf/0.1/" },
  "@id": "#me", "foaf:img": { "@id": "https://example.org/me.jpg" } }
</script></head><body></body></html>`;

// What rdflib sends for a data fetch (SolidOS 3.x).
const RDFLIB_ACCEPT = 'image/*;q=0.9, */*;q=0.1, application/rdf+xml;q=0.9, application/xhtml+xml;q=0.8, text/xml;q=0.5, application/xml;q=0.5, text/html;q=0.8, text/plain;q=0.5, text/n3, text/turtle, application/ld+json;q=0.9';
const URL = '/islandetag/public/site/';

describe('index.html container: distinct ETags per representation', () => {
  before(async () => {
    await startTestServer({ conneg: true });
    await createTestPod('islandetag');
    const res = await request(URL + 'index.html', {
      method: 'PUT',
      headers: { 'Content-Type': 'text/html' },
      body: PAGE,
      auth: 'islandetag'
    });
    assert.ok(res.status < 300, `PUT index.html failed: ${res.status}`);
  });

  after(async () => { await stopTestServer(); });

  it('the page, Turtle and JSON-LD each get their own ETag', async () => {
    const html = await request(URL, { headers: { Accept: 'text/html' } });
    const ttl = await request(URL, { headers: { Accept: 'text/turtle' } });
    const jsonld = await request(URL, { headers: { Accept: 'application/ld+json' } });
    assert.match(html.headers.get('content-type') || '', /text\/html/);
    assert.match(ttl.headers.get('content-type') || '', /text\/turtle/);
    assert.match(jsonld.headers.get('content-type') || '', /application\/ld\+json/);
    const tags = [html, ttl, jsonld].map(r => r.headers.get('etag'));
    assert.ok(tags.every(Boolean), `expected an ETag on every variant: ${tags}`);
    assert.strictEqual(new Set(tags).size, 3, `ETags must differ: ${tags}`);
  });

  it('revalidating with the page ETag does not 304 a Turtle request (the SolidOS case)', async () => {
    const html = await request(URL, { headers: { Accept: 'text/html' } });
    const pageTag = html.headers.get('etag');
    const res = await request(URL, { headers: { Accept: RDFLIB_ACCEPT, 'If-None-Match': pageTag } });
    assert.strictEqual(res.status, 200, 'must send the data, not a 304 for the cached page');
    assert.match(res.headers.get('content-type') || '', /text\/turtle/);
    assert.match(await res.text(), /example\.org\/me\.jpg/);
  });

  it('each variant still 304s against its own ETag', async () => {
    for (const accept of ['text/html', 'text/turtle', 'application/ld+json']) {
      const first = await request(URL, { headers: { Accept: accept } });
      const tag = first.headers.get('etag');
      const again = await request(URL, { headers: { Accept: accept, 'If-None-Match': tag } });
      assert.strictEqual(again.status, 304, `expected 304 for Accept: ${accept}`);
      assert.strictEqual(again.headers.get('etag'), tag);
    }
  });

  it('HEAD reports the same ETag as GET for each variant', async () => {
    for (const accept of ['text/html', 'text/turtle']) {
      const get = await request(URL, { headers: { Accept: accept } });
      const head = await request(URL, { method: 'HEAD', headers: { Accept: accept } });
      assert.strictEqual(head.headers.get('etag'), get.headers.get('etag'), `HEAD/GET ETag mismatch for ${accept}`);
    }
  });
});
