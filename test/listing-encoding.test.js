/**
 * Container listings percent-encode the names they list (#662).
 *
 * Names are stored decoded. Listed as they are, a space gives an IRI that
 * no RDF parser accepts (so the parent folder stops loading in SolidOS),
 * `#` and `?` cut the name short, and `%` is decoded twice.
 */

import { describe, it, before, after } from 'node:test';
import assert from 'node:assert';
import { generateContainerJsonLd, encodePathSegment } from '../src/ldp/container.js';
import { startTestServer, stopTestServer, createTestPod, request, getBaseUrl } from './helpers.js';

describe('encodePathSegment (#662)', () => {
  it('leaves ordinary names alone', () => {
    for (const name of ['index.ttl', 'card', 'a-b_c.d~e', "it's(1)!*.txt", 'a:b@c.ttl', 'x$&+,;=y']) {
      assert.strictEqual(encodePathSegment(name), name);
    }
  });

  it('encodes what would break or change the URL', () => {
    assert.strictEqual(encodePathSegment('family chat'), 'family%20chat');
    assert.strictEqual(encodePathSegment('a#b.txt'), 'a%23b.txt');
    assert.strictEqual(encodePathSegment('q?x.txt'), 'q%3Fx.txt');
    assert.strictEqual(encodePathSegment('pct%25.txt'), 'pct%2525.txt');
    assert.strictEqual(encodePathSegment('café.txt'), 'caf%C3%A9.txt');
    assert.strictEqual(encodePathSegment('a<b>"c'), 'a%3Cb%3E%22c');
  });

  it('round-trips through decodeURIComponent', () => {
    for (const name of ['family chat', 'a#b', 'q?x', '100%', 'pct%25', 'café', 'a:b@c', 'x y+z', '日本語.ttl']) {
      assert.strictEqual(decodeURIComponent(encodePathSegment(name)), name);
    }
  });
});

describe('generateContainerJsonLd encodes names (#662)', () => {
  it('lists encoded URLs for files and folders', () => {
    const out = generateContainerJsonLd('https://example.com/pod/', [
      { name: 'family chat', isDirectory: true },
      { name: 'a#b.txt', isDirectory: false },
      { name: 'plain.ttl', isDirectory: false },
    ]);
    assert.deepStrictEqual(out.contains.map(c => c['@id']), [
      'https://example.com/pod/family%20chat/',
      'https://example.com/pod/a%23b.txt',
      'https://example.com/pod/plain.ttl',
    ]);
  });
});

describe('container listing over HTTP (#662)', () => {
  let token;
  const names = ['family chat', 'a#b.txt', 'q?x.txt', 'pct%25.txt', 'café.txt', 'plain.txt'];

  before(async () => {
    await startTestServer({ conneg: true });
    const pod = await createTestPod('listenc');
    token = pod.token;
    for (const name of names) {
      const res = await request(`/listenc/public/enc/${encodeURIComponent(name)}`, {
        method: 'PUT', headers: { 'Content-Type': 'text/plain' }, body: name, auth: 'listenc'
      });
      assert.ok(res.status === 201 || res.status === 204, `PUT ${name}: ${res.status}`);
    }
  });
  after(async () => {
    await stopTestServer();
  });

  it('every listed URL fetches the resource it names', async () => {
    const res = await request('/listenc/public/enc/', { headers: { Accept: 'application/ld+json' }, auth: 'listenc' });
    assert.strictEqual(res.status, 200);
    const doc = await res.json();
    const node = Array.isArray(doc) ? doc[0] : (doc['@graph'] ? doc['@graph'].find(n => n.contains) : doc);
    const ids = [].concat(node.contains).map(c => (typeof c === 'string' ? c : c['@id']));
    assert.strictEqual(ids.length, names.length);
    const got = [];
    for (const id of ids) {
      assert.ok(!/[ <>"]/.test(id), `unencoded character in ${id}`);
      const path = id.slice(getBaseUrl().length);
      const one = await request(path, { auth: 'listenc' });
      assert.strictEqual(one.status, 200, `GET ${id}`);
      got.push(await one.text());
    }
    assert.deepStrictEqual(got.sort(), names.slice().sort());
  });

  it('the Turtle listing has no unencoded space', async () => {
    const res = await request('/listenc/public/enc/', { headers: { Accept: 'text/turtle' }, auth: 'listenc' });
    assert.strictEqual(res.status, 200);
    const turtle = await res.text();
    assert.ok(turtle.includes('/enc/family%20chat>'), turtle);
    assert.ok(!/<[^<>]* [^<>]*>/.test(turtle.replace(/"[^"]*"/g, '""')), 'an IRI with a space');
  });
});
