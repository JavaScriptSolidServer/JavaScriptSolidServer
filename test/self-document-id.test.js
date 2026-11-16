/**
 * A document that describes itself (#656).
 *
 * In Turtle the document is `<>`; in JSON-LD it is `"@id": ""` (the empty
 * reference, RFC 3986 §5.2.2). It used to be stored as `"@id": "."`, which
 * is the containing folder, so the triples moved to the container on read.
 */

import { describe, it, before, after } from 'node:test';
import assert from 'node:assert';
import { startTestServer, stopTestServer, request, assertStatus } from './helpers.js';
import { turtleToJsonLd, jsonLdToTurtle } from '../src/rdf/turtle.js';

const DOC = 'http://pod.example/notes/q1.ttl';
const SELF = '<> a <http://schema.org/Question> ; <http://purl.org/dc/terms/title> "About this document" .';

const nodesOf = (jsonLd) => (Array.isArray(jsonLd) ? jsonLd : jsonLd['@graph'] || [jsonLd]);

describe('a document describing itself — conversion (unit, #656)', () => {
  it('stores <> as the empty reference, not "."', async () => {
    const jsonLd = await turtleToJsonLd(SELF, DOC);
    const ids = nodesOf(jsonLd).map(n => n['@id']);
    assert.ok(ids.includes(''), `expected "@id": "" in ${JSON.stringify(ids)}`);
    assert.ok(!ids.includes('.'), 'must not be stored as "."');
  });

  it('round-trips to the document, not its folder', async () => {
    const turtle = await jsonLdToTurtle(await turtleToJsonLd(SELF, DOC), DOC);
    assert.match(turtle, /<http:\/\/pod\.example\/notes\/q1\.ttl>/);
    assert.doesNotMatch(turtle, /<http:\/\/pod\.example\/notes\/>/);
  });

  it('still keeps fragments relative', async () => {
    const jsonLd = await turtleToJsonLd('<#this> a <http://schema.org/Thing> .', DOC);
    assert.ok(nodesOf(jsonLd).some(n => n['@id'] === '#this'));
  });

  it('a self-describing container still resolves to the container', async () => {
    const base = 'http://pod.example/notes/';
    const turtle = await jsonLdToTurtle(await turtleToJsonLd('<> a <http://www.w3.org/ns/ldp#Container> .', base), base);
    assert.match(turtle, /<http:\/\/pod\.example\/notes\/>/);
  });
});

describe('a document describing itself — over HTTP (#656)', () => {
  let baseUrl;
  before(async () => { ({ baseUrl } = await startTestServer({ public: true, conneg: true })); });
  after(async () => { await stopTestServer(); });

  it('PUT Turtle with <>, GET Turtle: the subject is the document', async () => {
    const put = await request('/notes/q1.ttl', { method: 'PUT', headers: { 'Content-Type': 'text/turtle' }, body: SELF });
    assertStatus(put, 201);
    const res = await request('/notes/q1.ttl', { headers: { Accept: 'text/turtle' } });
    assertStatus(res, 200);
    const body = await res.text();
    assert.ok(body.includes(`<${baseUrl}/notes/q1.ttl>`), body);
    assert.ok(!body.includes(`<${baseUrl}/notes/>`), body);
  });
});
