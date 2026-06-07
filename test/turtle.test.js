/**
 * Direct unit tests for the JSON-LD → Turtle converter.
 *
 * The focus is on regression coverage for properties that would otherwise
 * be easy to regress silently:
 *   - cycle-safety in expandUri (DoS guard — a malicious context must not
 *     cause unbounded recursion / stack overflow)
 *   - duplicate @id across top-level docs must NOT suppress emission
 *     (the visited-set refactor previously dropped data)
 *   - cyclical nested node references must not hang the BFS
 */

import { describe, it } from 'node:test';
import assert from 'node:assert';
import { fromJsonLd, toJsonLd } from '../src/rdf/conneg.js';

describe('turtle converter — unit (#320 follow-ups)', () => {
  it('expandUri does not recurse forever on a cyclic context (a → b → a)', async () => {
    const doc = {
      '@context': {
        // Pathological: each term points at another term via CURIE, forming a loop.
        'a': { '@id': 'b:x' },
        'b': { '@id': 'a:y' }
      },
      '@id': 'https://example.test/s',
      'a': 'hello'
    };
    // The converter should finish — not stack-overflow — regardless of what
    // the output happens to look like. We only assert it completes with a
    // string result.
    const { content } = await fromJsonLd(doc, 'text/turtle', 'https://example.test/', true);
    assert.ok(typeof content === 'string');
  });

  it('expandUri does not recurse forever on a self-loop (a → a)', async () => {
    const doc = {
      '@context': {
        'selfy': 'selfy'
      },
      '@id': 'https://example.test/s',
      'selfy': 'hello'
    };
    const { content } = await fromJsonLd(doc, 'text/turtle', 'https://example.test/', true);
    assert.ok(typeof content === 'string');
  });

  it('duplicate top-level @id is not silently dropped', async () => {
    // Two docs describing the same subject — both claims must survive.
    // (Previously the visited-set in the BFS skipped the second pass.)
    const docs = [
      {
        '@context': { 'foaf': 'http://xmlns.com/foaf/0.1/' },
        '@id': 'https://example.test/alice',
        'foaf:name': 'Alice'
      },
      {
        '@context': { 'foaf': 'http://xmlns.com/foaf/0.1/' },
        '@id': 'https://example.test/alice',
        'foaf:age': 30
      }
    ];
    const { content } = await fromJsonLd(docs, 'text/turtle', 'https://example.test/', true);
    assert.ok(content.includes('Alice'), `Turtle should contain the name claim, got:\n${content}`);
    assert.ok(/30|"30"/.test(content), `Turtle should contain the age claim, got:\n${content}`);
  });

  it('prefix-looking context key defined as an object is not string-concatenated', async () => {
    // A user-supplied context can legally define a prefix-looking key as a
    // term-definition object (not a namespace string). The converter must
    // not treat it as a namespace — string-concatenating the object would
    // produce invalid IRIs like "[object Object]foo".
    const doc = {
      '@context': {
        // `bogus` is defined as a term object, not a namespace string.
        'bogus': { '@id': 'https://example.test/ns#bogus' }
      },
      '@id': 'https://example.test/s',
      // This looks like a CURIE `bogus:foo` but `bogus` is not a valid
      // namespace — the converter should leave it alone.
      'bogus:foo': 'hello'
    };
    const { content } = await fromJsonLd(doc, 'text/turtle', 'https://example.test/', true);
    assert.ok(typeof content === 'string');
    assert.ok(!content.includes('[object Object]'),
      `Turtle output must not contain object-stringification, got:\n${content}`);
  });

  it('nested object with `id`/`type` aliases survives the conversion (#415)', async () => {
    // Solid profiles use the JSON-LD 1.1 `id`/`type` aliases for
    // nested resources (no `@`). The converter must accept both
    // forms — without this, a CID v1 verificationMethod object
    // gets silently dropped:
    //   - the `cid:verificationMethod` predicate isn't emitted
    //   - the nested `#nostr-key-1` resource (Multikey, controller,
    //     publicKeyMultibase) isn't emitted either
    // Net: third-party Turtle consumers see `cid:authentication
    // <#nostr-key-1>` with no description of `#nostr-key-1`.
    const doc = {
      '@context': {
        cid: 'https://www.w3.org/ns/cid/v1#',
        verificationMethod: { '@id': 'cid:verificationMethod', '@container': '@set' },
        authentication: { '@id': 'cid:authentication', '@type': '@id', '@container': '@set' },
        controller: { '@id': 'cid:controller', '@type': '@id' },
        publicKeyMultibase: { '@id': 'cid:publicKeyMultibase' },
      },
      '@id': 'https://example.test/profile/card.jsonld#me',
      verificationMethod: [{
        // Aliases — `id`/`type`, not `@id`/`@type`.
        id: 'https://example.test/profile/card.jsonld#k',
        type: 'Multikey',
        controller: 'https://example.test/profile/card.jsonld#me',
        publicKeyMultibase: 'fe70102de7ec',
      }],
      authentication: ['https://example.test/profile/card.jsonld#k'],
    };
    const { content } = await fromJsonLd(doc, 'text/turtle', 'https://example.test/', true);

    // The cid:verificationMethod predicate must connect #me to the VM.
    assert.match(content, /cid:verificationMethod|<https:\/\/www\.w3\.org\/ns\/cid\/v1#verificationMethod>/,
      `cid:verificationMethod predicate missing from Turtle:\n${content}`);
    // The VM resource must be described — its type, controller, key.
    assert.ok(content.includes('https://example.test/profile/card.jsonld#k'),
      `VM #k must appear in Turtle:\n${content}`);
    assert.match(content, /Multikey|<https:\/\/www\.w3\.org\/ns\/cid\/v1#Multikey>/,
      `Multikey type missing from Turtle:\n${content}`);
    assert.ok(content.includes('fe70102de7ec'),
      `publicKeyMultibase value missing from Turtle:\n${content}`);
    assert.match(content, /cid:controller|<https:\/\/www\.w3\.org\/ns\/cid\/v1#controller>/,
      `cid:controller predicate missing on the VM:\n${content}`);
  });

  it('malformed `id`/`type` values are silently dropped, not crashed on (#415 review)', async () => {
    // Profiles in the wild can have malformed user-authored content
    // — e.g. `id: 42` or `type: null`. The converter must NOT throw
    // (downstream `resolveUri.startsWith` and `expandUri.includes`
    // assume strings); it should treat the malformed value as absent
    // and skip the affected resource cleanly.
    const doc = {
      '@context': { 'cid': 'https://www.w3.org/ns/cid/v1#' },
      '@id': 'https://example.test/s',
      // Nested object with a non-string `id` — must not crash.
      'cid:bad1': { id: 42, 'cid:foo': 'x' },
      // Nested object with a null `type` — must not crash.
      'cid:bad2': { id: 'https://example.test/n2', type: null, 'cid:foo': 'x' },
      // Array `type` with mixed string/non-string entries — string
      // entries should still emit.
      'cid:mixed': { id: 'https://example.test/n3', type: ['Multikey', 42, null], 'cid:foo': 'x' },
    };
    const { content } = await fromJsonLd(doc, 'text/turtle', 'https://example.test/', true);
    assert.ok(typeof content === 'string', 'must produce a string output, not throw');
    // The valid string type entry should survive in the mixed-type case.
    assert.ok(content.includes('https://example.test/n3'),
      `node n3 should appear:\n${content}`);
  });

  it('emits a space before `;` and `.` terminators (#419)', async () => {
    // The de-facto convention in W3C spec examples and Apache Jena
    // RIOT is to separate the statement-terminator from the previous
    // token by a space. n3.js packs them; JSS post-processes the
    // output to add the space.
    //
    // Use TWO predicates on the same subject so n3.js emits a `;`
    // continuation (multiple triples on one subject). If a future
    // N3 upgrade ever switched to "one triple per statement" style
    // and dropped `;` entirely, this test would otherwise pass
    // vacuously. The presence-of-terminator assertions below pin
    // that behavior.
    const doc = {
      '@context': { 'foaf': 'http://xmlns.com/foaf/0.1/' },
      '@id': 'https://example.test/alice',
      'foaf:name': 'Alice',
      'foaf:age': 30,
    };
    const { content } = await fromJsonLd(doc, 'text/turtle', 'https://example.test/', true);
    // Pin "at least one ` ;` and one ` .` exists" with a literal
    // SPACE — not just any whitespace. The intended output style
    // (matching W3C Turtle 1.1 spec examples) is a single space
    // separator: `value ;` / `value .`. Allowing `\n;` or `\t;`
    // would let the test pass on visually-different output.
    assert.match(content, / ;/, `output must contain at least one " ;" terminator (space-prefixed), got:\n${content}`);
    assert.match(content, / \.(?:\s|$)/, `output must contain at least one " ." terminator (space-prefixed), got:\n${content}`);
    // Every `;` must be preceded by a literal space. Same for `.`
    // at end-of-statement. Reject anything else (newline, tab,
    // packed-against-token).
    const offendingSemi = /[^ ];/.test(content);
    const offendingDot = /[^ ]\.\s*$/m.test(content) || /[^ ]\.\n/.test(content);
    assert.ok(!offendingSemi, `every ; must be preceded by a single space, got:\n${content}`);
    assert.ok(!offendingDot, `every . at line/doc end must be preceded by a single space, got:\n${content}`);
  });

  it('does NOT add a space inside literals containing `;` or `.` (#419 safety)', async () => {
    // Critical correctness test: the post-pass must NOT corrupt
    // literal values. A literal "foo;bar" with the post-pass naïvely
    // applied would become "foo ;bar" — silent data corruption.
    //
    // Assert by VALUE, not by lexical form. A quote-agnostic parser
    // round-trip survives any future N3 writer style change
    // (single vs double quotes, long-string `"""..."""`, etc.).
    const doc = {
      '@context': { 'ex': 'https://example.test/ns#' },
      '@id': 'https://example.test/s',
      'ex:semicolonInside': 'foo;bar',
      'ex:dotInside': 'has.dot',
      'ex:both': 'a;b.c',
    };
    const { content } = await fromJsonLd(doc, 'text/turtle', 'https://example.test/', true);
    // Round-trip: parse the emitted Turtle, walk the quads, assert
    // the literal values came back exactly as authored.
    const { Parser } = await import('n3');
    const parser = new Parser({ baseIRI: 'https://example.test/' });
    const quads = parser.parse(content);
    const objectsByPredicate = new Map();
    for (const q of quads) {
      if (q.object.termType !== 'Literal') continue;
      objectsByPredicate.set(q.predicate.value, q.object.value);
    }
    assert.strictEqual(objectsByPredicate.get('https://example.test/ns#semicolonInside'), 'foo;bar',
      `literal value for ex:semicolonInside must be "foo;bar"`);
    assert.strictEqual(objectsByPredicate.get('https://example.test/ns#dotInside'), 'has.dot',
      `literal value for ex:dotInside must be "has.dot"`);
    assert.strictEqual(objectsByPredicate.get('https://example.test/ns#both'), 'a;b.c',
      `literal value for ex:both must be "a;b.c"`);
  });

  it('does NOT add a space inside an IRI containing `;` (#419 safety)', async () => {
    // An IRI's content is bracketed by `<...>` — the post-pass
    // shouldn't touch what's inside. Assert by value via parser
    // round-trip so we don't depend on N3 writer formatting.
    const doc = {
      '@context': { 'ex': 'https://example.test/ns#' },
      '@id': 'https://example.test/s',
      'ex:rel': { '@id': 'https://example.test/path;with;semis' },
    };
    const { content } = await fromJsonLd(doc, 'text/turtle', 'https://example.test/', true);
    const { Parser } = await import('n3');
    const parser = new Parser({ baseIRI: 'https://example.test/' });
    const quads = parser.parse(content);
    const rels = quads
      .filter(q => q.predicate.value === 'https://example.test/ns#rel')
      .map(q => q.object.value);
    assert.deepStrictEqual(rels, ['https://example.test/path;with;semis'],
      `IRI value must round-trip with internal ; intact`);
  });

  it('cyclical nested node reference does not hang', async () => {
    // Two nested nodes reference each other. BFS must not loop.
    const a = { '@id': 'https://example.test/a', 'ex:knows': null };
    const b = { '@id': 'https://example.test/b', 'ex:knows': a };
    a['ex:knows'] = b;

    const doc = {
      '@context': { 'ex': 'https://example.test/ns#' },
      '@id': 'https://example.test/root',
      'ex:knows': a
    };
    const { content } = await fromJsonLd(doc, 'text/turtle', 'https://example.test/', true);
    assert.ok(typeof content === 'string');
    assert.ok(content.includes('https://example.test/a'), 'node a should appear');
    assert.ok(content.includes('https://example.test/b'), 'node b should appear');
  });

  describe('blank-node subject roundtrip (#536)', () => {
    const baseUri = 'https://example.test/u/c/bn.ttl';
    const input = '@prefix ex: <http://example.org/> .\n<#s> ex:p [ ex:a 1 ; ex:b 2 ] .\n';

    it('Turtle → JSON-LD emits blank-node SUBJECTS with the "_:" prefix', async () => {
      // Previously the subject side dropped "_:", producing a bare label
      // ("n3-0") that resolved as a relative IRI on read; the object side
      // (termToJsonLd) already kept "_:". Result: severed graph.
      const doc = await toJsonLd(input, 'text/turtle', baseUri, true);
      const nodes = Array.isArray(doc) ? doc : [doc];
      // The blank-node subject is the one carrying ex:a / ex:b.
      const bn = nodes.find(n => 'ex:a' in n);
      assert.ok(bn, 'expected a node carrying ex:a');
      assert.ok(typeof bn['@id'] === 'string' && bn['@id'].startsWith('_:'),
        `blank-node subject @id should start with "_:", got ${JSON.stringify(bn['@id'])}`);
    });

    it('Turtle → JSON-LD → Turtle preserves the blank-node connection', async () => {
      // End-to-end: parse output Turtle and verify the blank node carrying
      // ex:a / ex:b is the SAME node that <#s> ex:p points at — i.e. the
      // graph is not severed.
      const doc = await toJsonLd(input, 'text/turtle', baseUri, true);
      const { content: outTurtle } = await fromJsonLd(doc, 'text/turtle', baseUri, true);

      const { Parser } = await import('n3');
      const quads = new Parser({ baseIRI: baseUri }).parse(outTurtle);

      const pQuad = quads.find(q => q.predicate.value === 'http://example.org/p');
      assert.ok(pQuad, 'ex:p triple should be present');
      assert.strictEqual(pQuad.object.termType, 'BlankNode',
        'ex:p object must remain a blank node, not be promoted to a named IRI');

      const aQuad = quads.find(q => q.predicate.value === 'http://example.org/a');
      assert.ok(aQuad, 'ex:a triple should be present');
      assert.strictEqual(aQuad.subject.termType, 'BlankNode',
        'ex:a subject must remain a blank node');
      assert.strictEqual(aQuad.subject.value, pQuad.object.value,
        'the blank node carrying ex:a must be the same one ex:p references');
    });
  });
});
