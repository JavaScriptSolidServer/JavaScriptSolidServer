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
import { fromJsonLd } from '../src/rdf/conneg.js';

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
});
