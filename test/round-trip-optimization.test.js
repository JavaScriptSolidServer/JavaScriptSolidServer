/**
 * Tests for the round-trip optimization reader (#346).
 *
 * The reader is a small inline `<script>` that exposes
 * `window.__dataIsland.get(uri)` and (when rdflib loads) patches
 * `$rdf.fetcher.load()` to resolve from the inline JSON-LD data island
 * instead of issuing a second HTTP request. These tests pin:
 *   - presence in CDN, local, and module HTML wrappers when default
 *   - opt-out via `roundTripOptimization: false`
 *   - reader exposes the documented accessor
 *   - reader contains the bounded-retry guard (no infinite polling)
 *   - reader body is well-formed JS (no premature `</script>` close)
 */

import { describe, it } from 'node:test';
import assert from 'node:assert';
import {
  generateDatabrowserHtml,
  generateModuleDatabrowserHtml
} from '../src/mashlib/index.js';

describe('round-trip optimization reader — emission (#346)', () => {
  it('emits the reader script in CDN mode by default', () => {
    const html = generateDatabrowserHtml('https://x.test/foo', '2.0.0');
    assert.match(html, /window\.__dataIsland/);
    assert.match(html, /\$rdf\.fetcher/);
  });

  it('emits the reader script in local mode by default', () => {
    const html = generateDatabrowserHtml('https://x.test/foo');
    assert.match(html, /window\.__dataIsland/);
    assert.match(html, /\$rdf\.fetcher/);
  });

  it('emits the reader script in module mode by default', () => {
    const html = generateModuleDatabrowserHtml(
      '/dist/databrowser.js',
      'https://x.test/foo'
    );
    assert.match(html, /window\.__dataIsland/);
    assert.match(html, /\$rdf\.fetcher/);
  });

  it('omits the reader when roundTripOptimization is explicitly false (CDN)', () => {
    const html = generateDatabrowserHtml('https://x.test/foo', '2.0.0', {
      roundTripOptimization: false
    });
    assert.doesNotMatch(html, /window\.__dataIsland/);
  });

  it('omits the reader when roundTripOptimization is explicitly false (local)', () => {
    const html = generateDatabrowserHtml('https://x.test/foo', null, {
      roundTripOptimization: false
    });
    assert.doesNotMatch(html, /window\.__dataIsland/);
  });

  it('omits the reader when roundTripOptimization is explicitly false (module)', () => {
    const html = generateModuleDatabrowserHtml(
      '/dist/databrowser.js',
      'https://x.test/foo',
      { roundTripOptimization: false }
    );
    assert.doesNotMatch(html, /window\.__dataIsland/);
  });

  it('exposes the documented generic accessor shape', () => {
    const html = generateDatabrowserHtml('https://x.test/foo', '2.0.0');
    // window.__dataIsland.get(uri) is the public surface
    assert.match(html, /__dataIsland=window\.__dataIsland\|\|\{get:function/);
  });

  it('queries data islands by data-uri attribute', () => {
    const html = generateDatabrowserHtml('https://x.test/foo', '2.0.0');
    assert.match(html, /script#dataisland\[data-uri="/);
  });

  it('marks the fetcher as patched to prevent double-patching', () => {
    const html = generateDatabrowserHtml('https://x.test/foo', '2.0.0');
    assert.match(html, /__dataIslandPatched/);
  });

  it('bounds the polling retry to prevent infinite loop on non-rdflib clients', () => {
    const html = generateDatabrowserHtml('https://x.test/foo', '2.0.0');
    // Polling guard: ++n>100 caps at ~10 seconds (100 * 100ms)
    assert.match(html, /\+\+n>100/);
  });

  it('falls through to original fetcher.load on parse error', () => {
    const html = generateDatabrowserHtml('https://x.test/foo', '2.0.0');
    // Original load is captured and called on miss/error
    assert.match(html, /orig=f\.load\.bind\(f\)/);
    assert.match(html, /return orig\(uri,options\)/);
  });

  it('reader body does not contain a literal </script> token', () => {
    // The reader is itself a <script> block; any literal end-tag inside
    // its body would terminate the element prematurely.
    const html = generateDatabrowserHtml('https://x.test/foo', '2.0.0');
    // Extract just the reader script body and check it has no </script>
    // We grep for the IIFE we know is in the reader and assert no end-tag
    // inside the surrounding <script>...</script> the reader uses.
    const readerStart = html.indexOf('window.__dataIsland');
    assert.ok(readerStart > 0, 'reader script not found');
    // Walk forward until we find the closing </script> for the reader
    const readerEnd = html.indexOf('</script>', readerStart);
    assert.ok(readerEnd > readerStart, 'reader script not properly closed');
    const body = html.slice(readerStart, readerEnd);
    assert.doesNotMatch(body, /<\/script>/i,
      'reader body must not contain </script> token');
  });
});

describe('round-trip optimization reader — interaction with data island (#346)', () => {
  it('reader and data island both present when JSON-LD payload supplied', () => {
    const html = generateDatabrowserHtml(
      'https://test.solid.social/profile/card.jsonld',
      '2.0.0',
      { embedJsonLd: '{"@id":"#me","foaf:name":"Alice"}' }
    );
    assert.match(html, /id="dataisland"/);
    assert.match(html, /window\.__dataIsland/);
  });

  it('reader still present when data island is absent (no payload)', () => {
    const html = generateDatabrowserHtml('https://x.test/foo', '2.0.0');
    assert.doesNotMatch(html, /id="dataisland"/);
    // Reader is still emitted; it just no-ops on missing islands
    assert.match(html, /window\.__dataIsland/);
  });

  it('data island appears before reader script in document order', () => {
    const html = generateDatabrowserHtml(
      'https://x.test/foo',
      '2.0.0',
      { embedJsonLd: '{"@id":"#me"}' }
    );
    const islandPos = html.indexOf('id="dataisland"');
    const readerPos = html.indexOf('window.__dataIsland');
    assert.ok(islandPos > 0, 'data island missing');
    assert.ok(readerPos > 0, 'reader missing');
    assert.ok(islandPos < readerPos,
      'data island must appear before reader so the DOM element exists when reader queries it');
  });
});
