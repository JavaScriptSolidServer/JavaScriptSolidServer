/**
 * Phase-1 tests for the JSON-LD data island (#7).
 *
 * The mashlib HTML wrapper now carries the resource's JSON-LD bytes
 * inside a `<script type="application/ld+json" id="dataisland">`
 * block. Phase 1 doesn't change mashlib's runtime behaviour — the
 * island is purely additive — so these tests pin:
 *   - emission shape (script tag, id, MIME, data-uri)
 *   - escape: any `</script>` substring inside the body must not
 *     prematurely close the script tag
 *   - size cap: oversized payloads silently drop the island so we
 *     don't make every navigation re-download a multi-megabyte file
 *   - presence in the live HTTP response (resource and container)
 *   - safe URI attribute against quote / angle-bracket injection
 */

import { describe, it, before, after } from 'node:test';
import assert from 'node:assert';
import {
  startTestServer,
  stopTestServer,
  request,
  createTestPod,
  assertStatus,
  assertHeaderContains
} from './helpers.js';
import {
  generateDatabrowserHtml,
  generateModuleDatabrowserHtml,
  DATA_ISLAND_MAX_BYTES
} from '../src/mashlib/index.js';

describe('mashlib data island — emission (unit, #7)', () => {
  it('emits <script type="application/ld+json" id="dataisland" data-uri="..."> when payload supplied', () => {
    const html = generateDatabrowserHtml(
      'https://test.solid.social/profile/card.jsonld',
      '2.0.0',
      { embedJsonLd: '{"@id":"#me","foaf:name":"Alice"}' }
    );
    assert.match(html, /<script type="application\/ld\+json" id="dataisland" data-uri="https:\/\/test\.solid\.social\/profile\/card\.jsonld">/);
    assert.match(html, /"@id":"#me"/);
    assert.match(html, /<\/script>/);
  });

  it('omits the data island when no payload is supplied (back-compat)', () => {
    const html = generateDatabrowserHtml('https://x.test/foo', '2.0.0');
    assert.doesNotMatch(html, /id="dataisland"/);
  });

  it('omits the data island for oversized payloads (size cap)', () => {
    // Construct a JSON-LD body just over the cap.
    const filler = 'x'.repeat(DATA_ISLAND_MAX_BYTES + 1024);
    const oversized = `{"content":"${filler}"}`;
    const html = generateDatabrowserHtml(
      'https://x.test/big',
      '2.0.0',
      { embedJsonLd: oversized }
    );
    assert.doesNotMatch(html, /id="dataisland"/,
      'island must drop silently above DATA_ISLAND_MAX_BYTES');
  });

  // The escape strategy is "encode every `<` byte as the six-character
  // JSON escape `\\u003c`". Test the wide variety of strings that an
  // HTML parser would otherwise treat as a closing tag — `</script>`,
  // `</script >`, `</script\n>`, `</SCRIPT>`, `</scRIPT>` — plus
  // `<!--`, all of which require a literal `<` to start the dangerous
  // sequence. After escaping, no literal `<` exists in the body and
  // every transformed location appears as `\\u003c`.
  const escapeTrojans = [
    ['exact </script>',      '{"x":"a</script>b"}'],
    ['with space </script >', '{"x":"a</script >b"}'],
    ['with newline </script\\n>', '{"x":"a</script\n>b"}'],
    ['uppercase </SCRIPT>',  '{"x":"a</SCRIPT>b"}'],
    ['mixed </ScRiPt>',      '{"x":"a</ScRiPt>b"}'],
    ['<!-- comment',         '{"x":"<!-- hidden -->"}']
  ];
  for (const [label, body] of escapeTrojans) {
    it(`escape blocks ${label} from prematurely terminating the tag`, () => {
      const html = generateDatabrowserHtml(
        'https://x.test/r',
        '2.0.0',
        { embedJsonLd: body }
      );
      const start = html.indexOf('id="dataisland"');
      assert.ok(start > 0, 'data island should be present');
      // Slice from the island's `>` (end of opening tag) forward.
      const open = html.indexOf('>', start) + 1;
      const close = html.indexOf('</script>', open);
      const inner = html.slice(open, close);
      // After our escape, the body must contain NO literal `<`.
      assert.doesNotMatch(inner, /</,
        `script body must not contain a literal "<" — got: ${JSON.stringify(inner)}`);
      // The escaped form should be present (`<`).
      assert.match(inner, /\\u003c/,
        'escaped form `\\u003c` must appear');
    });
  }

  it('accepts a Buffer payload (handler may pass storage.read() result directly)', () => {
    // The src/handlers/resource.js path used to convert with .toString()
    // before passing in; tightening that contract risks regressions, so
    // the helper accepts a Buffer transparently.
    const buf = Buffer.from('{"@id":"#me","foaf:name":"BufferAlice"}', 'utf8');
    const html = generateDatabrowserHtml(
      'https://x.test/r',
      '2.0.0',
      { embedJsonLd: buf }
    );
    assert.match(html, /id="dataisland"/);
    assert.match(html, /"foaf:name":"BufferAlice"/);
  });

  it('the module-mode wrapper also emits the data island', () => {
    const html = generateModuleDatabrowserHtml(
      'https://example.test/mashlib.js',
      'https://test.solid.social/profile/card.jsonld',
      { embedJsonLd: '{"@id":"#me"}' }
    );
    assert.match(html, /<script type="application\/ld\+json" id="dataisland" data-uri="https:\/\/test\.solid\.social\/profile\/card\.jsonld">/);
    assert.match(html, /"@id":"#me"/);
  });

  it('escapes the data-uri attribute against quote / angle-bracket injection', () => {
    const html = generateDatabrowserHtml(
      'https://x.test/r"><img src=x onerror=alert(1)>',
      '2.0.0',
      { embedJsonLd: '{}' }
    );
    // The dangerous characters must be HTML-entity encoded inside the
    // attribute, so the attribute can't be broken open.
    assert.match(html, /data-uri="https:\/\/x\.test\/r&quot;&gt;&lt;img/);
    assert.doesNotMatch(html, /data-uri="https:\/\/x\.test\/r"><img/);
  });
});

// Integration coverage — the data island must actually appear in the
// HTTP response when a browser asks for the wrapper.
describe('mashlib data island — integration (#7)', () => {
  before(async () => {
    await startTestServer({ mashlibCdn: true });
    await createTestPod('islandtest');
    // Put a small JSON-LD resource we can fetch back as HTML.
    await request('/islandtest/public/note.jsonld', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/ld+json' },
      body: JSON.stringify({
        '@context': { foaf: 'http://xmlns.com/foaf/0.1/' },
        '@id': '#note',
        'foaf:name': 'island test'
      }),
      auth: 'islandtest'
    });
  });

  after(async () => { await stopTestServer(); });

  it('a browser GET to a JSON-LD resource carries the data island', async () => {
    const res = await request('/islandtest/public/note.jsonld', {
      headers: { Accept: 'text/html,application/xhtml+xml,*/*;q=0.8' }
    });
    assertStatus(res, 200);
    assertHeaderContains(res, 'Content-Type', 'text/html');
    const body = await res.text();
    assert.match(body, /id="dataisland"/);
    assert.match(body, /<script type="application\/ld\+json"/);
    assert.match(body, /"foaf:name":"island test"/);
  });

  it('a browser GET to a container carries the listing as a data island', async () => {
    const res = await request('/islandtest/public/', {
      headers: { Accept: 'text/html,application/xhtml+xml,*/*;q=0.8' }
    });
    assertStatus(res, 200);
    assertHeaderContains(res, 'Content-Type', 'text/html');
    const body = await res.text();
    assert.match(body, /id="dataisland"/);
    assert.match(body, /<script type="application\/ld\+json"/);
    // Contains an ldp:contains pointing at the resource we just PUT.
    assert.match(body, /note\.jsonld/);
  });

  it('non-HTML Accept (mashlib XHR) does NOT trigger the wrapper', async () => {
    const res = await request('/islandtest/public/note.jsonld', {
      headers: { Accept: 'application/ld+json' }
    });
    assertHeaderContains(res, 'Content-Type', 'application/ld+json');
    const body = await res.text();
    assert.doesNotMatch(body, /id="dataisland"/);
    assert.doesNotMatch(body, /<!doctype html>/i);
  });
});
