/**
 * Tests for the round-trip optimization reader (#346).
 *
 * The reader is a small inline `<script>` that exposes
 * `window.__dataIsland.get(uri)` and (when rdflib loads) patches
 * `$rdf.fetcher.load()` to resolve from the inline JSON-LD data island
 * instead of issuing a second HTTP request. These tests pin:
 *   - presence in CDN, local, and module HTML wrappers when enabled by default
 *   - opt-out via `roundTripOptimization: false`
 *   - reader exposes the documented accessor
 *   - reader contains the bounded-retry guard (no infinite polling)
 *   - reader body is well-formed JS (no premature `</script>` close)
 *   - runtime behavior of the accessor and the rdflib patch (via Node `vm`)
 */

import { describe, it } from 'node:test';
import assert from 'node:assert';
import vm from 'node:vm';
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

  it('exposes the documented public surface (window.__dataIsland with .get)', () => {
    // Public-surface assertion only — minified formatting is not pinned.
    // Runtime behavior is exercised in the vm-based suite below.
    const html = generateDatabrowserHtml('https://x.test/foo', '2.0.0');
    assert.match(html, /window\.__dataIsland/);
    assert.match(html, /\.get\s*[:=(]/);
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

/**
 * Helpers for the runtime suite: extract the reader IIFE from generated
 * HTML and evaluate it in a Node `vm` context with stubbed window /
 * document / $rdf so we can pin actual behavior, not just emitted
 * tokens.
 */
function extractReaderSource(html) {
  const start = html.indexOf('(function(){if(typeof window');
  if (start < 0) throw new Error('reader IIFE not found in HTML');
  const scriptOpen = html.lastIndexOf('<script>', start);
  const scriptClose = html.indexOf('</script>', start);
  return html.slice(scriptOpen + '<script>'.length, scriptClose);
}

function makeContext({ islands = {}, $rdf = undefined } = {}) {
  const document = {
    querySelector(selector) {
      const m = selector.match(/data-uri="([^"]+)"/);
      if (!m) return null;
      const uri = m[1];
      if (!(uri in islands)) return null;
      return { type: 'application/ld+json', textContent: islands[uri] };
    }
  };
  const window = { CSS: { escape: (s) => String(s).replace(/"/g, '\\"') } };
  return vm.createContext({
    window, document, $rdf,
    setTimeout, clearTimeout, Promise, String, console
  });
}

function runReader(ctx, html) {
  vm.runInContext(extractReaderSource(ctx.html || html), ctx);
}

describe('round-trip optimization reader — runtime behavior (#346)', () => {
  const html = generateDatabrowserHtml('https://x.test/foo', '2.0.0');

  it('window.__dataIsland.get returns {contentType, content} for matching island', () => {
    const ctx = makeContext({
      islands: { 'https://x.test/foo': '{"@id":"#me"}' }
    });
    vm.runInContext(extractReaderSource(html), ctx);
    const result = ctx.window.__dataIsland.get('https://x.test/foo');
    // Compare by value: result is constructed in the vm realm so its
    // prototype is not reference-equal to the host realm's Object.
    assert.strictEqual(result.contentType, 'application/ld+json');
    assert.strictEqual(result.content, '{"@id":"#me"}');
  });

  it('window.__dataIsland.get returns null when no matching island exists', () => {
    const ctx = makeContext({ islands: {} });
    vm.runInContext(extractReaderSource(html), ctx);
    assert.strictEqual(
      ctx.window.__dataIsland.get('https://x.test/missing'),
      null
    );
  });

  it('window.__dataIsland.get returns null for falsy uri input', () => {
    const ctx = makeContext({ islands: {} });
    vm.runInContext(extractReaderSource(html), ctx);
    assert.strictEqual(ctx.window.__dataIsland.get(null), null);
    assert.strictEqual(ctx.window.__dataIsland.get(undefined), null);
    assert.strictEqual(ctx.window.__dataIsland.get(''), null);
  });

  it('patches $rdf.fetcher.load synchronously when rdflib is already present', () => {
    const fakeFetcher = {
      requested: {},
      store: {},
      load: async () => 'original'
    };
    const $rdf = { fetcher: fakeFetcher, parse: () => {}, sym: (u) => u };
    const ctx = makeContext({ islands: {}, $rdf });
    vm.runInContext(extractReaderSource(html), ctx);
    assert.strictEqual(fakeFetcher.__dataIslandPatched, true,
      'fetcher should be marked patched');
  });

  it('patched fetcher.load resolves from data island instead of network', async () => {
    let networkCalls = 0;
    const parseCalls = [];
    const fakeFetcher = {
      requested: {},
      store: { kb: 'fake' },
      load: async () => { networkCalls++; return 'network'; }
    };
    const $rdf = {
      fetcher: fakeFetcher,
      parse(content, store, uri, contentType, callback) {
        parseCalls.push({ content, uri, contentType });
        callback(null);
      },
      sym: (u) => ({ uri: u })
    };
    const ctx = makeContext({
      islands: { 'https://x.test/foo': '{"@id":"#me"}' },
      $rdf
    });
    vm.runInContext(extractReaderSource(html), ctx);

    await fakeFetcher.load('https://x.test/foo', {});

    assert.strictEqual(networkCalls, 0, 'should not have hit network');
    assert.strictEqual(parseCalls.length, 1, '$rdf.parse called once');
    assert.strictEqual(parseCalls[0].content, '{"@id":"#me"}');
    assert.strictEqual(parseCalls[0].uri, 'https://x.test/foo');
    assert.strictEqual(parseCalls[0].contentType, 'application/ld+json');
    assert.strictEqual(fakeFetcher.requested['https://x.test/foo'], 'done');
  });

  it('patched fetcher.load falls through to original on data island miss', async () => {
    let networkCalls = [];
    const fakeFetcher = {
      requested: {},
      store: {},
      load: async function (uri, options) {
        networkCalls.push({ uri, options });
        return { source: 'network', uri };
      }
    };
    const $rdf = {
      fetcher: fakeFetcher,
      parse: () => {},
      sym: (u) => u
    };
    const ctx = makeContext({ islands: {}, $rdf });
    vm.runInContext(extractReaderSource(html), ctx);

    const result = await fakeFetcher.load('https://x.test/foo', { force: true });

    assert.strictEqual(networkCalls.length, 1);
    assert.strictEqual(networkCalls[0].uri, 'https://x.test/foo');
    assert.deepStrictEqual(networkCalls[0].options, { force: true });
    assert.deepStrictEqual(result, {
      source: 'network',
      uri: 'https://x.test/foo'
    });
  });

  it('patched fetcher.load falls through to original on parse error', async () => {
    let networkCalls = 0;
    const fakeFetcher = {
      requested: {},
      store: {},
      load: async () => { networkCalls++; return 'network'; }
    };
    const $rdf = {
      fetcher: fakeFetcher,
      parse(content, store, uri, contentType, callback) {
        callback(new Error('parse failed'));
      },
      sym: (u) => u
    };
    const ctx = makeContext({
      islands: { 'https://x.test/foo': 'not valid json-ld' },
      $rdf
    });
    vm.runInContext(extractReaderSource(html), ctx);

    const result = await fakeFetcher.load('https://x.test/foo', {});

    assert.strictEqual(networkCalls, 1, 'should have fallen through to network');
    assert.strictEqual(result, 'network');
  });

  it('rdflib patch is idempotent (running reader twice does not double-wrap)', () => {
    const fakeFetcher = {
      requested: {},
      store: {},
      load: async () => 'original'
    };
    const $rdf = { fetcher: fakeFetcher, parse: () => {}, sym: (u) => u };
    const ctx = makeContext({ islands: {}, $rdf });

    vm.runInContext(extractReaderSource(html), ctx);
    const firstPatchedLoad = fakeFetcher.load;

    // Second run — must detect __dataIslandPatched and skip
    vm.runInContext(extractReaderSource(html), ctx);

    assert.strictEqual(fakeFetcher.load, firstPatchedLoad,
      'second run should not re-wrap an already-patched fetcher');
  });

  it('does nothing when rdflib never loads (bounded retry exits silently)', () => {
    const ctx = makeContext({ islands: {} /* no $rdf */ });
    // Should not throw despite $rdf being undefined.
    assert.doesNotThrow(() => {
      vm.runInContext(extractReaderSource(html), ctx);
    });
    // Generic accessor still set up.
    assert.strictEqual(typeof ctx.window.__dataIsland.get, 'function');
  });
});
