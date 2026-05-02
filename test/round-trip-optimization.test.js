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
  generateModuleDatabrowserHtml,
  roundTripOptimizationScript
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

  it('looks up the data island by id and compares data-uri', () => {
    // Avoiding selector construction sidesteps CSS.escape pitfalls and
    // selector-injection surface in older browsers.
    const html = generateDatabrowserHtml('https://x.test/foo', '2.0.0');
    assert.match(html, /document\.getElementById\(\s*['"]dataisland['"]\s*\)/);
    assert.match(html, /getAttribute\(\s*['"]data-uri['"]\s*\)/);
  });

  it('marks the fetcher as patched to prevent double-patching', () => {
    const html = generateDatabrowserHtml('https://x.test/foo', '2.0.0');
    assert.match(html, /__dataIslandPatched/);
  });

  it('bounds the polling retry to prevent infinite loop on non-rdflib clients', () => {
    const html = generateDatabrowserHtml('https://x.test/foo', '2.0.0');
    // Polling guard caps total retries (whitespace-tolerant).
    // Actual runtime behavior is exercised in the vm-based suite below.
    assert.match(html, /\+\+\s*n\s*>\s*\d+/);
  });

  it('captures original fetcher.load before patching', () => {
    const html = generateDatabrowserHtml('https://x.test/foo', '2.0.0');
    // Public-surface assertion (whitespace-tolerant).
    // Runtime fall-through is exercised in the vm-based suite below.
    assert.match(html, /orig\s*=\s*f\.load\.bind\(f\)/);
  });

  it('reader contains exactly one </script> close tag (no premature close)', () => {
    // Test the source string directly (not a slice of the emitted HTML)
    // so a premature `</script>` cannot be silently treated as the
    // terminator. A correct reader has exactly one `</script>`: its own
    // closing tag.
    const wrapped = roundTripOptimizationScript();
    const closes = (wrapped.match(/<\/script\s*>/gi) || []).length;
    assert.strictEqual(closes, 1,
      'reader must have exactly one </script> close tag, got ' + closes);
    // Sanity: the close is at the very end (modulo trailing whitespace).
    assert.match(wrapped, /<\/script>\s*$/);
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
  // The reader IIFE begins with `(function () {` followed by the
  // `if (typeof window` guard. Locate that signature, then walk back
  // to the enclosing <script> open and forward to the closing </script>.
  const sigMatch = html.match(/\(function \(\)\s*\{\s*if \(typeof window/);
  if (!sigMatch) throw new Error('reader IIFE not found in HTML');
  const start = sigMatch.index;
  const scriptOpen = html.lastIndexOf('<script>', start);
  const scriptClose = html.indexOf('</script>', start);
  return html.slice(scriptOpen + '<script>'.length, scriptClose);
}

function makeContext({ islands = {}, $rdf = undefined } = {}) {
  // Single data island per page (matches the real DOM contract). The
  // accessor uses getElementById('dataisland'), so we expose at most
  // one element regardless of how many entries the test passes in.
  const islandEntries = Object.entries(islands);
  const islandEl = islandEntries.length > 0
    ? {
        type: 'application/ld+json',
        textContent: islandEntries[0][1],
        getAttribute(name) {
          return name === 'data-uri' ? islandEntries[0][0] : null;
        }
      }
    : null;
  const document = {
    getElementById(id) {
      return id === 'dataisland' ? islandEl : null;
    }
  };
  const window = {};
  // Stub setTimeout so the reader's polling fallback (up to ~10s of
  // 100ms ticks when $rdf is absent) does not register real Node
  // timers that keep the test process alive past the assertions.
  // Tests that need to exercise polling can build a custom context.
  return vm.createContext({
    window, document, $rdf,
    setTimeout: () => 0,
    clearTimeout: () => {},
    Promise, String, console, Response,
    Object: globalThis.Object
  });
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

    const result = await fakeFetcher.load('https://x.test/foo', {});

    assert.strictEqual(networkCalls, 0, 'should not have hit network');
    assert.strictEqual(parseCalls.length, 1, '$rdf.parse called once');
    assert.strictEqual(parseCalls[0].content, '{"@id":"#me"}');
    assert.strictEqual(parseCalls[0].uri, 'https://x.test/foo');
    assert.strictEqual(parseCalls[0].contentType, 'application/ld+json');
    assert.strictEqual(fakeFetcher.requested['https://x.test/foo'], 'done');

    // Return value is a real Response (or Response-shaped fallback) so
    // consumers using `instanceof Response` or `.text()` / `.json()`
    // see the same kind of object as on the network path.
    assert.strictEqual(result.ok, true);
    assert.strictEqual(result.status, 200);
    assert.strictEqual(result.url, 'https://x.test/foo');
    assert.strictEqual(typeof result.headers.get, 'function');
    // Content-type header round-trips through the Response init.
    assert.strictEqual(result.headers.get('content-type'), 'application/ld+json');
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

  it('installs a setter on window.$rdf to catch synchronous mashlib init', () => {
    // The setter closes the race where mashlib's bundle initializes and
    // calls panes.runDataBrowser() (and hence fetcher.load) synchronously
    // inside an onload handler — faster than any setTimeout poll could fire.
    const ctx = makeContext({ islands: {} /* no $rdf yet */ });
    vm.runInContext(extractReaderSource(html), ctx);
    const desc = Object.getOwnPropertyDescriptor(ctx.window, '$rdf');
    assert.ok(desc, 'setter descriptor missing on window.$rdf');
    assert.strictEqual(typeof desc.get, 'function', 'getter should be installed');
    assert.strictEqual(typeof desc.set, 'function', 'setter should be installed');
  });

  it('setter on window.$rdf patches fetcher immediately on assignment', () => {
    const fakeFetcher = {
      requested: {},
      store: {},
      load: async () => 'original'
    };
    const fakeRdf = { fetcher: fakeFetcher, parse: () => {}, sym: (u) => u };
    const ctx = makeContext({ islands: {} /* $rdf not yet set */ });
    vm.runInContext(extractReaderSource(html), ctx);
    // Simulate mashlib publishing its rdflib instance.
    ctx.window.$rdf = fakeRdf;
    assert.strictEqual(fakeFetcher.__dataIslandPatched, true,
      'fetcher should be patched the moment $rdf is assigned');
  });

  it('returns a real Response when the constructor is available', async () => {
    const fakeFetcher = {
      requested: {},
      store: {},
      load: async () => 'orig'
    };
    const $rdf = {
      fetcher: fakeFetcher,
      parse: (content, store, uri, ct, cb) => cb(null),
      sym: (u) => u
    };
    const ctx = makeContext({
      islands: { 'https://x.test/foo': '{"@id":"#me"}' },
      $rdf
    });
    vm.runInContext(extractReaderSource(html), ctx);
    const result = await fakeFetcher.load('https://x.test/foo', {});
    assert.ok(result instanceof Response,
      'should resolve to a real Response when constructor is available');
    assert.strictEqual(await result.text(), '{"@id":"#me"}');
    assert.strictEqual(result.url, 'https://x.test/foo');
  });

  it('falls back to Response-shaped object when Response is unavailable', async () => {
    // Build a context without Response so the fallback path runs.
    const islandEl = {
      type: 'application/ld+json',
      textContent: '{"@id":"#x"}',
      getAttribute: (n) => n === 'data-uri' ? 'https://x.test/foo' : null
    };
    const document = {
      getElementById: (id) => id === 'dataisland' ? islandEl : null
    };
    const window = {};
    const fakeFetcher = {
      requested: {},
      store: {},
      load: async () => 'orig'
    };
    const $rdf = {
      fetcher: fakeFetcher,
      parse: (c, s, u, ct, cb) => cb(null),
      sym: (u) => u
    };
    const ctx = vm.createContext({
      window, document, $rdf,
      setTimeout: () => 0, clearTimeout: () => {},
      Promise, String, console,
      Object: globalThis.Object
      // Note: no Response in this context.
    });
    vm.runInContext(extractReaderSource(html), ctx);
    const result = await fakeFetcher.load('https://x.test/foo', {});
    assert.strictEqual(result.ok, true);
    assert.strictEqual(result.status, 200);
    assert.strictEqual(result.url, 'https://x.test/foo');
    assert.strictEqual(typeof result.headers.get, 'function');
  });

  it('fallback headers.get returns the data island content-type (case-insensitive)', async () => {
    // Build a context without Response so the fallback headers path runs.
    const islandEl = {
      type: 'application/ld+json',
      textContent: '{"@id":"#x"}',
      getAttribute: (n) => n === 'data-uri' ? 'https://x.test/foo' : null
    };
    const document = {
      getElementById: (id) => id === 'dataisland' ? islandEl : null
    };
    const window = {};
    const fakeFetcher = {
      requested: {},
      store: {},
      load: async () => 'orig'
    };
    const $rdf = {
      fetcher: fakeFetcher,
      parse: (c, s, u, ct, cb) => cb(null),
      sym: (u) => u
    };
    const ctx = vm.createContext({
      window, document, $rdf,
      setTimeout: () => 0, clearTimeout: () => {},
      Promise, String, console,
      Object: globalThis.Object
      // No Response — forces fallback path.
    });
    vm.runInContext(extractReaderSource(html), ctx);
    const result = await fakeFetcher.load('https://x.test/foo', {});
    assert.strictEqual(result.headers.get('content-type'), 'application/ld+json');
    assert.strictEqual(result.headers.get('Content-Type'), 'application/ld+json');
    assert.strictEqual(result.headers.get('CONTENT-TYPE'), 'application/ld+json');
    assert.strictEqual(result.headers.get('etag'), null);
    assert.strictEqual(result.headers.get(123), null,
      'non-string name should return null without throwing');
  });

  it('preserves existing window.__dataIsland but ensures .get is callable', () => {
    // Simulate a prior script setting a truthy __dataIsland without .get.
    const islandEl = {
      type: 'application/ld+json',
      textContent: '{"@id":"#me"}',
      getAttribute: (n) => n === 'data-uri' ? 'https://x.test/foo' : null
    };
    const document = {
      getElementById: (id) => id === 'dataisland' ? islandEl : null
    };
    const preExisting = { someOtherProperty: 'original-value' };
    const window = { __dataIsland: preExisting };
    const ctx = vm.createContext({
      window, document,
      setTimeout: () => 0, clearTimeout: () => {},
      Promise, String, console, Response,
      Object: globalThis.Object
    });
    vm.runInContext(extractReaderSource(html), ctx);

    // Existing object preserved (not overwritten):
    assert.strictEqual(ctx.window.__dataIsland, preExisting);
    assert.strictEqual(ctx.window.__dataIsland.someOtherProperty, 'original-value');
    // .get added since it was missing:
    assert.strictEqual(typeof ctx.window.__dataIsland.get, 'function');
    // And it works:
    const result = ctx.window.__dataIsland.get('https://x.test/foo');
    assert.strictEqual(result.contentType, 'application/ld+json');
    assert.strictEqual(result.content, '{"@id":"#me"}');
  });

  it('does not overwrite a pre-existing window.__dataIsland.get', () => {
    const customGet = function () {
      return { contentType: 'custom', content: 'from-custom-get' };
    };
    const islandEl = {
      type: 'application/ld+json',
      textContent: '{"@id":"#me"}',
      getAttribute: (n) => n === 'data-uri' ? 'https://x.test/foo' : null
    };
    const document = {
      getElementById: (id) => id === 'dataisland' ? islandEl : null
    };
    const window = { __dataIsland: { get: customGet } };
    const ctx = vm.createContext({
      window, document,
      setTimeout: () => 0, clearTimeout: () => {},
      Promise, String, console, Response,
      Object: globalThis.Object
    });
    vm.runInContext(extractReaderSource(html), ctx);

    assert.strictEqual(ctx.window.__dataIsland.get, customGet,
      'pre-existing custom .get must not be replaced');
  });

  it('tolerates missing fetcher.requested without hanging the Promise', async () => {
    // Some rdflib/mashlib builds may not initialize `requested`.
    // The patched load must still resolve cleanly.
    const fakeFetcher = {
      // No `requested` property.
      store: {},
      load: async () => 'orig'
    };
    const $rdf = {
      fetcher: fakeFetcher,
      parse: (c, s, u, ct, cb) => cb(null),
      sym: (u) => u
    };
    const ctx = makeContext({
      islands: { 'https://x.test/foo': '{"@id":"#z"}' },
      $rdf
    });
    vm.runInContext(extractReaderSource(html), ctx);

    // Bound the wait so a hanging Promise fails the test rather than
    // hanging the whole suite.
    const result = await Promise.race([
      fakeFetcher.load('https://x.test/foo', {}),
      new Promise((_, reject) =>
        setTimeout(() => reject(new Error('load() hung')), 500))
    ]);
    assert.strictEqual(result.ok, true);
    assert.strictEqual(result.url, 'https://x.test/foo');
  });
});
