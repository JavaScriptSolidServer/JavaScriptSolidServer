/**
 * Panes loaded at start-up (#652).
 *
 * `--panes` gives the server a list of pane module URLs. The data browser
 * page loads and registers them before it starts SolidOS. These tests pin:
 *   - the list is cleaned (http(s) URLs and absolute paths only), and the
 *     dropped entries are reported
 *   - with no panes the generated page is unchanged
 *   - with panes the page loads them, then starts SolidOS (CDN and local)
 *   - module mode is not touched
 *   - a URL cannot break out of the inline script
 *   - the start-up function: always starts once, a dead or slow pane host
 *     holds back only its own pane, configured order is kept
 *   - the loader is served only when panes are configured, its path
 *     cannot be written to, and it loads nothing named in its own URL
 *   - the 401 page is a data browser page too, and gets the panes
 */

import { describe, it, before, after, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert';
import fs from 'node:fs/promises';
import {
  startTestServer,
  stopTestServer,
  request,
  createTestPod,
  assertStatus
} from './helpers.js';
import {
  generateDatabrowserHtml,
  generateModuleDatabrowserHtml,
  jssStartDataBrowser,
  normalizePanes,
  sortPanes,
  PANE_LOADER_PATH
} from '../src/mashlib/index.js';

const PANE = 'https://panes.example/calendar-pane.js';
const HTML = { Accept: 'text/html', 'Sec-Fetch-Dest': 'document' };

describe('panes at start-up — the list (unit, #652)', () => {
  it('accepts an array or a comma-separated string', () => {
    assert.deepStrictEqual(normalizePanes([PANE, '/public/panes/a.js']), [PANE, '/public/panes/a.js']);
    assert.deepStrictEqual(normalizePanes(` ${PANE} , /public/panes/a.js ,`), [PANE, '/public/panes/a.js']);
  });

  it('is empty for nothing', () => {
    for (const v of [undefined, null, false, '', [], ' , ']) {
      assert.deepStrictEqual(normalizePanes(v), []);
    }
  });

  it('drops anything that is not an http(s) URL or an absolute path', () => {
    const bad = ['javascript:alert(1)', 'data:text/javascript,1', '../a.js', 'a.js', '//evil.example/a.js', 'ftp://x/a.js', 'https://x/a b.js', 42, null];
    assert.deepStrictEqual(normalizePanes(bad), []);
  });

  it('removes duplicates and keeps order', () => {
    assert.deepStrictEqual(normalizePanes(['/b.js', PANE, '/b.js']), ['/b.js', PANE]);
  });

  it('reports what it dropped', () => {
    assert.deepStrictEqual(sortPanes(`${PANE}, htps://typo/a.js ,, foo.js`), {
      urls: [PANE],
      dropped: ['htps://typo/a.js', 'foo.js']
    });
    assert.deepStrictEqual(sortPanes(undefined), { urls: [], dropped: [] });
  });

  it('keeps a URL with a comma when given as an array', () => {
    const url = 'https://cdn.example/combine/a.js,b.js';
    assert.deepStrictEqual(normalizePanes([url]), [url]);
  });
});

describe('panes at start-up — the page (unit, #652)', () => {
  const modes = [
    ['CDN', (opts) => generateDatabrowserHtml('https://pod.example/', '2.0.0', opts)],
    ['local', (opts) => generateDatabrowserHtml('https://pod.example/', null, opts)]
  ];

  for (const [name, page] of modes) {
    it(`${name} mode: no panes leaves the page unchanged`, () => {
      const plain = page({});
      assert.strictEqual(page({ panes: [] }), plain);
      assert.strictEqual(page({ panes: null }), plain);
      assert.strictEqual(page({ panes: 'not a url' }), plain);
      assert.ok(!plain.includes(PANE_LOADER_PATH));
      assert.ok(!plain.includes('jssStartDataBrowser'));
    });

    it(`${name} mode: panes are loaded through the loader, then SolidOS starts`, () => {
      const html = page({ panes: [PANE] });
      assert.ok(html.includes('function jssStartDataBrowser('), 'defines the start-up function');
      assert.match(html, new RegExp(`jssStartDataBrowser\\(\\["${PANE.replace(/[.]/g, '\\.')}"\\], "/\\.well-known/jss/pane-loader\\.js\\?v=[^"]+", \\d+\\)`), 'calls it with the list, the versioned loader and a time limit');
      // The only call to runDataBrowser is the one inside the function.
      assert.strictEqual(html.split('panes.runDataBrowser()').length - 1, 1);
    });
  }

  it('module mode is not touched', () => {
    const plain = generateModuleDatabrowserHtml('https://cdn.example/mashlib.js', 'https://pod.example/', {});
    const withPanes = generateModuleDatabrowserHtml('https://cdn.example/mashlib.js', 'https://pod.example/', { panes: [PANE] });
    assert.strictEqual(withPanes, plain);
  });

  it('a pane URL cannot close the inline script', () => {
    const nasty = 'https://panes.example/a.js?x=</script><script>alert(1)</script>';
    for (const [, page] of modes) {
      const html = page({ panes: [nasty] });
      assert.ok(!html.includes('<script>alert(1)'), 'no injected script tag');
      assert.ok(html.includes('\\u003c/script>'), 'the < is escaped inside the script');
    }
  });
});

describe('panes at start-up — the start-up function (unit, #652)', () => {
  let starts, registered, log, saved;

  // A fake loader: loadPane registers a pane named after its URL, or
  // reports a failure for a URL the fake "network" rejects.
  const fakeLoader = (failing = []) => ({
    loadPane: async (url) => {
      if (failing.includes(url)) return { url, ok: false, reason: 'import failed' };
      registered.push(url);
      return { url, ok: true, name: url };
    }
  });
  // A fake import(): the loader URL gives the loader; each pane URL
  // settles when the test says so.
  const network = (loader, behaviour = {}) => (url) => {
    if (url === 'LOADER') return loader ? Promise.resolve(loader) : Promise.reject(new Error('no loader'));
    const b = behaviour[url];
    if (b === 'hang') return new Promise(() => {});
    if (b === 'fail') return Promise.reject(new Error('404'));
    if (typeof b === 'number') return new Promise((resolve) => setTimeout(() => resolve({}), b));
    return Promise.resolve({});
  };

  beforeEach(() => {
    starts = 0; registered = []; log = [];
    saved = { panes: globalThis.panes, info: console.info, warn: console.warn };
    globalThis.panes = { runDataBrowser: () => { starts++; log.push('start'); } };
    console.info = (m) => log.push('info ' + m);
    console.warn = (m) => log.push('warn ' + m);
  });
  afterEach(() => {
    globalThis.panes = saved.panes; console.info = saved.info; console.warn = saved.warn;
  });

  it('registers every pane, in the configured order, then starts once', async () => {
    // b arrives before a, but a is listed first.
    await jssStartDataBrowser(['a', 'b'], 'LOADER', 1000, network(fakeLoader(), { a: 30, b: 0 }));
    assert.deepStrictEqual(registered, ['a', 'b']);
    assert.strictEqual(starts, 1);
    assert.strictEqual(log[log.length - 1], 'start', 'SolidOS starts after the panes');
  });

  it('skips a pane that fails and still starts', async () => {
    await jssStartDataBrowser(['bad', 'good'], 'LOADER', 1000, network(fakeLoader(['bad']), { bad: 'fail' }));
    assert.deepStrictEqual(registered, ['good']);
    assert.strictEqual(starts, 1);
    assert.ok(log.some((l) => l.startsWith('warn [jss] pane skipped: bad')));
  });

  it('starts without panes when the loader cannot be imported', async () => {
    await jssStartDataBrowser(['a'], 'LOADER', 1000, network(null));
    assert.deepStrictEqual(registered, []);
    assert.strictEqual(starts, 1);
    assert.ok(log.some((l) => l.startsWith('warn [jss] panes not loaded')));
  });

  it('a host that never answers holds back only its own pane', async () => {
    const t0 = Date.now();
    await jssStartDataBrowser(['dead', 'good'], 'LOADER', 60, network(fakeLoader(), { dead: 'hang' }));
    assert.ok(Date.now() - t0 < 1000, 'did not wait for the dead host');
    assert.deepStrictEqual(registered, ['good'], 'the pane listed after the dead one is registered');
    assert.strictEqual(starts, 1);
  });

  it('a pane slower than the limit is registered when it arrives, without a second start', async () => {
    await jssStartDataBrowser(['slow', 'good'], 'LOADER', 40, network(fakeLoader(), { slow: 120 }));
    assert.deepStrictEqual(registered, ['good']);
    assert.strictEqual(starts, 1);
    await new Promise((resolve) => setTimeout(resolve, 150));
    assert.deepStrictEqual(registered, ['good', 'slow']);
    assert.strictEqual(starts, 1);
    assert.ok(log.some((l) => l.includes('"slow"') && l.includes('(after start-up)')));
  });

  it('starts at the time limit even if the loader itself hangs', async () => {
    const hangingLoader = (url) => new Promise(() => {});
    jssStartDataBrowser(['a'], 'LOADER', 30, hangingLoader);
    await new Promise((resolve) => setTimeout(resolve, 80));
    assert.strictEqual(starts, 1);
  });
});

describe('panes at start-up — the shipped loader (unit, #652)', () => {
  it('loads nothing named in its own URL', async () => {
    const source = await fs.readFile(new URL('../src/mashlib/pane-loader.js', import.meta.url), 'utf8');
    assert.ok(!/searchParams|import\.meta/.test(source), 'no ?pane= handling in the shipped copy');
    assert.match(source, /export async function loadPane /);
  });
});

describe('panes at start-up — live server with panes (#652)', () => {
  before(async () => {
    await startTestServer({ mashlibCdn: true, panes: `${PANE}, /public/panes/local-pane.js` });
    await createTestPod('panetest');
  });
  after(async () => { await stopTestServer(); });

  it('serves the loader as JavaScript, with or without the version query', async () => {
    for (const url of [PANE_LOADER_PATH, PANE_LOADER_PATH + '?v=1.2.3']) {
      const res = await request(url);
      assertStatus(res, 200);
      assert.match(res.headers.get('content-type'), /^text\/javascript/);
      assert.match(await res.text(), /export async function loadPanes/);
    }
  });

  it('answers HEAD for the loader with the same length as GET', async () => {
    const get = await request(PANE_LOADER_PATH);
    await get.text();
    const head = await request(PANE_LOADER_PATH, { method: 'HEAD' });
    assertStatus(head, 200);
    assert.match(head.headers.get('content-type'), /^text\/javascript/);
    assert.strictEqual(head.headers.get('content-length'), get.headers.get('content-length'));
  });

  it('refuses writes to the loader path', async () => {
    for (const method of ['PUT', 'DELETE', 'PATCH', 'POST']) {
      const res = await request(PANE_LOADER_PATH, {
        method,
        headers: { 'Content-Type': 'text/javascript' },
        body: method === 'DELETE' ? undefined : 'export default 1',
        auth: 'panetest'
      });
      assertStatus(res, 405, `${method} must be refused`);
    }
    const res = await request(PANE_LOADER_PATH);
    assert.match(await res.text(), /export async function loadPanes/, 'still the packaged loader');
  });

  it('the data browser page loads the configured panes', async () => {
    const res = await request('/panetest/public/', { headers: HTML });
    assertStatus(res, 200);
    const html = await res.text();
    assert.ok(html.includes('function jssStartDataBrowser('));
    assert.ok(html.includes(JSON.stringify([PANE, '/public/panes/local-pane.js'])));
  });

  it('the 401 page for a private resource loads them too', async () => {
    const res = await request('/panetest/private/', { headers: HTML });
    assertStatus(res, 401);
    const html = await res.text();
    assert.ok(html.includes('function jssStartDataBrowser('), 'the unauthorised page is a data browser page');
    assert.ok(html.includes(JSON.stringify([PANE, '/public/panes/local-pane.js'])));
  });
});

describe('panes at start-up — live server without panes (#652)', () => {
  before(async () => {
    await startTestServer({ mashlibCdn: true });
    await createTestPod('nopanes');
  });
  after(async () => { await stopTestServer(); });

  it('does not serve the loader', async () => {
    const res = await request(PANE_LOADER_PATH);
    assertStatus(res, 404);
  });

  it('the data browser page starts SolidOS directly', async () => {
    const res = await request('/nopanes/public/', { headers: HTML });
    assertStatus(res, 200);
    const html = await res.text();
    assert.ok(!html.includes('jssStartDataBrowser'));
    assert.ok(html.includes('panes.runDataBrowser()'));
  });
});
