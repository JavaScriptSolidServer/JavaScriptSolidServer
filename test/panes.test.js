/**
 * Panes loaded at start-up (#652).
 *
 * `--panes` gives the server a list of pane module URLs. The data browser
 * page loads and registers them before it starts SolidOS. These tests pin:
 *   - the list is cleaned (http(s) URLs and absolute paths only)
 *   - with no panes the generated page is unchanged
 *   - with panes the page loads them, then starts SolidOS, in every mode
 *   - a URL cannot break out of the inline script
 *   - the loader is served only when panes are configured, and its path
 *     cannot be written to
 */

import { describe, it, before, after } from 'node:test';
import assert from 'node:assert';
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
  normalizePanes,
  PANE_LOADER_PATH
} from '../src/mashlib/index.js';

const PANE = 'https://panes.example/calendar-pane.js';

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
});

describe('panes at start-up — the page (unit, #652)', () => {
  const modes = [
    ['CDN', (opts) => generateDatabrowserHtml('https://pod.example/', '2.0.0', opts)],
    ['local', (opts) => generateDatabrowserHtml('https://pod.example/', null, opts)],
    ['module', (opts) => generateModuleDatabrowserHtml('https://cdn.example/mashlib.js', 'https://pod.example/', opts)]
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

    it(`${name} mode: panes are loaded through the loader`, () => {
      const html = page({ panes: [PANE] });
      assert.ok(html.includes(PANE_LOADER_PATH), 'imports the loader');
      assert.ok(html.includes(JSON.stringify([PANE])), 'names the pane');
    });
  }

  it('CDN and local modes start SolidOS only through the pane step', () => {
    for (const cdn of ['2.0.0', null]) {
      const html = generateDatabrowserHtml('https://pod.example/', cdn, { panes: [PANE] });
      // The only call to runDataBrowser is inside jssStartDataBrowser.
      assert.strictEqual(html.split('panes.runDataBrowser()').length - 1, 1);
      assert.ok(html.includes('function jssStartDataBrowser()'));
      assert.match(html, /\.catch\(/, 'a loader failure is caught');
      assert.match(html, /setTimeout\(start, \d+\)/, 'a slow pane host cannot hold the page');
    }
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

describe('panes at start-up — live server with panes (#652)', () => {
  before(async () => {
    await startTestServer({ mashlibCdn: true, panes: `${PANE}, /public/panes/local-pane.js` });
    await createTestPod('panetest');
  });
  after(async () => { await stopTestServer(); });

  it('serves the loader as JavaScript', async () => {
    const res = await request(PANE_LOADER_PATH);
    assertStatus(res, 200);
    assert.match(res.headers.get('content-type'), /^text\/javascript/);
    const body = await res.text();
    assert.match(body, /export async function loadPanes/);
  });

  it('answers HEAD for the loader', async () => {
    const res = await request(PANE_LOADER_PATH, { method: 'HEAD' });
    assertStatus(res, 200);
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
    const res = await request('/panetest/public/', { headers: { Accept: 'text/html', 'Sec-Fetch-Dest': 'document' } });
    assertStatus(res, 200);
    const html = await res.text();
    assert.ok(html.includes('jssStartDataBrowser'));
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
    const res = await request('/nopanes/public/', { headers: { Accept: 'text/html', 'Sec-Fetch-Dest': 'document' } });
    assertStatus(res, 200);
    const html = await res.text();
    assert.ok(!html.includes('jssStartDataBrowser'));
    assert.ok(html.includes('panes.runDataBrowser()'));
  });
});
