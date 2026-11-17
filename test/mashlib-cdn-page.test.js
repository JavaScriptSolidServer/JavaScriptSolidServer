/**
 * Mashlib CDN mode: the page matches the mashlib version (#660).
 *
 * mashlib 3.x draws into `#OutlineView` inside `<solid-ui-provider>`;
 * 2.x draws into `<table id="outline">`. The default version is 3.1.0.
 */

import { describe, it } from 'node:test';
import assert from 'node:assert';
import { generateDatabrowserHtml, isMashlib3, jssSyncHeaderHeight } from '../src/mashlib/index.js';
import { defaults } from '../src/config.js';

describe('mashlib CDN page (#660)', () => {
  it('defaults to mashlib 3.1.0', () => {
    assert.strictEqual(defaults.mashlibVersion, '3.1.0');
  });

  it('tells 3.x from earlier versions', () => {
    for (const v of ['3.1.0', '3.0.0', 'v3.2.1', '4.0.0', '10.0.0']) assert.strictEqual(isMashlib3(v), true, v);
    for (const v of ['2.0.0', '2.1.3', '1.10.4', '', null, undefined, 'latest']) assert.strictEqual(isMashlib3(v), false, String(v));
  });

  it('serves the 3.x page for 3.x', () => {
    const html = generateDatabrowserHtml('https://pod.example/', '3.1.0');
    assert.ok(html.includes('<solid-ui-provider>'));
    assert.ok(html.includes('id="OutlineView"'));
    assert.ok(html.includes('data-app-shell="databrowser"'));
    assert.ok(html.includes('https://unpkg.com/mashlib@3.1.0/dist/mashlib.min.js'));
    assert.ok(html.includes('https://unpkg.com/mashlib@3.1.0/dist/mash.css'));
    assert.ok(html.includes('panes.runDataBrowser(); jssSyncHeaderHeight();'));
    assert.ok(html.includes('function jssSyncHeaderHeight()'));
    assert.ok(!html.includes('<table id="outline">'));
  });

  it('keeps the 2.x page for 2.x', () => {
    const html = generateDatabrowserHtml('https://pod.example/', '2.0.0');
    assert.ok(html.includes('<table id="outline">'));
    assert.ok(html.includes('id="PageHeader"'));
    assert.ok(!html.includes('solid-ui-provider'));
    assert.ok(!html.includes('jssSyncHeaderHeight'));
  });

  it('starts through the pane loader on the 3.x page when panes are configured', () => {
    const html = generateDatabrowserHtml('https://pod.example/', '3.1.0', { panes: ['https://panes.example/a.js'] });
    assert.ok(html.includes('id="OutlineView"'));
    assert.ok(html.includes('jssStartDataBrowser(["https://panes.example/a.js"]'));
    assert.ok(html.includes('jssSyncHeaderHeight();'));
  });

  it('keeps the data island on the 3.x page', () => {
    const html = generateDatabrowserHtml('https://pod.example/x', '3.1.0', { embedJsonLd: '{"@id":"https://pod.example/x"}' });
    assert.ok(html.includes('<script type="application/ld+json"'));
  });

  it('header sync is self-contained (serialized into the page)', () => {
    const src = jssSyncHeaderHeight.toString();
    assert.ok(src.startsWith('function jssSyncHeaderHeight()'));
    assert.ok(!/=>|`|\bconst\b|\blet\b/.test(src));
  });
});
