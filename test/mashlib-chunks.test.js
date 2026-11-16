/**
 * Mashlib CDN mode: lazy chunk requests are redirected to the CDN (#654).
 *
 * Mashlib asks the pod for its lazy chunks. 2.x names them
 * `841.mashlib.min.js`; 3.x names them `799.js`, `410.js`. Both shapes must
 * redirect, whatever the number, and nothing else at the root may.
 */

import { describe, it, before, after } from 'node:test';
import assert from 'node:assert';
import { startTestServer, stopTestServer, request } from './helpers.js';

const get = (path) => request(path, { redirect: 'manual' });

describe('mashlib CDN mode — lazy chunks (#654)', () => {
  before(async () => {
    await startTestServer({ mashlib: true, mashlibCdn: true, mashlibVersion: '3.1.0' });
  });
  after(async () => {
    await stopTestServer();
  });

  for (const file of ['841.mashlib.min.js', '841.mashlib.min.js.map', '799.js', '410.js', '841.js.map']) {
    it(`redirects /${file} to the CDN`, async () => {
      const res = await get(`/${file}`);
      assert.strictEqual(res.status, 302);
      assert.strictEqual(res.headers.get('location'), `https://unpkg.com/mashlib@3.1.0/dist/${file}`);
    });
  }

  for (const path of ['/app.js', '/799.json', '/799.js.txt', '/public/799.js', '/a799.js']) {
    it(`leaves ${path} alone`, async () => {
      const res = await get(path);
      assert.notStrictEqual(res.status, 302);
    });
  }
});

describe('without CDN mode — no chunk redirect (#654)', () => {
  before(async () => {
    await startTestServer({});
  });
  after(async () => {
    await stopTestServer();
  });

  it('does not redirect /799.js', async () => {
    const res = await get('/799.js');
    assert.notStrictEqual(res.status, 302);
  });
});
