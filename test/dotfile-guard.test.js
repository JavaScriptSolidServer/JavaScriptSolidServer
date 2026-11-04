/**
 * Dotfile guard vs percent-encoding (#639)
 *
 * The guard in server.js used to look at the raw request URL while the
 * storage lookup decoded it, so `/pod/%2Egit/config` passed the guard
 * and read `.git/config` from disk. Both now decode the same way.
 */
import { describe, it, before, after } from 'node:test';
import assert from 'node:assert';
import fs from 'fs-extra';
import path from 'path';
import { startTestServer, stopTestServer, createTestPod, request, assertStatus } from './helpers.js';
import { urlToPath, urlToPathWithPod } from '../src/utils/url.js';
import { decodeSegments, findForbiddenDotfile } from '../src/utils/dotfiles.js';

const POD = 'dotguard';
const CANARY = 'canary-639-do-not-serve';
const podDir = path.resolve('./data', POD);

describe('dotfile guard decodes the path before checking it (#639)', () => {
  before(async () => {
    await startTestServer();
    await createTestPod(POD);
    await fs.outputFile(path.join(podDir, '.git', 'config'), `[canary]\n\tvalue = ${CANARY}\n`);
    await fs.outputFile(path.join(podDir, '.env'), `SECRET=${CANARY}\n`);
    await fs.outputFile(path.join(podDir, 'public', '.htpasswd'), `${CANARY}\n`);
  });

  after(async () => {
    await stopTestServer();
  });

  async function assertBlocked(urlPath, status = 403) {
    const res = await request(urlPath);
    const body = await res.text();
    assertStatus(res, status, `${urlPath} should be ${status}`);
    assert.ok(!body.includes(CANARY), `${urlPath} leaked the file body`);
  }

  it('still blocks the literal dotfile paths', async () => {
    await assertBlocked(`/${POD}/.git/config`);
    await assertBlocked(`/${POD}/.env`);
    await assertBlocked(`/${POD}/public/.htpasswd`);
  });

  it('blocks a real .git/config requested with an encoded dot', async () => {
    await assertBlocked(`/${POD}/%2Egit/config`);
    await assertBlocked(`/${POD}/%2egit/config`);
    await assertBlocked(`/${POD}/%2Egit/%63onfig`);
  });

  it('blocks encoded forms of the other dotfiles', async () => {
    await assertBlocked(`/${POD}/%2Eenv`);
    await assertBlocked(`/${POD}/public/%2Ehtpasswd`);
    await assertBlocked(`/${POD}/public/%2E%68tpasswd`);
  });

  it('blocks encoded dotfiles on every method', async () => {
    for (const method of ['HEAD', 'PUT', 'DELETE', 'PATCH', 'POST']) {
      const res = await request(`/${POD}/%2Egit/config`, {
        method,
        headers: { 'Content-Type': 'text/plain' },
        body: method === 'HEAD' ? undefined : 'x',
        auth: POD
      });
      assertStatus(res, 403, `${method} should be 403`);
    }
    assert.strictEqual(await fs.readFile(path.join(podDir, '.git', 'config'), 'utf8'),
      `[canary]\n\tvalue = ${CANARY}\n`, 'the file on disk is untouched');
  });

  it('does not serve the file for a double-encoded dot either', async () => {
    // Decoded once this is `%2Egit`, which is not a file on disk: 404, never the body.
    const res = await request(`/${POD}/%252Egit/config`, { auth: POD });
    const body = await res.text();
    assertStatus(res, 404);
    assert.ok(!body.includes(CANARY));
  });

  it('refuses a path it cannot decode instead of passing it on', async () => {
    await assertBlocked(`/${POD}/%E0%A4%A/config`, 400);
    await assertBlocked(`/${POD}/%2Egit%2Fconfig`, 400);
    await assertBlocked(`/${POD}/public%2F%2Ehtpasswd`, 400);
  });

  it('allows the Solid dotfiles only when the dot is literal', async () => {
    const literal = await request(`/${POD}/public/.acl`, { auth: POD });
    assert.notStrictEqual(literal.status, 403);
    const encoded = await request(`/${POD}/public/%2Eacl`, { auth: POD });
    assertStatus(encoded, 403, 'a dot that only appears after decoding is refused');
    const wellKnown = await request('/.well-known/openid-configuration');
    assert.notStrictEqual(wellKnown.status, 403);
  });

  it('leaves ordinary encoded names alone', async () => {
    const put = await request(`/${POD}/public/a%20b.txt`, {
      method: 'PUT', headers: { 'Content-Type': 'text/plain' }, body: 'hello', auth: POD
    });
    assert.ok([201, 204].includes(put.status), `PUT gave ${put.status}`);
    const get = await request(`/${POD}/public/a%20b.txt`);
    assertStatus(get, 200);
    assert.strictEqual(await get.text(), 'hello');
    const trailingDot = await request(`/${POD}/public/name%2E`);
    assert.notStrictEqual(trailingDot.status, 403);
  });
});

describe('the path lookup refuses what the guard refuses (#639)', () => {
  it('rejects a segment that only becomes a dotfile by decoding', () => {
    for (const p of ['/alice/%2Egit/config', '/alice/%2eenv', '/alice/%2Eacl', '/alice/pub/%2E%2E%2Egit']) {
      assert.throws(() => urlToPath(p), (err) => err.statusCode === 403, p);
      assert.throws(() => urlToPathWithPod(p, 'alice'), (err) => err.statusCode === 403, p);
    }
  });

  it('rejects malformed encoding and encoded separators with 400', () => {
    for (const p of ['/alice/%E0%A4%A', '/alice/pub%2Fx', '/alice/pub%5Cx']) {
      assert.throws(() => urlToPath(p), (err) => err.statusCode === 400, p);
    }
  });

  it('still resolves literal dotfile names for internal callers', () => {
    assert.ok(urlToPath('/alice/.git/config').endsWith(path.join('alice', '.git', 'config')));
    assert.ok(urlToPath('/alice/.quota.json').endsWith('.quota.json'));
    assert.ok(urlToPath('/alice/.%61cl').endsWith(path.join('alice', '.acl')));
    assert.ok(urlToPathWithPod('/public/.acl', 'alice').endsWith(path.join('alice', 'public', '.acl')));
  });

  it('keeps the traversal stripping', () => {
    const root = urlToPath('/');
    assert.strictEqual(urlToPath('/alice/%2E%2E/%2E%2E/etc/passwd'), path.join(root, 'alice', 'etc', 'passwd'));
    assert.strictEqual(urlToPath('//alice/....//x'), path.join(root, 'alice', 'x'));
    assert.throws(() => urlToPath('/%2E%2E%2Fetc'), (err) => err.statusCode === 400);
  });

  it('decodeSegments and findForbiddenDotfile agree with the guard', () => {
    assert.deepStrictEqual(decodeSegments('/a/%2Eb').map((s) => s.decoded), ['', 'a', '.b']);
    assert.strictEqual(findForbiddenDotfile('/alice/%2Egit/config'), '.git');
    assert.strictEqual(findForbiddenDotfile('/alice/.acl'), null);
    assert.strictEqual(findForbiddenDotfile('/alice/%2Eacl'), '.acl');
    assert.strictEqual(findForbiddenDotfile('/.well-known/openid-configuration'), null);
    assert.throws(() => findForbiddenDotfile('/%zz'), (err) => err.statusCode === 400);
  });
});
