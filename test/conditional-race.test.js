/**
 * Concurrent conditional writes (#600)
 *
 * If-Match is only useful if the precondition check and the write are one step.
 * Several writers racing with the same, currently valid, ETag must end with exactly
 * one of them succeeding; the rest get 412 and the resource holds the winner's body.
 */

import { describe, it, before, after } from 'node:test';
import assert from 'node:assert';
import fs from 'node:fs';
import { startTestServer, stopTestServer, request, createTestPod, assertStatus } from './helpers.js';

const POD = 'racetest';
const JSON_LD = { 'Content-Type': 'application/ld+json' };

const put = (path, body, headers = {}) => request(path, {
  method: 'PUT', headers: { ...JSON_LD, ...headers }, body: JSON.stringify(body), auth: POD
});

async function createAndGetEtag(path, body) {
  assertStatus(await put(path, body), 201);
  const res = await request(path, { auth: POD });
  const etag = res.headers.get('ETag');
  assert.ok(etag, 'resource has an ETag');
  return etag;
}

describe('Concurrent conditional writes (#600)', () => {
  before(async () => {
    await startTestServer();
    await createTestPod(POD);
  });

  after(async () => {
    await stopTestServer();
  });

  it('racing PUTs with the same If-Match: exactly one wins, the others get 412', async () => {
    const path = `/${POD}/public/race-put.json`;
    const etag = await createAndGetEtag(path, { '@id': '#doc', 'http://example.org/v': 0 });

    const bodies = [1, 2, 3, 4, 5].map((v) => ({ '@id': '#doc', 'http://example.org/v': v, 'http://example.org/pad': 'x'.repeat(v * 7) }));
    const results = await Promise.all(bodies.map((b) => put(path, b, { 'If-Match': etag })));
    const statuses = results.map((r) => r.status);

    const winners = statuses.filter((s) => s === 204);
    assert.strictEqual(winners.length, 1, `exactly one 204, got ${statuses.join(',')}`);
    assert.ok(statuses.filter((s) => s === 412).length === bodies.length - 1, `the rest are 412, got ${statuses.join(',')}`);

    const stored = await (await request(path, { auth: POD })).json();
    const winner = bodies[statuses.indexOf(204)];
    assert.strictEqual(stored['http://example.org/v'], winner['http://example.org/v'], 'the stored body is the winner\'s');
  });

  it('racing DELETE and PUT with the same If-Match: exactly one wins', async () => {
    const path = `/${POD}/public/race-delete.json`;
    const etag = await createAndGetEtag(path, { '@id': '#doc', 'http://example.org/v': 0 });

    const [del, upd] = await Promise.all([
      request(path, { method: 'DELETE', headers: { 'If-Match': etag }, auth: POD }),
      put(path, { '@id': '#doc', 'http://example.org/v': 1, 'http://example.org/pad': 'yyyyyyyy' }, { 'If-Match': etag })
    ]);
    const ok = [del.status, upd.status].filter((s) => s === 204).length;
    assert.strictEqual(ok, 1, `exactly one of DELETE/PUT succeeds, got ${del.status}/${upd.status}`);
    assert.strictEqual([del.status, upd.status].includes(412), true, `the loser gets 412, got ${del.status}/${upd.status}`);

    const after = await request(path, { auth: POD });
    if (del.status === 204) assertStatus(after, 404, 'DELETE won, resource is gone');
    else assert.strictEqual((await after.json())['http://example.org/v'], 1, 'PUT won, resource holds its body');
  });

  it('racing If-None-Match: * creates: exactly one 201', async () => {
    const path = `/${POD}/public/race-create.json`;
    const results = await Promise.all([1, 2, 3].map((v) => put(path, { '@id': '#doc', 'http://example.org/v': v }, { 'If-None-Match': '*' })));
    const statuses = results.map((r) => r.status);
    assert.strictEqual(statuses.filter((s) => s === 201).length, 1, `exactly one 201, got ${statuses.join(',')}`);
    assert.strictEqual(statuses.filter((s) => s === 412).length, 2, `the rest are 412, got ${statuses.join(',')}`);
  });

  it('a failed If-Match PUT into a container that does not exist leaves nothing behind', async () => {
    const path = `/${POD}/public/race-nodir/x.json`;
    assertStatus(await put(path, { '@id': '#doc' }, { 'If-Match': '"nope"' }), 412);
    assertStatus(await request(`/${POD}/public/race-nodir/`, { auth: POD }), 404, 'no container was created');
  });

  it('no lock file is left next to the resource', async () => {
    const path = `/${POD}/public/race-lock.json`;
    const etag = await createAndGetEtag(path, { '@id': '#doc', 'http://example.org/v': 0 });
    await Promise.all([1, 2].map((v) => put(path, { '@id': '#doc', 'http://example.org/v': v, 'http://example.org/pad': 'p'.repeat(v * 3) }, { 'If-Match': etag })));
    const listing = await (await request(`/${POD}/public/`, { headers: { Accept: 'application/ld+json' }, auth: POD })).text();
    assert.ok(!listing.includes('race-lock.json.lock'), 'lock sidecar is not listed');
    assert.ok(!fs.existsSync(`./data/${POD}/public/.race-lock.json.lock`), 'lock sidecar is gone from disk');
  });

  it('the same PUTs in sequence: 204 then 412', async () => {
    const path = `/${POD}/public/race-seq.json`;
    const etag = await createAndGetEtag(path, { '@id': '#doc', 'http://example.org/v': 0 });
    assertStatus(await put(path, { '@id': '#doc', 'http://example.org/v': 1, 'http://example.org/pad': 'zzzz' }, { 'If-Match': etag }), 204);
    assertStatus(await put(path, { '@id': '#doc', 'http://example.org/v': 2, 'http://example.org/pad': 'zzzzzz' }, { 'If-Match': etag }), 412);
  });
});
