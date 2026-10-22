/**
 * Nostr relay NIP-11 tests
 *
 * NIP-11 says the relay information document is served at the relay's own
 * URL when the client sends `Accept: application/nostr+json`. Tools such as
 * `nak relay` only ask there, so serving it at <path>/info alone made the
 * relay look non-compliant. The WebSocket relay on the same path must keep
 * working.
 */

import { describe, it, before, after } from 'node:test';
import assert from 'node:assert';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { WebSocket } from 'ws';
import { createServer } from '../src/server.js';

describe('Nostr relay NIP-11', () => {
  let fastify;
  let base;

  before(async () => {
    const root = mkdtempSync(join(tmpdir(), 'jss-nip11-'));
    fastify = createServer({ root, port: 0, logger: false, nostr: true });
    await fastify.listen({ port: 0, host: '127.0.0.1' });
    base = `127.0.0.1:${fastify.server.address().port}`;
  });

  after(async () => {
    await fastify.close();
  });

  it('serves the info document at the relay URL for Accept: application/nostr+json', async () => {
    const res = await fetch(`http://${base}/relay`, { headers: { Accept: 'application/nostr+json' } });
    assert.strictEqual(res.status, 200);
    assert.match(res.headers.get('content-type'), /application\/nostr\+json/);
    assert.strictEqual(res.headers.get('access-control-allow-origin'), '*');
    const info = await res.json();
    assert.ok(info.supported_nips.includes(11));
  });

  it('still returns 404 for a plain GET of the relay URL', async () => {
    const res = await fetch(`http://${base}/relay`);
    assert.strictEqual(res.status, 404);
  });

  it('keeps serving the document at /relay/info', async () => {
    const res = await fetch(`http://${base}/relay/info`);
    assert.strictEqual(res.status, 200);
    const info = await res.json();
    assert.ok(info.supported_nips.includes(11));
  });

  it('still accepts WebSocket subscriptions on the relay URL', async () => {
    const ws = new WebSocket(`ws://${base}/relay`);
    const msg = await new Promise((resolve, reject) => {
      ws.on('open', () => ws.send(JSON.stringify(['REQ', 'sub1', { kinds: [1], limit: 1 }])));
      ws.on('message', (data) => resolve(JSON.parse(data.toString())));
      ws.on('error', reject);
    });
    ws.close();
    assert.deepStrictEqual(msg, ['EOSE', 'sub1']);
  });
});
