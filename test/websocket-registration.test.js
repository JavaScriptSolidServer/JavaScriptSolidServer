/**
 * @fastify/websocket registration tests (#545)
 *
 * Several features (notifications, nostr relay, webrtc, terminal, tunnel,
 * app plugins) need @fastify/websocket. Each registration adds an 'upgrade'
 * listener to the shared HTTP server; with more than one, every WebSocket
 * upgrade logs N-1 spurious "websocket upgrade failed" warnings. The server
 * must register the plugin exactly once, at the root, whatever is enabled.
 */

import { describe, it } from 'node:test';
import assert from 'node:assert';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createServer } from '../src/server.js';

async function upgradeListeners(options) {
  const root = mkdtempSync(join(tmpdir(), 'jss-ws-reg-'));
  const fastify = createServer({ root, port: 0, logger: false, ...options });
  await fastify.ready();
  try {
    return fastify.server.listenerCount('upgrade');
  } finally {
    await fastify.close();
  }
}

describe('@fastify/websocket registration', () => {
  it('adds no upgrade listener when no WebSocket feature is enabled', async () => {
    assert.strictEqual(await upgradeListeners({}), 0);
  });

  it('adds exactly one upgrade listener for a single WebSocket feature', async () => {
    assert.strictEqual(await upgradeListeners({ notifications: true }), 1);
    assert.strictEqual(await upgradeListeners({ nostr: true }), 1);
  });

  it('still adds exactly one upgrade listener with every WebSocket feature enabled', async () => {
    const listeners = await upgradeListeners({
      notifications: true, nostr: true, webrtc: true, tunnel: true, terminal: true,
    });
    assert.strictEqual(listeners, 1);
  });
});
