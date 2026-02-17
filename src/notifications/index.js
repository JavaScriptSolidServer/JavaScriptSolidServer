/**
 * Notifications Plugin
 *
 * Fastify plugin that adds WebSocket notification support.
 * Implements the legacy "solid-0.1" protocol for SolidOS compatibility.
 *
 * Usage:
 *   createServer({ notifications: true })
 *
 * Discovery:
 *   OPTIONS /resource returns Updates-Via header with WebSocket URL
 *
 * Client usage:
 *   const ws = new WebSocket(updatesViaUrl);
 *   ws.send('sub http://example.org/resource');
 *   ws.onmessage = (e) => { if (e.data.startsWith('pub ')) ... }
 */

import websocket from '@fastify/websocket';
import fp from 'fastify-plugin';
import { handleWebSocket, getConnectionCount, getSubscriptionCount } from './websocket.js';
import { getWebIdFromRequestAsync } from '../auth/token.js';
export { emitChange } from './events.js';

/**
 * Register the notifications plugin with Fastify
 * @param {FastifyInstance} fastify
 * @param {object} options
 */
export async function notificationsPlugin(fastify, options) {
  const websocketCompat = fp(
    (instance, opts, next) => websocket(instance, opts, next),
    { name: '@fastify/websocket', fastify: '^5.0.0' }
  );
  // Register the WebSocket plugin
  await fastify.register(websocketCompat);

  // WebSocket route for notifications (dedicated path to avoid route conflicts)
  // Clients discover this via Updates-Via header
  fastify.get('/.notifications', { websocket: true }, (socket, request) => {
    const webIdPromise = getWebIdFromRequestAsync(request)
      .then((result) => result.webId)
      .catch(() => null);
    handleWebSocket(socket, request, webIdPromise);
  });

  // Optional: Status endpoint for monitoring
  fastify.get('/.well-known/solid/notifications', async (request, reply) => {
    return {
      connections: getConnectionCount(),
      subscriptions: getSubscriptionCount(),
      protocol: 'solid-0.1'
    };
  });
}

export default notificationsPlugin;
