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
import { handleWebSocket, getConnectionCount, getSubscriptionCount } from './websocket.js';
import { getWebIdFromRequestAsync } from '../auth/token.js';
export { emitChange } from './events.js';

/**
 * Register the notifications plugin with Fastify
 * @param {FastifyInstance} fastify
 * @param {object} options
 */
export async function notificationsPlugin(fastify, options) {
  // Register the WebSocket plugin
  await fastify.register(websocket);

  // WebSocket route for notifications (dedicated path to avoid route conflicts)
  // Clients discover this via Updates-Via header
  // In @fastify/websocket v8, handler receives (connection, request) where connection.socket is the raw WebSocket
  fastify.get('/.notifications', { websocket: true }, async (connection, request) => {
    // Get WebID from auth token (if present) for ACL checking on subscriptions
    const { webId } = await getWebIdFromRequestAsync(request);
    handleWebSocket(connection.socket, request, webId);
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
