/**
 * WebRTC Signaling Server Plugin
 *
 * Lightweight signaling server for WebRTC peer-to-peer connections.
 * Relays SDP offers/answers and ICE candidates between authenticated users.
 * The actual media/data flow directly between peers — JSS just introduces them.
 *
 * Usage: jss start --webrtc
 * Endpoint: wss://your.pod/.webrtc
 *
 * Protocol (JSON over WebSocket):
 *   → { type: "offer",     to: "<webid>", sdp: "..." }
 *   → { type: "answer",    to: "<webid>", sdp: "..." }
 *   → { type: "candidate", to: "<webid>", candidate: {...} }
 *   → { type: "hangup",    to: "<webid>" }
 *   ← { type: "offer",     from: "<webid>", sdp: "..." }
 *   ← { type: "answer",    from: "<webid>", sdp: "..." }
 *   ← { type: "candidate", from: "<webid>", candidate: {...} }
 *   ← { type: "hangup",    from: "<webid>" }
 *   ← { type: "error",     message: "..." }
 *   ← { type: "peers",     you: "<webid>", peers: ["<webid>", ...] }
 *   ← { type: "peer-joined", webId: "<webid>" }
 *   ← { type: "peer-left",   webId: "<webid>" }
 */

import websocket from '@fastify/websocket';
import { getWebIdFromRequestAsync } from '../auth/token.js';

const ALLOWED_TYPES = new Set(['offer', 'answer', 'candidate', 'hangup']);
const MAX_MESSAGE_SIZE = 64 * 1024; // 64KB

/**
 * Register WebRTC signaling routes on Fastify instance
 *
 * @param {object} fastify - Fastify instance
 * @param {object} options - Options
 * @param {string} options.path - WebSocket path (default: '/.webrtc')
 */
export async function webrtcPlugin(fastify, options = {}) {
  const path = options.path || '/.webrtc';

  // Instance-scoped peer state
  const peers = new Map();

  // Only register @fastify/websocket if not already registered
  if (!fastify.websocketServer) {
    await fastify.register(websocket);
  }

  // Clean up all connections on server close
  fastify.addHook('onClose', async () => {
    for (const [, socket] of peers) {
      socket.close();
    }
    peers.clear();
  });

  function broadcast(senderWebId, msg) {
    const data = JSON.stringify(msg);
    for (const [id, socket] of peers) {
      if (id !== senderWebId && socket.readyState === 1) {
        socket.send(data);
      }
    }
  }

  fastify.get(path, { websocket: true }, async (connection, request) => {
    const socket = connection.socket;

    // Authenticate the connection
    const { webId } = await getWebIdFromRequestAsync(request);
    if (!webId) {
      socket.send(JSON.stringify({ type: 'error', message: 'Authentication required' }));
      socket.close();
      return;
    }

    // Register this peer (close old connection if reconnecting)
    const existing = peers.get(webId);
    const isReconnect = !!existing;
    if (existing) {
      peers.delete(webId);
      existing.close();
    }
    peers.set(webId, socket);
    socket.webId = webId;

    // Notify the peer of their identity and online peers
    socket.send(JSON.stringify({
      type: 'peers',
      you: webId,
      peers: [...peers.keys()].filter(id => id !== webId)
    }));

    // Only broadcast peer-joined for new connections, not reconnects
    if (!isReconnect) {
      broadcast(webId, { type: 'peer-joined', webId });
    }

    socket.on('message', (data) => {
      // Enforce max message size (Buffer.byteLength for reliable byte count)
      const raw = Buffer.isBuffer(data) ? data : Buffer.from(data);
      if (raw.byteLength > MAX_MESSAGE_SIZE) {
        socket.send(JSON.stringify({ type: 'error', message: 'Message too large' }));
        return;
      }

      let msg;
      try {
        msg = JSON.parse(raw.toString());
      } catch {
        socket.send(JSON.stringify({ type: 'error', message: 'Invalid JSON' }));
        return;
      }

      if (!msg.to || !msg.type) {
        socket.send(JSON.stringify({ type: 'error', message: 'Missing "to" or "type" field' }));
        return;
      }

      // Only relay known signaling types
      if (!ALLOWED_TYPES.has(msg.type)) {
        socket.send(JSON.stringify({ type: 'error', message: `Unknown type "${msg.type}"` }));
        return;
      }

      const target = peers.get(msg.to);
      if (!target || target.readyState !== 1) {
        socket.send(JSON.stringify({ type: 'error', message: 'Peer not online', peer: msg.to }));
        return;
      }

      // Build relay payload with whitelisted fields only (prevent prototype pollution)
      const relay = Object.create(null);
      relay.type = msg.type;
      relay.from = webId;
      if (typeof msg.sdp === 'string') relay.sdp = msg.sdp;
      if (msg.candidate != null && typeof msg.candidate === 'object' && !Array.isArray(msg.candidate)) {
        relay.candidate = msg.candidate;
      }
      target.send(JSON.stringify(relay));
    });

    socket.on('close', () => {
      // Only remove if this socket is still the registered one (not replaced by reconnect)
      if (peers.get(webId) === socket) {
        peers.delete(webId);
        broadcast(webId, { type: 'peer-left', webId });
      }
    });

    // Error handler: close event will follow and handle cleanup
    socket.on('error', () => {});
  });
}

export default webrtcPlugin;
