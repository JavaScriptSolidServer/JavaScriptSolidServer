/**
 * WebRTC Signaling Server Plugin
 *
 * Lightweight signaling server for WebRTC peer-to-peer connections.
 * Relays SDP offers/answers and ICE candidates between authenticated users.
 * The actual media/data flows directly between peers — JSS just introduces them.
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
 *   ← { type: "peers",     peers: ["<webid>", ...] }
 */

import websocket from '@fastify/websocket';
import { getWebIdFromRequestAsync } from '../auth/token.js';

// Connected peers: webId → WebSocket
const peers = new Map();

/**
 * Register WebRTC signaling routes on Fastify instance
 *
 * @param {object} fastify - Fastify instance
 * @param {object} options - Options
 * @param {string} options.path - WebSocket path (default: '/.webrtc')
 */
export async function webrtcPlugin(fastify, options = {}) {
  const path = options.path || '/.webrtc';

  await fastify.register(websocket);

  fastify.get(path, { websocket: true }, async (connection, request) => {
    const socket = connection.socket;

    // Authenticate the connection
    const { webId } = await getWebIdFromRequestAsync(request);
    if (!webId) {
      socket.send(JSON.stringify({ type: 'error', message: 'Authentication required' }));
      socket.close();
      return;
    }

    // Register this peer
    const existing = peers.get(webId);
    if (existing) {
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

    // Notify other peers that someone came online
    broadcast(webId, { type: 'peer-joined', webId });

    socket.on('message', (data) => {
      let msg;
      try {
        msg = JSON.parse(data.toString());
      } catch {
        socket.send(JSON.stringify({ type: 'error', message: 'Invalid JSON' }));
        return;
      }

      if (!msg.to || !msg.type) {
        socket.send(JSON.stringify({ type: 'error', message: 'Missing "to" or "type" field' }));
        return;
      }

      const target = peers.get(msg.to);
      if (!target || target.readyState !== 1) {
        socket.send(JSON.stringify({ type: 'error', message: 'Peer not online', peer: msg.to }));
        return;
      }

      // Relay the message, replacing 'to' with 'from'
      const relay = { ...msg, from: webId };
      delete relay.to;
      target.send(JSON.stringify(relay));
    });

    socket.on('close', () => {
      peers.delete(webId);
      broadcast(webId, { type: 'peer-left', webId });
    });

    socket.on('error', () => {
      peers.delete(webId);
    });
  });
}

/**
 * Send a message to all connected peers except the sender
 */
function broadcast(senderWebId, msg) {
  const data = JSON.stringify(msg);
  for (const [id, socket] of peers) {
    if (id !== senderWebId && socket.readyState === 1) {
      socket.send(data);
    }
  }
}

export default webrtcPlugin;
