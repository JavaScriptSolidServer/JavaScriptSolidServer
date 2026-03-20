/**
 * WebRTC Signaling Server Plugin
 *
 * Lightweight signaling server for WebRTC peer-to-peer connections.
 * Supports two discovery modes:
 *
 * 1. Identity-based — connect to a specific peer by WebID
 * 2. Content-addressed — find peers sharing the same resource hash
 *
 * Relays SDP offers/answers and ICE candidates between peers.
 * The actual media/data flows directly between peers — JSS just introduces them.
 *
 * Usage: jss start --webrtc
 * Endpoint: wss://your.pod/.webrtc
 *
 * Identity-based protocol (JSON over WebSocket):
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
 *
 * Content-addressed protocol (JSON over WebSocket):
 *   → { type: "announce",  resource: "<hash>", offers: [{ sdp: "...", offer_id: "..." }, ...] }
 *   → { type: "answer",    resource: "<hash>", to: "<peer_id>", offer_id: "...", sdp: "..." }
 *   → { type: "leave",     resource: "<hash>" }
 *   ← { type: "offer",     resource: "<hash>", from: "<peer_id>", offer_id: "...", sdp: "..." }
 *   ← { type: "answer",    resource: "<hash>", from: "<peer_id>", offer_id: "...", sdp: "..." }
 *   ← { type: "resource-peers", resource: "<hash>", count: <n> }
 */

import websocket from '@fastify/websocket';
import { getWebIdFromRequestAsync } from '../auth/token.js';

const ALLOWED_TYPES = new Set(['offer', 'answer', 'candidate', 'hangup']);
const MAX_MESSAGE_SIZE = 64 * 1024; // 64KB
const MAX_OFFERS_PER_ANNOUNCE = 10;
const MAX_RESOURCES_PER_PEER = 50;
const RESOURCE_HASH_RE = /^[a-fA-F0-9]{8,128}$/;

/**
 * Register WebRTC signaling routes on Fastify instance
 *
 * @param {object} fastify - Fastify instance
 * @param {object} options - Options
 * @param {string} options.path - WebSocket path (default: '/.webrtc')
 */
export async function webrtcPlugin(fastify, options = {}) {
  const path = options.path || '/.webrtc';

  // Instance-scoped peer state (identity-based)
  const peers = new Map();

  // Instance-scoped resource state (content-addressed)
  // Map<resourceHash, Map<peerId, socket>>
  const resources = new Map();

  // Track which resources each peer has joined
  // Map<peerId, Set<resourceHash>>
  const peerResources = new Map();

  // Peer ID counter for content-addressed mode
  let nextPeerId = 1;

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
    resources.clear();
    peerResources.clear();
  });

  function broadcast(senderWebId, msg) {
    const data = JSON.stringify(msg);
    for (const [id, socket] of peers) {
      if (id !== senderWebId && socket.readyState === 1) {
        try { socket.send(data); } catch { /* socket closed between check and send */ }
      }
    }
  }

  // --- Content-addressed helpers ---

  function getResourcePeers(resourceHash) {
    let group = resources.get(resourceHash);
    if (!group) {
      group = new Map();
      resources.set(resourceHash, group);
    }
    return group;
  }

  function addPeerToResource(peerId, socket, resourceHash) {
    const group = getResourcePeers(resourceHash);
    group.set(peerId, socket);

    let tracked = peerResources.get(peerId);
    if (!tracked) {
      tracked = new Set();
      peerResources.set(peerId, tracked);
    }
    tracked.add(resourceHash);
  }

  function removePeerFromResource(peerId, resourceHash) {
    const group = resources.get(resourceHash);
    if (group) {
      group.delete(peerId);
      if (group.size === 0) resources.delete(resourceHash);
    }
    const tracked = peerResources.get(peerId);
    if (tracked) {
      tracked.delete(resourceHash);
      if (tracked.size === 0) peerResources.delete(peerId);
    }
  }

  function removePeerFromAllResources(peerId) {
    const tracked = peerResources.get(peerId);
    if (!tracked) return;
    for (const hash of tracked) {
      const group = resources.get(hash);
      if (group) {
        group.delete(peerId);
        if (group.size === 0) resources.delete(hash);
      }
    }
    peerResources.delete(peerId);
  }

  function handleAnnounce(socket, peerId, msg) {
    const hash = msg.resource;
    if (!hash || typeof hash !== 'string' || !RESOURCE_HASH_RE.test(hash)) {
      socket.send(JSON.stringify({ type: 'error', message: 'Invalid resource hash' }));
      return;
    }

    // Limit resources per peer
    const tracked = peerResources.get(peerId);
    if (tracked && tracked.size >= MAX_RESOURCES_PER_PEER && !tracked.has(hash)) {
      socket.send(JSON.stringify({ type: 'error', message: 'Too many resources' }));
      return;
    }

    const group = getResourcePeers(hash);
    addPeerToResource(peerId, socket, hash);

    // Relay offers to existing peers in the group
    const offers = Array.isArray(msg.offers) ? msg.offers.slice(0, MAX_OFFERS_PER_ANNOUNCE) : [];
    const existingPeers = [...group.entries()].filter(([id]) => id !== peerId);

    for (let i = 0; i < offers.length && i < existingPeers.length; i++) {
      const offer = offers[i];
      const [targetId, targetSocket] = existingPeers[i];
      if (targetSocket.readyState !== 1) continue;
      if (typeof offer.sdp !== 'string') continue;

      const relay = Object.create(null);
      relay.type = 'offer';
      relay.resource = hash;
      relay.from = peerId;
      relay.offer_id = typeof offer.offer_id === 'string' ? offer.offer_id : String(i);
      relay.sdp = offer.sdp;
      try { targetSocket.send(JSON.stringify(relay)); } catch { /* peer gone */ }
    }

    // Tell the announcer how many peers are in the group
    socket.send(JSON.stringify({
      type: 'resource-peers',
      resource: hash,
      count: group.size - 1
    }));
  }

  function handleResourceAnswer(socket, peerId, msg) {
    const hash = msg.resource;
    if (!hash || typeof hash !== 'string') return;

    const group = resources.get(hash);
    if (!group) return;

    const targetId = msg.to;
    const targetSocket = group.get(targetId);
    if (!targetSocket || targetSocket.readyState !== 1) {
      socket.send(JSON.stringify({ type: 'error', message: 'Peer not in resource group' }));
      return;
    }

    const relay = Object.create(null);
    relay.type = 'answer';
    relay.resource = hash;
    relay.from = peerId;
    if (typeof msg.offer_id === 'string') relay.offer_id = msg.offer_id;
    if (typeof msg.sdp === 'string') relay.sdp = msg.sdp;
    try { targetSocket.send(JSON.stringify(relay)); } catch { /* peer gone */ }
  }

  function handleLeave(socket, peerId, msg) {
    const hash = msg.resource;
    if (!hash || typeof hash !== 'string') return;
    removePeerFromResource(peerId, hash);
  }

  // --- WebSocket handler ---

  fastify.get(path, { websocket: true }, async (connection, request) => {
    const socket = connection.socket;

    // Authenticate the connection
    const { webId } = await getWebIdFromRequestAsync(request);
    if (!webId) {
      socket.send(JSON.stringify({ type: 'error', message: 'Authentication required' }));
      socket.close();
      return;
    }

    // Assign a stable peer ID for content-addressed mode
    const peerId = String(nextPeerId++);
    socket._peerId = peerId;

    // Register this peer (close old connection if reconnecting)
    const existing = peers.get(webId);
    const isReconnect = !!existing;
    if (existing) {
      // Clean up old connection's resource memberships
      if (existing._peerId) removePeerFromAllResources(existing._peerId);
      peers.delete(webId);
      existing.close();
    }
    peers.set(webId, socket);
    socket.webId = webId;

    // Notify the peer of their identity and online peers
    socket.send(JSON.stringify({
      type: 'peers',
      you: webId,
      peerId: peerId,
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

      if (!msg.type) {
        socket.send(JSON.stringify({ type: 'error', message: 'Missing "type" field' }));
        return;
      }

      // Content-addressed messages
      if (msg.type === 'announce') {
        handleAnnounce(socket, peerId, msg);
        return;
      }
      if (msg.type === 'answer' && msg.resource) {
        handleResourceAnswer(socket, peerId, msg);
        return;
      }
      if (msg.type === 'leave') {
        handleLeave(socket, peerId, msg);
        return;
      }

      // Identity-based messages require "to" field
      if (!msg.to) {
        socket.send(JSON.stringify({ type: 'error', message: 'Missing "to" field' }));
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
      try { target.send(JSON.stringify(relay)); } catch {
        socket.send(JSON.stringify({ type: 'error', message: 'Peer not online', peer: msg.to }));
      }
    });

    socket.on('close', () => {
      // Clean up content-addressed resource memberships
      removePeerFromAllResources(peerId);

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
