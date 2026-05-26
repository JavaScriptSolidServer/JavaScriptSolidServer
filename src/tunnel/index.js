/**
 * Tunnel Plugin — Decentralized ngrok
 *
 * Tunnels HTTP traffic to a local dev server through JSS via WebSocket.
 * A tunnel client connects over WebSocket, registers a name, and receives
 * proxied HTTP requests which it forwards to localhost.
 *
 * Usage: jss start --tunnel
 * Tunnel client connects to: wss://your.pod/.tunnel
 * Public URL: https://your.pod/tunnel/{name}/path
 *
 * Tunnel client protocol (JSON over WebSocket):
 *   → { type: "register", name: "myapp" }
 *   ← { type: "registered", name: "myapp", url: "/tunnel/myapp/" }
 *   ← { type: "request", id: "<uuid>", method: "GET", path: "/api/hello", headers: {...}, body: "..." }
 *   → { type: "response", id: "<uuid>", status: 200, headers: {...}, body: "..." }
 *   ← { type: "error", message: "..." }
 */

import websocket from '@fastify/websocket';
import { getWebIdFromRequestAsync } from '../auth/token.js';
import { randomUUID } from 'crypto';

const REQUEST_TIMEOUT = 30000; // 30s timeout for tunnel responses
const MAX_MESSAGE_SIZE = 10 * 1024 * 1024; // 10MB

/**
 * @param {object} fastify - Fastify instance
 * @param {object} options - Options
 * @param {string} options.path - WebSocket path for tunnel clients (default: '/.tunnel')
 */
export async function tunnelPlugin(fastify, options = {}) {
  const wsPath = options.path || '/.tunnel';

  // Instance-scoped: tunnel name → { socket, webId }
  const tunnels = new Map();
  // Pending HTTP requests waiting for tunnel response: id → { resolve, timer }
  const pending = new Map();

  if (!fastify.websocketServer) {
    await fastify.register(websocket);
  }

  fastify.addHook('onClose', async () => {
    for (const [, tunnel] of tunnels) {
      tunnel.socket.close();
    }
    tunnels.clear();
    for (const [, p] of pending) {
      clearTimeout(p.timer);
      p.resolve({ status: 502, headers: {}, body: 'Tunnel shutting down' });
    }
    pending.clear();
  });

  // WebSocket endpoint for tunnel clients
  fastify.get(wsPath, { websocket: true }, async (connection, request) => {
    const socket = connection.socket;

    // Browser WebSockets can't set an Authorization header, so accept the
    // bearer token as a ?token= query param too — mirrors the /.webrtc
    // endpoint. Lets browser-based tunnel clients authenticate. (#528)
    const queryToken = request.query?.token;
    if (queryToken && !request.headers.authorization) {
      request.headers.authorization = `Bearer ${queryToken}`;
    }

    // Authenticate
    const { webId } = await getWebIdFromRequestAsync(request);
    if (!webId) {
      socket.send(JSON.stringify({ type: 'error', message: 'Authentication required' }));
      socket.close();
      return;
    }

    let tunnelName = null;

    socket.on('message', (data) => {
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

      if (msg.type === 'register') {
        // Register a tunnel name
        const name = (msg.name || '').replace(/[^a-zA-Z0-9_-]/g, '');
        if (!name) {
          socket.send(JSON.stringify({ type: 'error', message: 'Invalid tunnel name' }));
          return;
        }

        const existing = tunnels.get(name);
        if (existing && existing.webId !== webId) {
          socket.send(JSON.stringify({ type: 'error', message: 'Tunnel name taken by another user' }));
          return;
        }

        // Close old tunnel with same name from same user
        if (existing) {
          existing.socket.close();
        }

        tunnelName = name;
        tunnels.set(name, { socket, webId });
        socket.send(JSON.stringify({ type: 'registered', name, url: `/tunnel/${name}/` }));

      } else if (msg.type === 'response') {
        // Tunnel client returning an HTTP response
        if (!msg.id) return;
        const p = pending.get(msg.id);
        if (p) {
          clearTimeout(p.timer);
          pending.delete(msg.id);
          p.resolve({
            status: msg.status || 502,
            headers: msg.headers || {},
            body: msg.body || '',
            bodyEncoding: msg.bodyEncoding
          });
        }
      }
    });

    socket.on('close', () => {
      if (tunnelName && tunnels.get(tunnelName)?.socket === socket) {
        tunnels.delete(tunnelName);
        // Resolve pending requests for this tunnel only with 502
        for (const [id, p] of pending) {
          if (p.tunnelName === tunnelName) {
            clearTimeout(p.timer);
            pending.delete(id);
            p.resolve({ status: 502, headers: {}, body: 'Tunnel disconnected' });
          }
        }
      }
    });

    socket.on('error', () => {});
  });

  // HTTP proxy: /tunnel/{name}/*
  fastify.all('/tunnel/:name/*', async (request, reply) => {
    const { name } = request.params;
    const tunnel = tunnels.get(name);

    if (!tunnel || tunnel.socket.readyState !== 1) {
      return reply.code(502).send({ error: 'Bad Gateway', message: 'Tunnel not connected' });
    }

    // Build the downstream path (strip /tunnel/{name} prefix)
    const fullPath = request.url.replace(`/tunnel/${name}`, '') || '/';
    const id = randomUUID();

    // Serialize the HTTP request
    const tunnelReq = Object.create(null);
    tunnelReq.type = 'request';
    tunnelReq.id = id;
    tunnelReq.method = request.method;
    tunnelReq.path = fullPath;
    tunnelReq.headers = Object.create(null);
    // Forward relevant headers (skip hop-by-hop)
    const skipHeaders = new Set(['host', 'connection', 'upgrade', 'transfer-encoding', 'cookie', 'authorization', 'proxy-authorization']);
    for (const [k, v] of Object.entries(request.headers)) {
      if (!skipHeaders.has(k.toLowerCase())) {
        tunnelReq.headers[k] = v;
      }
    }
    // Forward body if present
    if (request.body) {
      tunnelReq.body = Buffer.isBuffer(request.body)
        ? request.body.toString('base64')
        : typeof request.body === 'string' ? request.body : JSON.stringify(request.body);
      tunnelReq.bodyEncoding = Buffer.isBuffer(request.body) ? 'base64' : 'utf8';
    }

    // Send to tunnel client and wait for response
    const responsePromise = new Promise((resolve) => {
      const timer = setTimeout(() => {
        pending.delete(id);
        resolve({ status: 504, headers: {}, body: 'Gateway Timeout' });
      }, REQUEST_TIMEOUT);
      pending.set(id, { resolve, timer, tunnelName: name });
    });

    try {
      tunnel.socket.send(JSON.stringify(tunnelReq));
    } catch {
      const p = pending.get(id);
      if (p) { clearTimeout(p.timer); pending.delete(id); }
      return reply.code(502).send({ error: 'Bad Gateway', message: 'Failed to reach tunnel client' });
    }

    const res = await responsePromise;

    // Set response headers
    const hopHeaders = new Set(['connection', 'transfer-encoding', 'keep-alive', 'set-cookie']);
    for (const [k, v] of Object.entries(res.headers)) {
      if (!hopHeaders.has(k.toLowerCase())) {
        reply.header(k, v);
      }
    }

    // Decode body if base64
    const body = res.bodyEncoding === 'base64' && res.body
      ? Buffer.from(res.body, 'base64')
      : res.body || '';

    return reply.code(res.status).send(body);
  });

  // Also handle /tunnel/{name} without trailing path
  fastify.all('/tunnel/:name', async (request, reply) => {
    // Redirect to add trailing slash, or proxy as root
    const { name } = request.params;
    const tunnel = tunnels.get(name);

    if (!tunnel || tunnel.socket.readyState !== 1) {
      return reply.code(502).send({ error: 'Bad Gateway', message: 'Tunnel not connected' });
    }

    return reply.redirect(308, `/tunnel/${name}/`);
  });
}

export default tunnelPlugin;
