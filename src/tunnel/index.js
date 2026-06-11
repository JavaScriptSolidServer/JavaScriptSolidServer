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
 *   → { type: "register", name: "myapp", passthrough?: true }
 *   ← { type: "registered", name: "myapp", url: "/tunnel/myapp/", passthrough: true|false }
 *   ← { type: "request", id: "<uuid>", method: "GET", path: "/api/hello", headers: {...}, body: "..." }
 *   → { type: "response", id: "<uuid>", status: 200, headers: {...}, body: "..." }
 *   ← { type: "error", message: "..." }
 *
 * Credential passthrough (#530): by default the proxy strips
 * `Cookie` / `Authorization` from inbound requests and `Set-Cookie`
 * from outbound responses, so a tunnel exposes PUBLIC content only.
 * A client may opt in per-registration with `passthrough: true`,
 * which forwards those three headers and makes authenticated access
 * (bearer/DPoP, cookie sessions) work through the tunnel. Opting in
 * means visitor credentials bound for the tunnelled service are
 * handed to the registered client — safe exactly when the registrant
 * owns the tunnelled service (the normal "my own pod through my own
 * relay" case), which is why it is per-tunnel, owner-asserted, and
 * off by default. `Proxy-Authorization` is always stripped — it is
 * addressed to this relay, never to the tunnelled service.
 *
 * Even with passthrough on, the relay's OWN IdP session/interaction
 * cookies are stripped from the forwarded Cookie header. oidc-provider
 * sets them with `path: '/'`, so a browser attaches them to
 * `/tunnel/...` requests too — but they authenticate the visitor to
 * THE RELAY, not to the tunnelled service. Forwarding them would let a
 * tunnel client capture a visitor's relay `_session` and replay it
 * against the relay's `/idp/*` endpoints (session hijack). See #530.
 */

// Cookie names reserved by the relay's own oidc-provider IdP
// (`_session`, `_session.sig`, `_session.legacy[.sig]`, `_interaction`,
// `_interaction.sig`, `_interaction_resume[.sig]`). They share two
// prefixes; we match the prefix plus a `.`/`_` boundary so a tunnelled
// service's unrelated cookie (e.g. `_sessionsLeft`) isn't stripped.
const RELAY_COOKIE_PREFIXES = ['_session', '_interaction'];

function isRelayCookieName(name) {
  return RELAY_COOKIE_PREFIXES.some(
    (p) => name === p || name.startsWith(`${p}.`) || name.startsWith(`${p}_`),
  );
}

/**
 * Remove the relay's own IdP cookies from a forwarded Cookie header,
 * keeping the visitor's cookies bound for the tunnelled service.
 * Returns '' when nothing remains (caller then drops the header).
 */
function stripRelayCookies(cookieHeader) {
  if (typeof cookieHeader !== 'string') return '';
  return cookieHeader
    .split(';')
    .map((s) => s.trim())
    .filter(Boolean)
    .filter((pair) => {
      const eq = pair.indexOf('=');
      const name = (eq === -1 ? pair : pair.slice(0, eq)).trim();
      return !isRelayCookieName(name);
    })
    .join('; ');
}

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

        // Per-tunnel credential passthrough (#530) — strict boolean so a
        // truthy-but-wrong value ("false", 1) can't silently enable
        // credential forwarding. Echoed in the ack so the client knows
        // which mode the relay actually applied.
        const passthrough = msg.passthrough === true;

        tunnelName = name;
        tunnels.set(name, { socket, webId, passthrough });
        socket.send(JSON.stringify({ type: 'registered', name, url: `/tunnel/${name}/`, passthrough }));

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
    // Forward relevant headers. Hop-by-hop headers are always skipped;
    // credentials (cookie / authorization) are skipped UNLESS the tunnel
    // registered with passthrough (#530 — owner opted in to receive
    // visitor credentials). Proxy-Authorization is always stripped: it
    // is addressed to this relay, never to the tunnelled service.
    const skipHeaders = new Set(['host', 'connection', 'upgrade', 'transfer-encoding', 'proxy-authorization']);
    if (!tunnel.passthrough) {
      skipHeaders.add('cookie');
      skipHeaders.add('authorization');
    }
    for (const [k, v] of Object.entries(request.headers)) {
      const lower = k.toLowerCase();
      if (skipHeaders.has(lower)) continue;
      if (lower === 'cookie' && tunnel.passthrough) {
        // Forward the visitor's cookies for the tunnelled service, but
        // never the relay's own IdP session cookies (#530 security).
        const filtered = stripRelayCookies(v);
        if (filtered) tunnelReq.headers[k] = filtered;
        continue;
      }
      tunnelReq.headers[k] = v;
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

    // Set response headers. Set-Cookie is stripped by default so a
    // tunnelled service can't set cookies on the relay's origin; with
    // passthrough (#530) the owner opted in and session flows (e.g.
    // OIDC login cookies) must survive the proxy. Fastify accepts an
    // array value for set-cookie, which JSON serialization preserves.
    const hopHeaders = new Set(['connection', 'transfer-encoding', 'keep-alive']);
    if (!tunnel.passthrough) {
      hopHeaders.add('set-cookie');
    }
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
