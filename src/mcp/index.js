/**
 * MCP (Model Context Protocol) plugin.
 *
 * Usage:
 *   createServer({ mcp: true })
 *
 * Endpoint:
 *   POST /mcp  (JSON-RPC 2.0, MCP Streamable HTTP transport)
 *
 * Auth:
 *   Reuses JSS's existing auth chain — Bearer / DPoP / NIP-98 — so
 *   the same WAC rules that gate /public, /private, etc. also gate
 *   tool calls. Anonymous requests get the same WAC treatment as
 *   any other anonymous request.
 *
 * Spec: https://spec.modelcontextprotocol.io/specification/2025-03-26/
 */

import {
  PROTOCOL_VERSION,
  SERVER_INFO,
  RPC_ERRORS,
  rpcResult,
  rpcError
} from './protocol.js';
import { listToolsForRpc, callTool, TOOLS } from './tools.js';
import { getWebIdFromRequestAsync } from '../auth/token.js';

const ALLOWED_METHODS = new Set([
  'initialize',
  'initialized',
  'notifications/initialized',
  'tools/list',
  'tools/call',
  'ping'
]);

function originOf(request) {
  const host = request.headers.host || request.hostname;
  const proto = request.protocol || 'http';
  return `${proto}://${host}`;
}

async function dispatch(msg, ctx) {
  const { id, method, params } = msg;

  if (!ALLOWED_METHODS.has(method)) {
    return rpcError(id, RPC_ERRORS.METHOD_NOT_FOUND, `unknown method: ${method}`);
  }

  if (method === 'ping') {
    return rpcResult(id, {});
  }

  if (method === 'initialize') {
    return rpcResult(id, {
      protocolVersion: PROTOCOL_VERSION,
      serverInfo: SERVER_INFO,
      capabilities: {
        tools: { listChanged: false }
      }
    });
  }

  if (method === 'initialized' || method === 'notifications/initialized') {
    // Notifications carry no id; nothing to return
    return null;
  }

  if (method === 'tools/list') {
    return rpcResult(id, { tools: listToolsForRpc() });
  }

  if (method === 'tools/call') {
    const toolName = params?.name;
    const toolArgs = params?.arguments || {};
    if (!toolName) {
      return rpcError(id, RPC_ERRORS.INVALID_PARAMS, 'tool name required');
    }
    const result = await callTool(toolName, toolArgs, ctx);
    return rpcResult(id, result);
  }

  return rpcError(id, RPC_ERRORS.METHOD_NOT_FOUND, `unhandled method: ${method}`);
}

function isStreamingToolCall(body) {
  return body
    && body.method === 'tools/call'
    && body.params?.name
    && TOOLS[body.params.name]
    // Sniff: invoke the handler synchronously so we can detect the
    // `{ stream: true, init, run }` shape. Streaming tools must be
    // pure-synchronous in their shape-decision (no awaits before
    // returning the stream descriptor).
    && (() => {
      try {
        // We can't safely call the handler without a ctx, so we just
        // rely on the tool name being in our streaming-tools set.
        return STREAMING_TOOLS.has(body.params.name);
      } catch { return false; }
    })();
}

const STREAMING_TOOLS = new Set(['subscribe']);

async function handleStreamingTool(request, reply, body, ctx) {
  const tool = TOOLS[body.params.name];
  let descriptor;
  try {
    descriptor = tool.handler(body.params.arguments || {}, ctx);
  } catch (e) {
    reply.code(500);
    reply.header('Content-Type', 'application/json');
    return rpcError(body.id, RPC_ERRORS.INTERNAL_ERROR, e.message);
  }
  if (!descriptor || descriptor.stream !== true) {
    // Tool decided not to stream after all — emit single-shot response
    reply.header('Content-Type', 'application/json');
    return rpcResult(body.id, descriptor);
  }

  // Switch to SSE
  reply.raw.writeHead(200, {
    'Content-Type': 'text/event-stream',
    'Cache-Control': 'no-cache, no-transform',
    'Connection': 'keep-alive',
    'X-Accel-Buffering': 'no'
  });

  const controller = new AbortController();
  request.raw.on('close', () => controller.abort());

  const sendEvent = (payload) => {
    if (controller.signal.aborted) return;
    const note = {
      jsonrpc: '2.0',
      method: 'notifications/tool_event',
      params: { tool: body.params.name, event: payload }
    };
    reply.raw.write(`event: notification\ndata: ${JSON.stringify(note)}\n\n`);
  };

  try {
    const initial = await descriptor.init();
    if (initial) sendEvent(initial);
    await descriptor.run(sendEvent, controller.signal);
  } catch (e) {
    sendEvent({ type: 'error', message: e.message });
  } finally {
    if (!controller.signal.aborted) reply.raw.end();
  }
  return reply;
}

/**
 * Register the MCP plugin with Fastify.
 */
export async function mcpPlugin(fastify, _options) {
  fastify.post('/mcp', async (request, reply) => {
    const body = request.body;
    if (!body || typeof body !== 'object') {
      reply.code(400);
      return rpcError(null, RPC_ERRORS.INVALID_REQUEST, 'expected JSON-RPC body');
    }

    // Identity for tool calls — pulled from the inbound auth on /mcp itself.
    // null webId means "anonymous"; WAC will treat it accordingly.
    const { webId } = await getWebIdFromRequestAsync(request).catch(() => ({ webId: null }));

    // Federation depth (used by call_remote_pod to enforce the cap)
    const depthHdr = request.headers['mcp-federation-depth'];
    const federationDepth = depthHdr ? parseInt(depthHdr, 10) || 0 : 0;

    const ctx = {
      webId: webId || null,
      origin: originOf(request),
      federationDepth
    };

    // Streaming tool? Hand off to SSE handler.
    if (!Array.isArray(body) && isStreamingToolCall(body)) {
      return handleStreamingTool(request, reply, body, ctx);
    }

    // Batch support (array of requests)
    if (Array.isArray(body)) {
      const out = [];
      for (const msg of body) {
        const r = await dispatch(msg, ctx);
        if (r) out.push(r);
      }
      reply.header('Content-Type', 'application/json');
      return out;
    }

    const result = await dispatch(body, ctx);
    if (result === null) {
      // Notification (no response body)
      reply.code(204);
      return null;
    }
    reply.header('Content-Type', 'application/json');
    return result;
  });

  fastify.options('/mcp', async (_request, reply) => {
    reply.header('Allow', 'POST, OPTIONS');
    reply.code(204);
    return null;
  });
}
