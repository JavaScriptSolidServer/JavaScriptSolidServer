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
import { listToolsForRpc, callTool } from './tools.js';
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

    const ctx = {
      webId: webId || null,
      origin: originOf(request)
    };

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
