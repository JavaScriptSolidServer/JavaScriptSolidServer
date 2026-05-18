/**
 * MCP (Model Context Protocol) protocol envelope.
 *
 * Implements the Streamable HTTP transport for MCP 2025-03-26.
 * Single endpoint (POST /mcp). Client sends JSON-RPC 2.0 requests.
 * Server responds with JSON-RPC 2.0 responses (single-shot JSON for now;
 * SSE streaming can be added later for subscribe-style tools).
 *
 * Spec: https://spec.modelcontextprotocol.io/specification/2025-03-26/
 */

export const PROTOCOL_VERSION = '2025-03-26';

export const SERVER_INFO = {
  name: 'jss-mcp',
  version: '0.1.0'
};

// JSON-RPC error codes
export const RPC_ERRORS = {
  PARSE_ERROR: -32700,
  INVALID_REQUEST: -32600,
  METHOD_NOT_FOUND: -32601,
  INVALID_PARAMS: -32602,
  INTERNAL_ERROR: -32603,
  // MCP-specific
  TOOL_ERROR: -32000,
  AUTH_REQUIRED: -32001,
  ACCESS_DENIED: -32002
};

export function rpcResult(id, result) {
  return { jsonrpc: '2.0', id, result };
}

export function rpcError(id, code, message, data) {
  const err = { code, message };
  if (data !== undefined) err.data = data;
  return { jsonrpc: '2.0', id, error: err };
}

export function toolText(text) {
  return { content: [{ type: 'text', text }], isError: false };
}

export function toolError(message) {
  return { content: [{ type: 'text', text: message }], isError: true };
}

export function toolJson(value) {
  return toolText(JSON.stringify(value, null, 2));
}
