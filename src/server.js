import Fastify from 'fastify';
import { handleGet, handleHead, handlePut, handleDelete, handleOptions, handlePatch } from './handlers/resource.js';
import { handlePost, handleCreatePod } from './handlers/container.js';
import { getCorsHeaders } from './ldp/headers.js';
import { authorize, handleUnauthorized } from './auth/middleware.js';

/**
 * Create and configure Fastify server
 */
export function createServer(options = {}) {
  const fastify = Fastify({
    logger: options.logger ?? true,
    trustProxy: true,
    // Handle raw body for non-JSON content
    bodyLimit: 10 * 1024 * 1024 // 10MB
  });

  // Add raw body parser for all content types
  fastify.addContentTypeParser('*', { parseAs: 'buffer' }, (req, body, done) => {
    done(null, body);
  });

  // Global CORS preflight
  fastify.addHook('onRequest', async (request, reply) => {
    // Add CORS headers to all responses
    const corsHeaders = getCorsHeaders(request.headers.origin);
    Object.entries(corsHeaders).forEach(([k, v]) => reply.header(k, v));

    // Handle preflight OPTIONS
    if (request.method === 'OPTIONS') {
      // Add Allow header for LDP compliance
      reply.header('Allow', 'GET, HEAD, POST, PUT, DELETE, PATCH, OPTIONS');
      reply.code(204).send();
      return reply;
    }
  });

  // Authorization hook - check WAC permissions
  // Skip for pod creation endpoint (needs special handling)
  fastify.addHook('preHandler', async (request, reply) => {
    // Skip auth for pod creation and OPTIONS
    if (request.url === '/.pods' || request.method === 'OPTIONS') {
      return;
    }

    const { authorized, webId, wacAllow, authError } = await authorize(request, reply);

    // Store webId and wacAllow on request for handlers to use
    request.webId = webId;
    request.wacAllow = wacAllow;

    if (!authorized) {
      return handleUnauthorized(reply, webId !== null, wacAllow, authError);
    }
  });

  // Pod creation endpoint
  fastify.post('/.pods', handleCreatePod);

  // LDP routes - using wildcard routing
  fastify.get('/*', handleGet);
  fastify.head('/*', handleHead);
  fastify.put('/*', handlePut);
  fastify.delete('/*', handleDelete);
  fastify.post('/*', handlePost);
  fastify.patch('/*', handlePatch);
  fastify.options('/*', handleOptions);

  // Root route
  fastify.get('/', handleGet);
  fastify.head('/', handleHead);
  fastify.options('/', handleOptions);
  fastify.post('/', handlePost);

  return fastify;
}

/**
 * Start the server
 */
export async function startServer(port = 3000, host = '0.0.0.0') {
  const server = createServer();

  try {
    await server.listen({ port, host });
    return server;
  } catch (err) {
    server.log.error(err);
    process.exit(1);
  }
}
