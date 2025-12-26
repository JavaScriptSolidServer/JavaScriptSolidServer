import Fastify from 'fastify';
import { handleGet, handleHead, handlePut, handleDelete, handleOptions } from './handlers/resource.js';
import { handlePost, handleCreatePod } from './handlers/container.js';
import { getCorsHeaders } from './ldp/headers.js';

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

    // Handle preflight
    if (request.method === 'OPTIONS') {
      reply.code(204).send();
      return reply;
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
