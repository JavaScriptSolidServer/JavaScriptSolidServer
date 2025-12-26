import Fastify from 'fastify';
import { handleGet, handleHead, handlePut, handleDelete, handleOptions, handlePatch } from './handlers/resource.js';
import { handlePost, handleCreatePod } from './handlers/container.js';
import { getCorsHeaders } from './ldp/headers.js';
import { authorize, handleUnauthorized } from './auth/middleware.js';
import { notificationsPlugin } from './notifications/index.js';

/**
 * Create and configure Fastify server
 * @param {object} options - Server options
 * @param {boolean} options.logger - Enable logging (default true)
 * @param {boolean} options.conneg - Enable content negotiation for RDF (default false)
 * @param {boolean} options.notifications - Enable WebSocket notifications (default false)
 */
export function createServer(options = {}) {
  // Content negotiation is OFF by default - we're a JSON-LD native server
  const connegEnabled = options.conneg ?? false;
  // WebSocket notifications are OFF by default
  const notificationsEnabled = options.notifications ?? false;

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

  // Attach server config to requests
  fastify.decorateRequest('connegEnabled', null);
  fastify.decorateRequest('notificationsEnabled', null);
  fastify.addHook('onRequest', async (request) => {
    request.connegEnabled = connegEnabled;
    request.notificationsEnabled = notificationsEnabled;
  });

  // Register WebSocket notifications plugin if enabled
  if (notificationsEnabled) {
    fastify.register(notificationsPlugin);
  }

  // Global CORS preflight
  fastify.addHook('onRequest', async (request, reply) => {
    // Add CORS headers to all responses
    const corsHeaders = getCorsHeaders(request.headers.origin);
    Object.entries(corsHeaders).forEach(([k, v]) => reply.header(k, v));

    // Add Updates-Via header for WebSocket notification discovery
    if (notificationsEnabled) {
      const wsProtocol = request.protocol === 'https' ? 'wss' : 'ws';
      reply.header('Updates-Via', `${wsProtocol}://${request.hostname}/.notifications`);
    }

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
