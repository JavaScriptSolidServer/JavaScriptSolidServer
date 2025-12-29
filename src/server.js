import Fastify from 'fastify';
import { readFile } from 'fs/promises';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import { handleGet, handleHead, handlePut, handleDelete, handleOptions, handlePatch } from './handlers/resource.js';
import { handlePost, handleCreatePod } from './handlers/container.js';
import { getCorsHeaders } from './ldp/headers.js';
import { authorize, handleUnauthorized } from './auth/middleware.js';
import { notificationsPlugin } from './notifications/index.js';
import { idpPlugin } from './idp/index.js';

const __dirname = dirname(fileURLToPath(import.meta.url));

/**
 * Create and configure Fastify server
 * @param {object} options - Server options
 * @param {boolean} options.logger - Enable logging (default true)
 * @param {boolean} options.conneg - Enable content negotiation for RDF (default false)
 * @param {boolean} options.notifications - Enable WebSocket notifications (default false)
 * @param {boolean} options.idp - Enable built-in Identity Provider (default false)
 * @param {string} options.idpIssuer - IdP issuer URL (default: server URL)
 * @param {object} options.ssl - SSL configuration { key, cert } (default null)
 * @param {string} options.root - Data directory path (default from env or ./data)
 * @param {boolean} options.subdomains - Enable subdomain-based pods for XSS protection (default false)
 * @param {string} options.baseDomain - Base domain for subdomain pods (e.g., "example.com")
 */
export function createServer(options = {}) {
  // Content negotiation is OFF by default - we're a JSON-LD native server
  const connegEnabled = options.conneg ?? false;
  // WebSocket notifications are OFF by default
  const notificationsEnabled = options.notifications ?? false;
  // Identity Provider is OFF by default
  const idpEnabled = options.idp ?? false;
  const idpIssuer = options.idpIssuer;
  // Subdomain mode is OFF by default - use path-based pods
  const subdomainsEnabled = options.subdomains ?? false;
  const baseDomain = options.baseDomain || null;
  // Mashlib data browser is OFF by default
  // mashlibCdn: if true, load from CDN; if false, serve locally
  const mashlibEnabled = options.mashlib ?? false;
  const mashlibCdn = options.mashlibCdn ?? false;
  const mashlibVersion = options.mashlibVersion ?? '2.0.0';

  // Set data root via environment variable if provided
  if (options.root) {
    process.env.DATA_ROOT = options.root;
  }

  // Fastify options
  const fastifyOptions = {
    logger: options.logger ?? true,
    trustProxy: true,
    // Handle raw body for non-JSON content
    bodyLimit: 10 * 1024 * 1024 // 10MB
  };

  // Add HTTPS support if SSL config provided
  if (options.ssl && options.ssl.key && options.ssl.cert) {
    fastifyOptions.https = {
      key: options.ssl.key,
      cert: options.ssl.cert,
    };
  }

  const fastify = Fastify(fastifyOptions);

  // Add raw body parser for all content types
  fastify.addContentTypeParser('*', { parseAs: 'buffer' }, (req, body, done) => {
    done(null, body);
  });

  // Attach server config to requests
  fastify.decorateRequest('connegEnabled', null);
  fastify.decorateRequest('notificationsEnabled', null);
  fastify.decorateRequest('idpEnabled', null);
  fastify.decorateRequest('subdomainsEnabled', null);
  fastify.decorateRequest('baseDomain', null);
  fastify.decorateRequest('podName', null);
  fastify.decorateRequest('mashlibEnabled', null);
  fastify.decorateRequest('mashlibCdn', null);
  fastify.decorateRequest('mashlibVersion', null);
  fastify.addHook('onRequest', async (request) => {
    request.connegEnabled = connegEnabled;
    request.notificationsEnabled = notificationsEnabled;
    request.idpEnabled = idpEnabled;
    request.subdomainsEnabled = subdomainsEnabled;
    request.baseDomain = baseDomain;
    request.mashlibEnabled = mashlibEnabled;
    request.mashlibCdn = mashlibCdn;
    request.mashlibVersion = mashlibVersion;

    // Extract pod name from subdomain if enabled
    if (subdomainsEnabled && baseDomain) {
      const host = request.hostname;
      // Check if host is a subdomain of baseDomain
      if (host !== baseDomain && host.endsWith('.' + baseDomain)) {
        // Extract subdomain (e.g., "alice.example.com" -> "alice")
        const subdomain = host.slice(0, -(baseDomain.length + 1));
        // Only single-level subdomains (no dots)
        if (!subdomain.includes('.')) {
          request.podName = subdomain;
        }
      }
    }
  });

  // Register WebSocket notifications plugin if enabled
  if (notificationsEnabled) {
    fastify.register(notificationsPlugin);
  }

  // Register Identity Provider plugin if enabled
  if (idpEnabled) {
    fastify.register(idpPlugin, { issuer: idpIssuer });
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
    // Note: OPTIONS requests are handled by handleOptions to include Accept-* headers
  });

  // Authorization hook - check WAC permissions
  // Skip for pod creation endpoint (needs special handling)
  fastify.addHook('preHandler', async (request, reply) => {
    // Skip auth for pod creation, OPTIONS, IdP routes, mashlib, and well-known endpoints
    const mashlibPaths = ['/mashlib.min.js', '/mash.css', '/841.mashlib.min.js'];
    if (request.url === '/.pods' ||
        request.method === 'OPTIONS' ||
        request.url.startsWith('/idp/') ||
        request.url.startsWith('/.well-known/') ||
        mashlibPaths.some(p => request.url === p || request.url.startsWith(p + '.'))) {
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

  // Mashlib static files (served from root like NSS does)
  if (mashlibEnabled) {
    const mashlibDir = join(__dirname, 'mashlib-local', 'dist');
    const mashlibFiles = {
      '/mashlib.min.js': { file: 'mashlib.min.js', type: 'application/javascript' },
      '/mashlib.min.js.map': { file: 'mashlib.min.js.map', type: 'application/json' },
      '/mash.css': { file: 'mash.css', type: 'text/css' },
      '/mash.css.map': { file: 'mash.css.map', type: 'application/json' },
      '/841.mashlib.min.js': { file: '841.mashlib.min.js', type: 'application/javascript' },
      '/841.mashlib.min.js.map': { file: '841.mashlib.min.js.map', type: 'application/json' }
    };

    for (const [path, config] of Object.entries(mashlibFiles)) {
      fastify.get(path, async (request, reply) => {
        try {
          const content = await readFile(join(mashlibDir, config.file));
          return reply.type(config.type).send(content);
        } catch {
          return reply.code(404).send({ error: 'Not Found' });
        }
      });
    }
  }

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
