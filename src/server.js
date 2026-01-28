import Fastify from 'fastify';
import rateLimit from '@fastify/rate-limit';
import { readFile } from 'fs/promises';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import { handleGet, handleHead, handlePut, handleDelete, handleOptions, handlePatch } from './handlers/resource.js';
import { handlePost, handleCreatePod, createPodStructure } from './handlers/container.js';
import * as storage from './storage/filesystem.js';
import { getCorsHeaders } from './ldp/headers.js';
import { authorize, handleUnauthorized } from './auth/middleware.js';
import { notificationsPlugin } from './notifications/index.js';
import { startFileWatcher } from './notifications/events.js';
import { idpPlugin } from './idp/index.js';
import { isGitRequest, isGitWriteOperation, handleGit } from './handlers/git.js';
import { AccessMode } from './wac/parser.js';
import { registerNostrRelay } from './nostr/relay.js';
import { activityPubPlugin, getActorHandler } from './ap/index.js';

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
 * @param {boolean} options.git - Enable Git HTTP backend for clone/push (default false)
 * @param {boolean} options.nostr - Enable Nostr relay (default false)
 * @param {string} options.nostrPath - Nostr relay WebSocket path (default '/relay')
 * @param {number} options.nostrMaxEvents - Max events in relay memory (default 1000)
 * @param {boolean} options.activitypub - Enable ActivityPub federation (default false)
 * @param {string} options.apUsername - ActivityPub username (default 'me')
 * @param {string} options.apDisplayName - ActivityPub display name
 * @param {string} options.apSummary - ActivityPub bio/summary
 * @param {string} options.apNostrPubkey - Nostr pubkey for identity linking
 * @param {boolean} options.webidTls - Enable WebID-TLS client certificate auth (default false)
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
  // SolidOS UI (modern Nextcloud-style interface) - requires mashlib
  const solidosUiEnabled = options.solidosUi ?? false;
  // Git HTTP backend is OFF by default - enables clone/push via git protocol
  const gitEnabled = options.git ?? false;
  // Nostr relay is OFF by default
  const nostrEnabled = options.nostr ?? false;
  const nostrPath = options.nostrPath ?? '/relay';
  const nostrMaxEvents = options.nostrMaxEvents ?? 1000;
  // ActivityPub federation is OFF by default
  const activitypubEnabled = options.activitypub ?? false;
  const apUsername = options.apUsername ?? 'me';
  const apDisplayName = options.apDisplayName ?? options.apUsername ?? 'Anonymous';
  const apSummary = options.apSummary ?? '';
  const apNostrPubkey = options.apNostrPubkey ?? null;
  // Invite-only registration is OFF by default - open registration
  const inviteOnly = options.inviteOnly ?? false;
  // Single-user mode - creates pod on startup, disables registration
  const singleUser = options.singleUser ?? false;
  const singleUserName = options.singleUserName ?? 'me';
  // Default storage quota per pod (50MB default, 0 = unlimited)
  const defaultQuota = options.defaultQuota ?? 50 * 1024 * 1024;
  // WebID-TLS client certificate authentication is OFF by default
  const webidTlsEnabled = options.webidTls ?? false;
  // Live reload - injects script to auto-refresh browser on file changes
  const liveReloadEnabled = options.liveReload ?? false;

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

    // Enable client certificate request for WebID-TLS
    if (webidTlsEnabled) {
      fastifyOptions.https.requestCert = true;
      // Don't reject unauthorized - we verify via WebID profile, not CA chain
      fastifyOptions.https.rejectUnauthorized = false;
    }
  }

  const fastify = Fastify(fastifyOptions);

  // Add raw body parser for all content types
  fastify.addContentTypeParser('*', { parseAs: 'buffer' }, (req, body, done) => {
    done(null, body);
  });

  // Git content types need explicit handling (binary data)
  fastify.addContentTypeParser('application/x-git-receive-pack-request', { parseAs: 'buffer' }, (req, body, done) => {
    done(null, body);
  });
  fastify.addContentTypeParser('application/x-git-upload-pack-request', { parseAs: 'buffer' }, (req, body, done) => {
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
  fastify.decorateRequest('solidosUiEnabled', null);
  fastify.decorateRequest('defaultQuota', null);
  fastify.decorateRequest('config', null);
  fastify.decorateRequest('liveReloadEnabled', null);
  fastify.addHook('onRequest', async (request) => {
    request.connegEnabled = connegEnabled;
    request.notificationsEnabled = notificationsEnabled || liveReloadEnabled;
    request.idpEnabled = idpEnabled;
    request.subdomainsEnabled = subdomainsEnabled;
    request.baseDomain = baseDomain;
    request.mashlibEnabled = mashlibEnabled;
    request.mashlibCdn = mashlibCdn;
    request.mashlibVersion = mashlibVersion;
    request.solidosUiEnabled = solidosUiEnabled;
    request.defaultQuota = defaultQuota;
    request.config = { public: options.public, readOnly: options.readOnly };
    request.liveReloadEnabled = liveReloadEnabled;

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

  // Register WebSocket notifications plugin if enabled (or live reload needs it)
  if (notificationsEnabled || liveReloadEnabled) {
    fastify.register(notificationsPlugin);
  }

  // Register Identity Provider plugin if enabled
  if (idpEnabled) {
    fastify.register(idpPlugin, { issuer: idpIssuer, inviteOnly, singleUser });
  }

  // Register Nostr relay if enabled
  if (nostrEnabled) {
    fastify.register(async (instance) => {
      await registerNostrRelay(instance, {
        path: nostrPath,
        maxEvents: nostrMaxEvents
      });
    });
  }

  // Register ActivityPub plugin if enabled
  if (activitypubEnabled) {
    fastify.register(activityPubPlugin, {
      username: apUsername,
      displayName: apDisplayName,
      summary: apSummary,
      nostrPubkey: apNostrPubkey
    });
  }

  // Register rate limiting plugin
  // Protects against brute force attacks and resource exhaustion
  fastify.register(rateLimit, {
    global: false, // Don't apply globally, only to specific routes
    max: 100, // Default max requests per window
    timeWindow: '1 minute',
    // Custom error response
    errorResponseBuilder: (request, context) => ({
      error: 'Too Many Requests',
      message: `Rate limit exceeded. Try again in ${Math.ceil(context.after / 1000)} seconds.`,
      retryAfter: Math.ceil(context.after / 1000)
    })
  });

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

  // ActivityPub actor endpoint - dedicated route for /profile/card with AP Accept header
  // Registered before wildcard routes to take priority
  if (activitypubEnabled) {
    fastify.route({
      method: 'GET',
      url: '/profile/card',
      handler: async (request, reply) => {
        const accept = request.headers.accept || '';
        const wantsAP = accept.includes('activity+json') ||
                        accept.includes('ld+json; profile="https://www.w3.org/ns/activitystreams"');

        const actorHandler = getActorHandler();
        if (wantsAP && actorHandler) {
          const actor = actorHandler(request);
          return reply
            .type('application/activity+json')
            .send(actor);
        }

        // Not AP request - serve the HTML profile from disk
        // This is handled by importing the resource handler
        const { handleGet } = await import('./handlers/resource.js');
        return handleGet(request, reply);
      }
    });
  }

  // Security: Block access to dotfiles except allowed Solid-specific ones
  // This prevents exposure of .git/, .env, .htpasswd, etc.
  // Git protocol requests bypass this check when git is enabled
  const ALLOWED_DOTFILES = ['.well-known', '.acl', '.meta', '.pods', '.notifications', '.account'];
  fastify.addHook('onRequest', async (request, reply) => {
    // Allow git protocol requests through when git is enabled
    if (gitEnabled && isGitRequest(request.url)) {
      return;
    }

    const segments = request.url.split('/').map(s => s.split('?')[0]); // Remove query strings
    const hasForbiddenDotfile = segments.some(seg =>
      seg.startsWith('.') &&
      seg.length > 1 &&
      !ALLOWED_DOTFILES.includes(seg)
    );

    if (hasForbiddenDotfile) {
      return reply.code(403).send({ error: 'Forbidden', message: 'Dotfile access is not allowed' });
    }
  });

  // Git HTTP backend handler - uses git http-backend CGI
  // Authorization: Read for clone/fetch, Write for push
  if (gitEnabled) {
    fastify.addHook('preHandler', async (request, reply) => {
      if (!isGitRequest(request.url)) {
        return;
      }

      // Determine required mode: Write for push, Read for clone/fetch
      const needsWrite = isGitWriteOperation(request.url);
      const requiredMode = needsWrite ? AccessMode.WRITE : AccessMode.READ;

      // Run WAC authorization with the correct mode for git operations
      const { authorized, webId, wacAllow, authError } = await authorize(request, reply, { requiredMode });
      request.webId = webId;
      request.wacAllow = wacAllow;

      if (!authorized) {
        const message = needsWrite ? 'Write access required for push' : 'Read access required for clone';
        reply.header('WAC-Allow', wacAllow);
        if (!webId) {
          // No authentication - request Basic auth for git clients
          reply.header('WWW-Authenticate', 'Basic realm="Solid"');
        }
        return reply.code(webId ? 403 : 401).send({ error: message });
      }

      // Handle the git request directly
      return handleGit(request, reply);
    });
  }

  // Authorization hook - check WAC permissions
  // Skip for pod creation endpoint (needs special handling)
  fastify.addHook('preHandler', async (request, reply) => {
    // Skip auth for pod creation, OPTIONS, IdP routes, mashlib, solidos-ui, well-known, notifications, nostr, git, and AP
    const mashlibPaths = ['/mashlib.min.js', '/mash.css', '/841.mashlib.min.js'];
    const apPaths = ['/inbox', '/profile/card/inbox', '/profile/card/outbox', '/profile/card/followers', '/profile/card/following'];
    // Check if request wants ActivityPub content for profile
    const accept = request.headers.accept || '';
    const wantsAP = accept.includes('activity+json') || accept.includes('ld+json; profile="https://www.w3.org/ns/activitystreams"');
    const isProfileAP = activitypubEnabled && wantsAP && (request.url === '/profile/card' || request.url.startsWith('/profile/card?'));
    if (request.url === '/.pods' ||
        request.url === '/.notifications' ||
        request.method === 'OPTIONS' ||
        request.url.startsWith('/idp/') ||
        request.url.startsWith('/.well-known/') ||
        request.url.startsWith('/solidos-ui/') ||
        (nostrEnabled && request.url.startsWith(nostrPath)) ||
        (gitEnabled && isGitRequest(request.url)) ||
        (activitypubEnabled && apPaths.some(p => request.url === p || request.url.startsWith(p + '?'))) ||
        isProfileAP ||
        mashlibPaths.some(p => request.url === p || request.url.startsWith(p + '.'))) {
      return;
    }

    const { authorized, webId, wacAllow, authError } = await authorize(request, reply);

    // Store webId and wacAllow on request for handlers to use
    request.webId = webId;
    request.wacAllow = wacAllow;

    // Set WAC-Allow header for all responses (handlers may override)
    reply.header('WAC-Allow', wacAllow);

    if (!authorized) {
      return handleUnauthorized(request, reply, webId !== null, wacAllow, authError);
    }
  });

  // Pod creation endpoint with rate limiting
  // Limit: 1 pod per IP per day to prevent resource exhaustion and namespace squatting
  fastify.post('/.pods', {
    config: {
      rateLimit: {
        max: 1,
        timeWindow: '1 day',
        keyGenerator: (request) => request.ip
      }
    }
  }, handleCreatePod);

  // Mashlib static files (served from root like NSS does)
  if (mashlibEnabled) {
    if (mashlibCdn) {
      // CDN mode: redirect chunk requests to CDN
      // Mashlib uses code splitting, so it loads chunks like 789.mashlib.min.js
      const cdnBase = `https://unpkg.com/mashlib@${mashlibVersion}/dist`;
      const chunkPattern = /^\/\d+\.mashlib\.min\.js(\.map)?$/;

      fastify.addHook('onRequest', async (request, reply) => {
        if (chunkPattern.test(request.url)) {
          const filename = request.url.split('/').pop();
          return reply.redirect(302, `${cdnBase}/${filename}`);
        }
      });
    } else {
      // Local mode: serve from local files
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
  }

  // SolidOS UI static files (modern Nextcloud-style interface)
  // Serves from /solidos-ui/* - requires mashlib to be enabled as well
  if (solidosUiEnabled && mashlibEnabled) {
    const solidosUiDir = join(__dirname, 'mashlib-local', 'dist', 'solidos-ui');

    // Serve all files under /solidos-ui/* path
    fastify.get('/solidos-ui/*', async (request, reply) => {
      try {
        // Get the path after /solidos-ui/
        const filePath = request.url.replace('/solidos-ui/', '').split('?')[0];
        const fullPath = join(solidosUiDir, filePath);

        // Determine content type based on extension
        const ext = filePath.split('.').pop()?.toLowerCase();
        const contentTypes = {
          'js': 'application/javascript',
          'css': 'text/css',
          'map': 'application/json',
          'html': 'text/html'
        };
        const contentType = contentTypes[ext] || 'application/octet-stream';

        const content = await readFile(fullPath);
        return reply.type(contentType).send(content);
      } catch (err) {
        request.log.error(err, 'Failed to serve solidos-ui file');
        return reply.code(404).send({ error: 'Not Found' });
      }
    });
  }

  // Rate limit configuration for write operations
  // Protects against resource exhaustion and abuse
  const writeRateLimit = {
    config: {
      rateLimit: {
        max: 60,
        timeWindow: '1 minute',
        keyGenerator: (request) => request.webId || request.ip
      }
    }
  };

  // LDP routes - using wildcard routing
  // Read operations - no rate limit (handled by bodyLimit)
  fastify.get('/*', handleGet);
  fastify.head('/*', handleHead);
  fastify.options('/*', handleOptions);

  // Write operations - rate limited
  fastify.put('/*', writeRateLimit, handlePut);
  fastify.delete('/*', writeRateLimit, handleDelete);
  fastify.post('/*', writeRateLimit, handlePost);
  fastify.patch('/*', writeRateLimit, handlePatch);

  // Root route
  fastify.get('/', handleGet);
  fastify.head('/', handleHead);
  fastify.options('/', handleOptions);
  fastify.post('/', writeRateLimit, handlePost);

  // Single-user mode: create pod on startup if it doesn't exist
  if (singleUser) {
    fastify.addHook('onReady', async () => {
      // Determine base URL for pod URIs
      const protocol = options.ssl ? 'https' : 'http';
      const host = options.host === '0.0.0.0' ? 'localhost' : (options.host || 'localhost');
      const port = options.port || 3000;
      const baseUrl = idpIssuer?.replace(/\/$/, '') || `${protocol}://${host}:${port}`;
      const issuer = idpIssuer || `${baseUrl}/`;

      // Root-level pod (empty or '/' name) vs named pod
      const isRootPod = !singleUserName || singleUserName === '/';
      const podPath = isRootPod ? '/' : `/${singleUserName}/`;
      const podUri = isRootPod ? `${baseUrl}/` : `${baseUrl}/${singleUserName}/`;
      const webId = `${podUri}profile/card#me`;
      const displayName = isRootPod ? 'me' : singleUserName;

      // Check if pod already exists (profile/card is the indicator)
      const profileExists = await storage.exists(`${podPath}profile/card`);

      if (!profileExists) {
        fastify.log.info(`Creating single-user pod at ${podUri}...`);

        if (isRootPod) {
          // Root-level pod - create structure directly at /
          await createRootPodStructure(webId, podUri, issuer, displayName);
        } else {
          // Named pod at /{name}/
          await createPodStructure(singleUserName, webId, podUri, issuer, defaultQuota);
        }
        fastify.log.info(`Single-user pod created at ${podUri}`);
      }
    });
  }

  /**
   * Create root-level pod structure (for single-user mode with pod at /)
   */
  async function createRootPodStructure(webId, podUri, issuer, displayName) {
    const { generateProfile, generatePreferences, generateTypeIndex, serialize } = await import('./webid/profile.js');
    const { generateOwnerAcl, generatePrivateAcl, generateInboxAcl, generatePublicFolderAcl, serializeAcl } = await import('./wac/parser.js');

    // Create directories at root
    await storage.createContainer('/inbox/');
    await storage.createContainer('/public/');
    await storage.createContainer('/private/');
    await storage.createContainer('/Settings/');
    await storage.createContainer('/profile/');

    // Generate profile
    const profileHtml = generateProfile({ webId, name: displayName, podUri, issuer });
    await storage.write('/profile/card', profileHtml);

    // Preferences and type indexes
    const prefs = generatePreferences({ webId, podUri });
    await storage.write('/Settings/Preferences.ttl', serialize(prefs));

    const publicTypeIndex = generateTypeIndex(`${podUri}Settings/publicTypeIndex.ttl`);
    await storage.write('/Settings/publicTypeIndex.ttl', serialize(publicTypeIndex));

    const privateTypeIndex = generateTypeIndex(`${podUri}Settings/privateTypeIndex.ttl`);
    await storage.write('/Settings/privateTypeIndex.ttl', serialize(privateTypeIndex));

    // ACL files
    const rootAcl = generateOwnerAcl(podUri, webId, true);
    await storage.write('/.acl', serializeAcl(rootAcl));

    const privateAcl = generatePrivateAcl(`${podUri}private/`, webId);
    await storage.write('/private/.acl', serializeAcl(privateAcl));

    const settingsAcl = generatePrivateAcl(`${podUri}Settings/`, webId);
    await storage.write('/Settings/.acl', serializeAcl(settingsAcl));

    const inboxAcl = generateInboxAcl(`${podUri}inbox/`, webId);
    await storage.write('/inbox/.acl', serializeAcl(inboxAcl));

    const publicAcl = generatePublicFolderAcl(`${podUri}public/`, webId);
    await storage.write('/public/.acl', serializeAcl(publicAcl));

    const profileAcl = generatePublicFolderAcl(`${podUri}profile/`, webId);
    await storage.write('/profile/.acl', serializeAcl(profileAcl));

    // Note: Quota not initialized for root-level pods (no user directory)
  }

  // Start file watcher for live reload (watches filesystem for external changes)
  if (liveReloadEnabled) {
    const dataRoot = options.root || process.env.DATA_ROOT || './data';
    const protocol = options.ssl ? 'https' : 'http';
    // Use configured port, or default; actual URL will be localhost
    const port = options.port || 3000;
    const baseUrl = `${protocol}://localhost:${port}`;
    startFileWatcher(dataRoot, baseUrl);
  }

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
