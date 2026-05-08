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
import { handleCorsProxy, isCorsProxyRequest, setProxyCorsHeaders } from './handlers/cors-proxy.js';
import { AccessMode } from './wac/parser.js';
import { registerNostrRelay } from './nostr/relay.js';
import { createPayHandler, isPayRequest } from './handlers/pay.js';
import { activityPubPlugin, getActorHandler } from './ap/index.js';
import { remoteStoragePlugin } from './remotestorage.js';
import { dbPlugin } from './db/index.js';
import { webrtcPlugin } from './webrtc/index.js';
import { tunnelPlugin } from './tunnel/index.js';
import { terminalPlugin } from './terminal/index.js';
import { registerErrorHandler } from './utils/error-handler.js';

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
 * @param {boolean} options.pay - Enable HTTP 402 paid /pay/* routes (default false)
 * @param {number} options.payCost - Cost per request in satoshis (default 1)
 * @param {string} options.payMempoolUrl - Mempool API base URL (default testnet4)
 * @param {string} options.payAddress - Pod's MRC20 address for receiving token transfers
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
  // mashlibCdn: load from CDN; mashlibModule: URL to ES module entry point
  const mashlibModule = options.mashlibModule ?? false;
  const mashlibCdn = options.mashlibCdn ?? false;
  const mashlibEnabled = mashlibCdn || !!mashlibModule;
  const mashlibVersion = options.mashlibVersion ?? '2.0.0';
  // Git HTTP backend is OFF by default - enables clone/push via git protocol
  const gitEnabled = options.git ?? false;
  // CORS proxy (#378) — OFF by default. Numeric settings get the
  // sane-default fallback if the env var or config file supplies a
  // non-finite/non-positive value (e.g. JSS_CORS_PROXY_MAX_BYTES=banana
  // would otherwise leave the cap as the string "banana", making
  // `bytesSeen > "banana"` always false and silently disabling the
  // safety limit).
  const positiveInt = (v, fallback) =>
    (typeof v === 'number' && Number.isFinite(v) && v > 0) ? v : fallback;
  const corsProxyEnabled = options.corsProxy === true;
  const corsProxyMaxBytes = positiveInt(options.corsProxyMaxBytes, 50 * 1024 * 1024);
  const corsProxyTimeoutMs = positiveInt(options.corsProxyTimeoutMs, 30_000);
  const corsProxyMaxRedirects = positiveInt(options.corsProxyMaxRedirects, 5);
  // Nostr relay is OFF by default
  const nostrEnabled = options.nostr ?? false;
  const nostrPath = options.nostrPath ?? '/relay';
  const nostrMaxEvents = options.nostrMaxEvents ?? 1000;
  // WebRTC signaling is OFF by default
  const webrtcEnabled = options.webrtc ?? false;
  const webrtcPath = options.webrtcPath ?? '/.webrtc';
  // Terminal (WebSocket shell) is OFF by default
  const terminalEnabled = options.terminal ?? false;
  // Tunnel proxy is OFF by default
  const tunnelEnabled = options.tunnel ?? false;
  const tunnelPath = options.tunnelPath ?? '/.tunnel';
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
  // Default null = root pod (#348). Pass an explicit singleUserName
  // to mount the pod at /<name>/ instead. Normalize the
  // historical `'/'` / `''` forms to null up front so downstream
  // code (remoteStoragePlugin, decorators, etc.) doesn't have to
  // re-check for the same three shapes.
  //
  // Pre-#348 installs (default 'me') that upgrade in place will see
  // a fresh empty root pod alongside their /me/ data. The fix is to
  // pass `--single-user-name me` on restart (or move data/me/* out
  // to the data root). At v0.0.x we accept that one-time
  // intervention rather than carrying detection magic in the code.
  const rawSingleUserName = options.singleUserName ?? null;
  const singleUserName =
    (rawSingleUserName === '/' || rawSingleUserName === '')
      ? null
      : rawSingleUserName;
  const singleUserPassword = options.singleUserPassword ?? null;
  // Default storage quota per pod (50MB default, 0 = unlimited)
  const defaultQuota = options.defaultQuota ?? 50 * 1024 * 1024;
  // WebID-TLS client certificate authentication is OFF by default
  const webidTlsEnabled = options.webidTls ?? false;
  // Live reload - injects script to auto-refresh browser on file changes
  const liveReloadEnabled = options.liveReload ?? false;
  // MongoDB-backed /db/ route is OFF by default
  const mongoEnabled = options.mongo ?? false;
  const mongoUrl = options.mongoUrl ?? 'mongodb://localhost:27017';
  const mongoDatabase = options.mongoDatabase ?? 'solid';
  // HTTP 402 paid /pay/ routes are OFF by default
  const payEnabled = options.pay ?? false;
  const payCost = options.payCost ?? 1;
  const payMempoolUrl = options.payMempoolUrl ?? 'https://mempool.space/testnet4';
  const payAddress = options.payAddress ?? null; // Pod's MRC20 address for token deposits
  const payToken = options.payToken ?? null; // Token ticker for primary market
  const payRate = options.payRate ?? 1; // Sats per token
  const payChains = options.payChains ?? null; // Multi-chain IDs (e.g. "tbtc3,tbtc4")

  // Set data root via environment variable if provided
  if (options.root) {
    process.env.DATA_ROOT = options.root;
  }

  // Fastify options
  const loggerEnabled = options.logger ?? true;
  const fastifyOptions = {
    logger: loggerEnabled ? { level: options.logLevel || 'info' } : false,
    disableRequestLogging: true,
    trustProxy: true,
    // Force close connections on server.close() (useful for tests with WebSockets)
    forceCloseConnections: options.forceCloseConnections ?? false,
    // Handle raw body for non-JSON content
    bodyLimit: 10 * 1024 * 1024, // 10MB
    // Gracefully handle client TCP errors (ECONNRESET, EPIPE, etc.)
    clientErrorHandler: (err, socket) => {
      if (err.code === 'ECONNRESET' || err.code === 'EPIPE' || err.code === 'ECONNABORTED') {
        socket.destroy();
        return;
      }
      // Default Fastify behavior for other client errors
      socket.destroy(err);
    }
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
  registerErrorHandler(fastify);

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
  fastify.decorateRequest('mashlibModule', null);
  fastify.decorateRequest('defaultQuota', null);
  fastify.decorateRequest('config', null);
  fastify.decorateRequest('liveReloadEnabled', null);
  fastify.decorateRequest('singleUser', null);
  fastify.decorateRequest('singleUserName', null);
  fastify.addHook('onRequest', async (request) => {
    request.connegEnabled = connegEnabled;
    request.notificationsEnabled = notificationsEnabled || liveReloadEnabled;
    request.idpEnabled = idpEnabled;
    request.subdomainsEnabled = subdomainsEnabled;
    request.baseDomain = baseDomain;
    request.mashlibEnabled = mashlibEnabled;
    request.mashlibCdn = mashlibCdn;
    request.mashlibVersion = mashlibVersion;
    request.mashlibModule = mashlibModule;
    request.defaultQuota = defaultQuota;
    request.config = { public: options.public, readOnly: options.readOnly };
    request.liveReloadEnabled = liveReloadEnabled;
    request.singleUser = singleUser;
    request.singleUserName = singleUserName;

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

  // Unified access log — one line per request
  fastify.addHook('onResponse', async (request, reply) => {
    if (!request.log.isLevelEnabled('info')) return;
    request.log.info({
      method: request.method,
      url: request.url,
      statusCode: reply.statusCode,
      remoteAddress: request.ip || request.headers['x-forwarded-for'] || request.socket?.remoteAddress,
      responseTime: Math.round(reply.elapsedTime * 100) / 100,
      userAgent: request.headers['user-agent'] || undefined,
      referrer: request.headers.referer || undefined,
      contentLength: reply.getHeader('content-length') || undefined,
    }, `${request.method} ${request.url} ${reply.statusCode} ${Math.round(reply.elapsedTime)}ms`);
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

  // Register WebRTC signaling if enabled
  if (webrtcEnabled) {
    fastify.register(webrtcPlugin, { path: webrtcPath });
  }

  // Register terminal (WebSocket shell) if enabled
  if (terminalEnabled) {
    fastify.register(terminalPlugin, { path: '/.terminal', public: options.public || false });
  }

  // Register tunnel proxy if enabled
  if (tunnelEnabled) {
    fastify.register(tunnelPlugin, { path: tunnelPath });
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

  // Register remoteStorage plugin (always on — no flag needed)
  fastify.register(remoteStoragePlugin, {
    username: singleUserName || 'me',
    ownerWebId: null  // single-user: any authenticated user can access
  });

  // Register MongoDB /db/ route if enabled
  if (mongoEnabled) {
    fastify.register(dbPlugin, { mongoUrl, mongoDatabase, singleUser });
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

  // ActivityPub actor endpoint - dedicated route for /profile/card.jsonld with AP Accept header
  // Registered before wildcard routes to take priority
  if (activitypubEnabled) {
    fastify.route({
      method: 'GET',
      url: '/profile/card.jsonld',
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

    // Allow pay routes through when pay is enabled (.balance, .deposit)
    if (payEnabled && isPayRequest(request.url)) {
      return;
    }

    // Allow WebRTC and tunnel endpoints through when enabled
    const urlNoQuery = request.url.split('?')[0];
    if (tunnelEnabled && (urlNoQuery === tunnelPath || urlNoQuery.startsWith('/tunnel/'))) {
      return;
    }
    if (webrtcEnabled && urlNoQuery === webrtcPath) {
      return;
    }
    if (terminalEnabled && urlNoQuery === '/.terminal') {
      return;
    }

    // Only inspect the path component — splitting the full URL on '/'
    // would catch dot-prefixed segments inside query-string values
    // (e.g. /proxy?url=https://example.com/.git/config), rejecting
    // legitimate proxy requests for upstream URLs that happen to
    // contain dotfile-like path segments. The dotfile guard is about
    // *this* pod's filesystem, not what the URL looks like.
    const segments = request.url.split('?')[0].split('/');
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
      const { authorized, webId, wacAllow, authError, paymentRequired } = await authorize(request, reply, { requiredMode });
      request.webId = webId;
      request.wacAllow = wacAllow;

      if (paymentRequired) {
        return reply.code(402).send({ type: 'PaymentRequired', ...paymentRequired });
      }

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

  // HTTP 402 Payment Required handler for /pay/* routes
  if (payEnabled) {
    fastify.addHook('preHandler', createPayHandler({ cost: payCost, mempoolUrl: payMempoolUrl, payAddress, payToken, payRate, payChains }));
  }

  // CORS proxy (#378) — WAC-gated. Standard authorize() path runs against
  // /proxy as a virtual resource; pod owner controls access by writing an
  // .acl on /proxy (or inheriting from /.acl). OPTIONS preflight returns
  // 204 directly without auth so browser CORS checks succeed before sign-in.
  if (corsProxyEnabled) {
    fastify.addHook('preHandler', async (request, reply) => {
      const urlPath = request.url.split('?')[0];
      if (!isCorsProxyRequest(urlPath)) {
        return;
      }

      // OPTIONS preflight short-circuits to the handler (which returns
      // 204 + proxy CORS headers) without going through authorize() at
      // all. authorize() does have its own OPTIONS short-circuit, but
      // routing through here keeps the preflight off the auth/payment
      // path entirely — preflights must never debit ledgers or evaluate
      // PaymentConditions.
      if (request.method === 'OPTIONS') {
        return handleCorsProxy(request, reply, {
          maxBytes: corsProxyMaxBytes,
          timeoutMs: corsProxyTimeoutMs,
          maxRedirects: corsProxyMaxRedirects,
        });
      }

      // Don't override requiredMode — let authorize() derive it from the
      // request method via getRequiredMode(). GET/HEAD need READ on the
      // /proxy resource, POST needs APPEND/WRITE — pod owners can grant
      // these separately via ACL modes (e.g. acl:Read for browse-only,
      // acl:Append/Write for proxying side-effecting POSTs upstream).
      //
      // skipParentForMissing prevents authorize()'s "non-existent resource +
      // write method → check parent container" fallback from kicking in.
      // /proxy is a virtual endpoint with no backing storage, so the
      // fallback would route POST authorization to / (the root) instead
      // of /proxy — too permissive. With this flag, authorize() checks
      // ACLs against /proxy directly regardless of storage existence.
      const { authorized, webId, wacAllow, authError, paymentRequired, paid, balance, currency } =
        await authorize(request, reply, { skipParentForMissing: true });
      request.webId = webId;
      request.wacAllow = wacAllow;

      // Surface paid-access bookkeeping the same way the standard WAC
      // hook does (lines 564-569 below). When a /proxy ACL uses a
      // PaymentCondition and the caller has sufficient balance,
      // checkAccess() returns paid (the cost), balance, and currency —
      // browser-side renders charge UI off these. Without this, ledger
      // debit happens silently.
      if (paid !== undefined) {
        reply.header('X-Cost', String(paid));
        reply.header('X-Balance', String(balance));
        if (currency) reply.header('X-Pay-Currency', currency);
      }

      // Set WAC-Allow on success too, matching the global WAC hook
      // (line 562 area). Browser clients read it via Expose-Headers
      // to render auth UX. Without this, only 401/403/402 responses
      // carry WAC-Allow, which is inconsistent.
      reply.header('WAC-Allow', wacAllow);

      // ACL with a PaymentCondition surfaces as 402 here — mirrors the
      // git handler at src/server.js:418 and the standard WAC hook so
      // payment-gated /proxy ACLs behave consistently.
      if (paymentRequired) {
        setProxyCorsHeaders(reply);
        reply.header('WAC-Allow', wacAllow);
        return reply.code(402).send({ type: 'PaymentRequired', ...paymentRequired });
      }

      if (request.method !== 'OPTIONS' && !authorized) {
        // Apply proxy CORS headers BEFORE handleUnauthorized so the 401/403
        // is readable by browser clients (without these the browser surfaces
        // the response as a generic CORS failure — same shape as #374).
        setProxyCorsHeaders(reply);
        reply.header('WAC-Allow', wacAllow);
        return handleUnauthorized(request, reply, webId !== null, wacAllow, authError);
      }

      return handleCorsProxy(request, reply, {
        maxBytes: corsProxyMaxBytes,
        timeoutMs: corsProxyTimeoutMs,
        maxRedirects: corsProxyMaxRedirects,
      });
    });
  }

  // Authorization hook - check WAC permissions
  // Skip for pod creation endpoint (needs special handling)
  fastify.addHook('preHandler', async (request, reply) => {
    // Skip auth for pod creation, OPTIONS, IdP routes, mashlib, well-known, notifications, nostr, git, and AP
    const mashlibPaths = ['/mashlib.min.js', '/mash.css', '/841.mashlib.min.js'];
    const apPaths = ['/inbox', '/profile/card.jsonld/inbox', '/profile/card.jsonld/outbox', '/profile/card.jsonld/followers', '/profile/card.jsonld/following',
      '/api/v1/apps', '/api/v1/instance', '/api/v1/accounts/verify_credentials',
      '/oauth/authorize', '/oauth/token'];
    // Check if request wants ActivityPub content for profile
    const accept = request.headers.accept || '';
    const wantsAP = accept.includes('activity+json') || accept.includes('ld+json; profile="https://www.w3.org/ns/activitystreams"');
    const isProfileAP = activitypubEnabled && wantsAP && (request.url === '/profile/card.jsonld' || request.url.startsWith('/profile/card.jsonld?'));
    if (request.url === '/.pods' ||
        request.url === '/.notifications' ||
        request.method === 'OPTIONS' ||
        request.url === '/idp' ||
        request.url.startsWith('/idp/') ||
        request.url.startsWith('/idp?') ||
        request.url.startsWith('/.well-known/') ||
        (nostrEnabled && request.url.startsWith(nostrPath)) ||
        (gitEnabled && isGitRequest(request.url)) ||
        (corsProxyEnabled && isCorsProxyRequest(request.url.split('?')[0])) ||
        (activitypubEnabled && apPaths.some(p => request.url === p || request.url.startsWith(p + '?'))) ||
        isProfileAP ||
        request.url.startsWith('/storage/') ||
        (payEnabled && isPayRequest(request.url)) ||
        (mongoEnabled && (request.url === '/db' || request.url.startsWith('/db/'))) ||
        (webrtcEnabled && (request.url === webrtcPath || request.url.startsWith(webrtcPath + '?'))) ||
        (terminalEnabled && (request.url === '/.terminal' || request.url.startsWith('/.terminal?'))) ||
        (tunnelEnabled && (request.url === tunnelPath || request.url.startsWith(tunnelPath + '?') || request.url.startsWith('/tunnel/'))) ||
        mashlibPaths.some(p => request.url === p || request.url.startsWith(p + '.'))) {
      return;
    }

    const { authorized, webId, wacAllow, authError, paymentRequired, paid, balance, currency } = await authorize(request, reply);

    // Store webId and wacAllow on request for handlers to use
    request.webId = webId;
    request.wacAllow = wacAllow;

    // Set WAC-Allow header for all responses (handlers may override)
    reply.header('WAC-Allow', wacAllow);

    // Set payment headers for paid access
    if (paid !== undefined) {
      reply.header('X-Cost', String(paid));
      reply.header('X-Balance', String(balance));
      if (currency) reply.header('X-Pay-Currency', currency);
    }

    // Handle payment-gated resources
    if (paymentRequired) {
      return reply.code(402).send({
        type: 'PaymentRequired',
        ...paymentRequired
      });
    }

    if (!authorized) {
      return handleUnauthorized(request, reply, webId !== null, wacAllow, authError);
    }
  });

  // Pod creation endpoint with rate limiting
  // Limit: 1 pod per IP per day to prevent resource exhaustion and namespace squatting
  // Disabled in single-user mode
  if (singleUser) {
    fastify.post('/.pods', async (request, reply) => {
      return reply.code(403).send({ error: 'Forbidden', message: 'Pod creation disabled in single-user mode' });
    });
  } else {
    fastify.post('/.pods', {
      config: {
        rateLimit: {
          max: 1,
          timeWindow: '1 day',
          keyGenerator: (request) => request.ip
        }
      }
    }, handleCreatePod);
  }

  // Mashlib CDN mode: redirect chunk requests to CDN
  if (mashlibEnabled && mashlibCdn) {
    const cdnBase = `https://unpkg.com/mashlib@${mashlibVersion}/dist`;
    const chunkPattern = /^\/\d+\.mashlib\.min\.js(\.map)?$/;

    fastify.addHook('onRequest', async (request, reply) => {
      if (chunkPattern.test(request.url)) {
        const filename = request.url.split('/').pop();
        return reply.redirect(302, `${cdnBase}/${filename}`);
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

      // Root pod (no name) vs named pod. After the singleUserName
      // normalization at the top of createServer(), null is the only
      // root-pod shape we need to recognize here.
      const isRootPod = !singleUserName;
      const podPath = isRootPod ? '/' : `/${singleUserName}/`;
      const podUri = isRootPod ? `${baseUrl}/` : `${baseUrl}/${singleUserName}/`;
      const displayName = isRootPod ? 'me' : singleUserName;

      // Check if pod already exists. Accept either the new `card.jsonld`
      // or legacy extensionless `card` layout so we don't re-seed a pod
      // that was created by an older JSS version. Compute the effective
      // WebID against whichever profile file actually resolves — a
      // legacy pod must keep its `/profile/card#me` WebID, otherwise the
      // seeded IDP account would point at a non-existent document.
      const hasJsonLd = await storage.exists(`${podPath}profile/card.jsonld`);
      const hasLegacy = !hasJsonLd && await storage.exists(`${podPath}profile/card`);
      const profileFile = hasJsonLd ? 'profile/card.jsonld'
                          : hasLegacy ? 'profile/card'
                          : 'profile/card.jsonld'; // fresh pod default
      const webId = `${podUri}${profileFile}#me`;
      const profileExists = hasJsonLd || hasLegacy;

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

      // Seed an IDP account so the operator can actually log in. Without
      // this, single-user + --idp produces a pod but no credential, and
      // registration is intentionally disabled in single-user mode — so
      // the pod is unloggable until a password is set externally (#323).
      //
      // Root pods (#348) need this too: the pod has no name, but the IDP
      // still needs *some* username for the login form. Default to 'me'
      // — matches the WebID fragment, fits the historical convention.
      if (idpEnabled) {
        // The IDP also persists `podName` and surfaces it as the
        // `name` claim under the OIDC `profile` scope (see
        // src/idp/accounts.js). For root pods we use 'me' here too —
        // a null podName would leak through as a null/missing
        // profile.name on every login, which OIDC clients expect to
        // be a non-empty human-readable string.
        await seedSingleUserIdpAccount({
          fastify,
          username: isRootPod ? 'me' : singleUserName,
          webId,
          podName: isRootPod ? 'me' : singleUserName,
          providedPassword: singleUserPassword
        });
      }
    });
  }

  /**
   * Seed an IDP account for the single-user pod owner if one doesn't
   * already exist. Password sources, in priority order:
   *   1. `--single-user-password` / `JSS_SINGLE_USER_PASSWORD`
   *   2. interactive prompt (TTY only)
   *   3. error — server stays up but logs that login won't work yet
   */
  async function seedSingleUserIdpAccount({ fastify, username, webId, podName, providedPassword }) {
    const { findByUsername, createAccount } = await import('./idp/accounts.js');
    const existing = await findByUsername(username);
    if (existing) return; // already seeded — idempotent

    // Treat anything that isn't a non-empty string as "not provided" so
    // a misconfigured env coercion or stray boolean can't reach bcrypt.
    let password = (typeof providedPassword === 'string' && providedPassword.length > 0)
      ? providedPassword
      : null;

    if (!password) {
      if (process.stdin.isTTY && process.stdout.isTTY) {
        try {
          password = await promptPasswordOnce(`[jss] Set initial IDP password for "${username}": `);
        } catch (err) {
          fastify.log.warn({ err }, `Password prompt failed for "${username}"`);
          return;
        }
      } else {
        fastify.log.warn(
          `--single-user --idp: no password provided. Set --single-user-password or ` +
          `JSS_SINGLE_USER_PASSWORD before starting (or run on a TTY to be prompted). ` +
          `Login is currently not possible for "${username}".`
        );
        return;
      }
    }

    if (typeof password !== 'string' || password.length === 0) {
      fastify.log.warn(`Empty password — skipping IDP account creation for "${username}".`);
      return;
    }

    try {
      await createAccount({ username, password, webId, podName });
      fastify.log.info(`IDP account seeded for single-user "${username}".`);
    } catch (err) {
      fastify.log.error({ err }, `Failed to seed IDP account for "${username}"`);
    }
  }

  /**
   * Read a password from stdin without echoing it. Uses the public
   * `emitKeypressEvents` + raw-mode keypress API rather than overriding
   * the underscored `_writeToOutput` on a `readline.Interface`, which is
   * a private/unstable hook.
   */
  async function promptPasswordOnce(prompt) {
    const { emitKeypressEvents } = await import('node:readline');
    const stdin = process.stdin;
    const stdout = process.stdout;
    if (!stdin.isTTY || typeof stdin.setRawMode !== 'function') {
      throw new Error('Interactive password prompt requires a TTY');
    }
    return new Promise((resolve, reject) => {
      let password = '';
      const wasRaw = stdin.isRaw === true;
      const onKeypress = (str, key = {}) => {
        if (key.ctrl && key.name === 'c') {
          cleanup();
          reject(new Error('Password prompt cancelled'));
          return;
        }
        if (key.name === 'return' || key.name === 'enter') {
          cleanup();
          resolve(password);
          return;
        }
        if (key.name === 'backspace' || key.name === 'delete') {
          password = password.slice(0, -1);
          return;
        }
        // Only accept printable input — \P{C} excludes control codes,
        // so escape sequences from arrow keys, function keys, etc. don't
        // sneak invisible bytes into the password buffer.
        if (!key.ctrl && !key.meta &&
            typeof str === 'string' && str.length > 0 &&
            /^\P{C}+$/u.test(str)) {
          password += str;
        }
      };
      const cleanup = () => {
        stdin.removeListener('keypress', onKeypress);
        if (!wasRaw) stdin.setRawMode(false);
        stdout.write('\n');
        stdin.pause();
      };
      emitKeypressEvents(stdin);
      stdout.write(prompt);
      if (!wasRaw) stdin.setRawMode(true);
      stdin.resume();
      stdin.on('keypress', onKeypress);
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
    await storage.createContainer('/settings/');
    await storage.createContainer('/profile/');

    // Generate profile
    const profile = generateProfile({ webId, name: displayName, podUri, issuer });
    await storage.write('/profile/card.jsonld', serialize(profile));

    // Preferences and type indexes
    const prefs = generatePreferences({ webId, podUri });
    await storage.write('/settings/prefs.jsonld', serialize(prefs));

    const publicTypeIndex = generateTypeIndex(`${podUri}settings/publicTypeIndex.jsonld`, { listed: true });
    await storage.write('/settings/publicTypeIndex.jsonld', serialize(publicTypeIndex));

    const privateTypeIndex = generateTypeIndex(`${podUri}settings/privateTypeIndex.jsonld`, { listed: false });
    await storage.write('/settings/privateTypeIndex.jsonld', serialize(privateTypeIndex));

    // ACL files
    const rootAcl = generateOwnerAcl(podUri, webId, true);
    await storage.write('/.acl', serializeAcl(rootAcl));

    const privateAcl = generatePrivateAcl(`${podUri}private/`, webId);
    await storage.write('/private/.acl', serializeAcl(privateAcl));

    const settingsAcl = generatePrivateAcl(`${podUri}settings/`, webId);
    await storage.write('/settings/.acl', serializeAcl(settingsAcl));

    // publicTypeIndex: public read, overrides the private default inherited from /settings/
    const publicTypeIndexAcl = generateOwnerAcl(`${podUri}settings/publicTypeIndex.jsonld`, webId, false);
    await storage.write('/settings/publicTypeIndex.jsonld.acl', serializeAcl(publicTypeIndexAcl));

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
