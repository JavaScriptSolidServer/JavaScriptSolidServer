/**
 * Plugin loader — the #206 seam, assembled from its shipped parts.
 *
 *   createServer({
 *     plugins: [
 *       { module: 'tideholm/jss-plugin/tideholm-jss.js', prefix: '/tideholm',
 *         config: { bots: 8 } },
 *       { module: './my-app/plugin.js', prefix: '/myapp' },
 *     ],
 *   })
 *
 * Each entry's module is imported and its exported `activate(api)` called
 * during server startup (before listen completes). The api wires the seams
 * every plugin consumer so far has needed:
 *
 *   api.fastify              scoped Fastify instance to register routes on
 *   api.prefix               the entry's mount prefix ('' when none)
 *   api.config               the entry's config object, verbatim
 *   api.log                  server logger
 *   api.auth.getAgent(req)   -> agent id string | null   (#584)
 *   api.storage.pluginDir()  -> private server-side data dir for this plugin
 *   api.serverInfo()         -> { baseUrl, protocol, host, port, listening } (#601)
 *   api.reservePath(path)    claim + WAC-exempt a protocol-pinned path (#602)
 *   api.ws.route(path, (socket, request) => {})          (#588)
 *
 * The entry's `prefix` is added to appPaths automatically (#582), so the
 * plugin owns authentication and authorization under its mount — the same
 * deal the bundled pseudo-plugins (idp, /db, /storage/…) already have.
 *
 * ws.route registers WebSocket endpoints through @fastify/websocket — the
 * same single upgrade path the bundled realtime features (nostr relay,
 * tunnel, notifications…) use — so plugins never attach their own 'upgrade'
 * listener. That matters: node only auto-destroys stray upgrade attempts
 * while the server has NO 'upgrade' listener, so a plugin attaching one
 * would become responsible for every unclaimed socket on the host (#588).
 * The handler receives the raw ws socket; a plugin with its own
 * WebSocketServer({ noServer: true }) can feed it straight in:
 *   api.ws.route('/myapp/ws', (socket, req) => wss.emit('connection', socket, req));
 *
 * activate() may return { deactivate() {} }; deactivate runs on server
 * close (world saves, timer teardown). A plugin that fails to load fails
 * the boot loudly — the operator wrote the config, and a server silently
 * missing an app is worse than one that refuses to start.
 */

import fs from 'fs';
import path from 'path';
import { pathToFileURL } from 'url';
import websocket from '@fastify/websocket';
import { getAgent } from '../auth.js';

/**
 * api.log speaks both dialects: pino-style (info/warn/error/debug, what
 * fastify.log is) and console-style (log/error, what plain node apps
 * expect) — plugins shouldn't need to know which logger the host runs.
 */
export function makePluginLog(base) {
  const call = (level) => (...args) => {
    const fn = base?.[level] ?? base?.info ?? base?.log;
    if (typeof fn === 'function') fn.call(base, ...args);
  };
  return { log: call('info'), info: call('info'), warn: call('warn'), error: call('error'), debug: call('debug') };
}

/**
 * Compile a parameterized reservation like '/:user/did.json' (#602) to a
 * matcher. ':name' segments match one path segment; everything else is
 * literal. Parameterized reservations match the exact path shape (plus an
 * optional query string) — NOT a subtree — because they exist for pinned
 * documents inside otherwise WAC-governed namespaces (did:web), where
 * exempting a whole subtree would be a WAC bypass.
 */
// Only a segment that is ENTIRELY ':name' is a parameter. '/:user.json'
// is literal (its own segment mixes a param sigil with literal text) —
// treating it as a wildcard would exempt a far broader set of URLs than
// the ':name'-per-segment contract promises.
const PARAM_SEGMENT = /^:[A-Za-z_][A-Za-z0-9_]*$/;

export function isParamPath(p) {
  return p.split('/').some((seg) => PARAM_SEGMENT.test(seg));
}

export function compilePathPattern(p) {
  const pattern = p
    .split('/')
    // Exclude '?' as well as '/': a param must be a single PATH segment,
    // so it must not swallow the query delimiter — otherwise a query
    // containing '/' (e.g. /alice?x=a/b) would fail to match a shape the
    // path part satisfies, making matching depend on query contents.
    .map((seg) => (PARAM_SEGMENT.test(seg)
      ? '[^/?]+'
      : seg.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')))
    .join('/');
  return new RegExp(`^${pattern}(?:\\?.*)?$`);
}

// Collision key: two reservations conflict when they exempt the same
// URLs, so parameter NAMES don't matter — '/:user/did.json' and
// '/:acct/did.json' are the same claim. Each segment is tagged by TYPE
// (param vs literal) so a canonicalized param can't alias a literal
// segment that happens to be the placeholder text (e.g. a literal '/:/…').
// '\x00' never occurs in a real path, so it's a safe framing prefix.
export function reservationKey(p) {
  return p.split('/')
    .map((seg) => (PARAM_SEGMENT.test(seg) ? '\x00P' : `\x00L${seg}`))
    .join('/');
}

/** Same normalization appPaths applies: no trailing slash, must be '/x…'. */
export function normalizePrefix(p) {
  if (typeof p !== 'string') return '';
  const trimmed = p.trim().replace(/\/+$/, '');
  return trimmed.startsWith('/') && trimmed.length > 1 ? trimmed : '';
}

/**
 * Directory-safe plugin id: entry.id, or derived from the module spec.
 * Bare package specifiers keep their full path ('@scope/pkg/plugin.js' ->
 * 'scope-pkg-plugin') so same-named files in different packages don't
 * collide; file paths use the basename, because a machine-specific
 * directory prefix must not name the plugin's data dir (the id — and with
 * it pluginDir — would change whenever the deployment moves). The loader
 * additionally rejects duplicate ids, so any residual collision fails the
 * boot instead of silently sharing storage.
 */
export function pluginId(spec) {
  const module = String(spec.module);
  const raw = typeof spec.id === 'string' && spec.id
    ? spec.id
    : (module.startsWith('.') || path.isAbsolute(module)
        ? path.basename(module)
        : module
      ).replace(/\.[cm]?js$/, '');
  const id = raw.toLowerCase().replace(/[^a-z0-9_-]+/g, '-').replace(/^-+|-+$/g, '');
  if (!id) throw new Error(`plugins: cannot derive an id from ${JSON.stringify(spec.module)}; set entry.id`);
  return id;
}

/**
 * Load and activate every plugin entry. Called from createServer inside a
 * fastify.register scope, so `fastify` here is that scope; routes and hooks
 * plugins add land on the running server.
 *
 * @param {object} fastify   scoped instance the plugins register on
 * @param {Array}  entries   options.plugins, verbatim
 * @param {object} ctx       { appPaths, root, log }
 */
export async function loadPlugins(fastify, entries, ctx) {
  const log = makePluginLog(ctx.log);
  const seenIds = new Set();
  // reservePath claims (#602), shared across all entries of this load so
  // two plugins reserving the same pinned path fail the boot with both
  // names — loud beats the silent-loser outcome witnessed with webfinger
  // vs remotestorage.
  const reservations = new Map();
  for (const entry of entries) {
    const spec = typeof entry === 'string' ? { module: entry } : entry;
    if (!spec || typeof spec.module !== 'string' || !spec.module) {
      throw new Error('plugins: each entry needs a module (import specifier or path)');
    }
    const id = pluginId(spec);
    if (seenIds.has(id)) {
      throw new Error(`plugins: duplicate id '${id}' — set entry.id to keep the plugins' data dirs apart`);
    }
    seenIds.add(id);

    // Paths resolve from the operator's cwd; bare specifiers stay package
    // imports resolved from JSS's own module graph.
    const href = spec.module.startsWith('.') || path.isAbsolute(spec.module)
      ? pathToFileURL(path.resolve(spec.module)).href
      : spec.module;
    let mod;
    try {
      mod = await import(href);
    } catch (err) {
      throw new Error(`plugin ${id}: cannot import ${spec.module}: ${err.message}`);
    }
    const activate = mod.activate ?? mod.default;
    if (typeof activate !== 'function') {
      throw new Error(`plugin ${id}: module exports no activate(api) function`);
    }

    // Any provided prefix must validate — a falsy one ('', 0) silently
    // skipping the appPaths exemption would mount the app behind WAC.
    // Omit the property entirely for a plugin with no mount prefix.
    const prefix = normalizePrefix(spec.prefix);
    if (spec.prefix !== undefined && !prefix) {
      throw new Error(`plugin ${id}: invalid prefix ${JSON.stringify(spec.prefix)} (must start with '/'; omit for none)`);
    }
    if (prefix) ctx.appPaths.push(prefix); // WAC exemption under the mount (#582)

    const api = {
      fastify,
      prefix,
      config: spec.config ?? {},
      log,
      auth: { getAgent },
      storage: {
        // Under the data root's dot-guard (like .idp): never served over LDP.
        pluginDir() {
          const dir = path.join(ctx.root, '.plugins', id);
          fs.mkdirSync(dir, { recursive: true });
          return dir;
        },
      },
      // The server's own origin (#601) — for minting absolute URLs and
      // loopback calls, so plugins stop repeating baseUrl in config where
      // a wrong value fails quietly. A function, not a snapshot: with
      // port 0 the real port exists only once the server is listening,
      // so call it lazily (per request, or in an onListen hook via
      // api.fastify) rather than caching the result during activate.
      // An explicit idpIssuer is the deployment's canonical public origin
      // and wins over the host:port derivation, mirroring the pod-seeding
      // logic in server.js.
      // Reserve a path the protocol pins outside the plugin's prefix
      // (#602): fixed roots like /xrpc or /_matrix (literal — exempts the
      // subtree, like a prefix), or parameterized documents like
      // /:user/did.json (exact-shape match only; see compilePathPattern).
      // The claim is deliberate and cross-plugin: a second plugin
      // reserving the same path fails the boot naming both claimants,
      // instead of one silently losing. Registering the routes is still
      // the plugin's job via api.fastify.
      reservePath(p, opts = {}) {
        // Validate AFTER normalization: '//' or '/ ' normalize to '',
        // and an empty string in appPaths would match every URL in the
        // WAC hook — a one-call total WAC bypass.
        const key = typeof p === 'string' ? p.trim().replace(/\/+$/, '') : '';
        if (!key.startsWith('/') || key.length < 2) {
          throw new Error(`plugin ${id}: reservePath needs an absolute path, got ${JSON.stringify(p)}`);
        }
        // Track by the shape, not the raw string: '/:user/did.json' and
        // '/:acct/did.json' exempt the same URLs, so they're the same
        // claim and must collide loudly like two literal reservations.
        const claim = reservationKey(key);
        const holder = reservations.get(claim);
        if (holder && holder !== id) {
          throw new Error(`plugin ${id}: path '${key}' is already reserved by plugin '${holder}'`);
        }
        reservations.set(claim, id);
        if (isParamPath(key)) {
          // Parameterized reservations are method-gated, read-only by
          // default: the URL shape lives inside a WAC-governed pod
          // namespace, and exempting PUT/DELETE would hand the LDP
          // fallthrough an unauthenticated write path.
          const methods = new Set((opts.methods ?? ['GET', 'HEAD', 'OPTIONS'])
            .map((m) => String(m).toUpperCase()));
          ctx.appPathPatterns?.push({ re: compilePathPattern(key), methods });
        } else if (!ctx.appPaths.includes(key)) {
          // Literal reservations behave exactly like an entry prefix:
          // the plugin owns the subtree, every method.
          ctx.appPaths.push(key);
        }
        log.info(`plugin ${id} reserved ${key}`);
      },
      serverInfo() {
        const o = ctx.origin ?? {};
        const addr = fastify.server?.listening ? fastify.server.address() : null;
        const live = addr && typeof addr === 'object' ? addr : null;
        // Once listening, the live bind wins over configured values —
        // listen() may be called with a different host/port than
        // createServer() was given (tests do exactly this).
        const port = live?.port ?? o.port ?? null;
        const rawHost = live?.address ?? o.host;
        // Unspecified binds aren't callable addresses; report the
        // loopback name instead. IPv6 literals need brackets in URLs.
        const host = !rawHost || rawHost === '0.0.0.0' || rawHost === '::' ? 'localhost' : rawHost;
        const protocol = o.ssl ? 'https' : 'http';
        const urlHost = host.includes(':') ? `[${host}]` : host;
        const baseUrl = o.baseUrl || `${protocol}://${urlHost}:${port}`;
        return { baseUrl, protocol, host, port, listening: !!live };
      },
      // Mount a node-style (req, res) handler — a wrapped HTTP app, reverse
      // proxy, or framework adapter — under the plugin's prefix (#583). This
      // bundles the four things every such plugin needs and otherwise
      // rediscovers: the appPaths WAC exemption (already applied above), a
      // scoped pass-through content parser so the wrapped app receives an
      // unconsumed body stream, reply.hijack() so Fastify releases the
      // response, and registration on both the bare prefix and its subtree.
      // Without the scoped parser, Fastify drains the request stream before
      // the handler runs and any body-reading app hangs forever.
      async mountApp(handler, opts = {}) {
        if (typeof handler !== 'function') {
          throw new Error(`plugin ${id}: mountApp(handler) needs a (req, res) function`);
        }
        // Any provided prefix must validate — same rule as entry.prefix: a
        // falsy normalization silently falling back to the entry prefix
        // would mount the app (and WAC-exempt it) somewhere unexpected.
        const secondary = normalizePrefix(opts.prefix);
        if (opts.prefix !== undefined && !secondary) {
          throw new Error(`plugin ${id}: mountApp invalid prefix ${JSON.stringify(opts.prefix)} (must start with '/'; omit to use the entry prefix)`);
        }
        const mountPrefix = secondary || prefix;
        if (!mountPrefix) {
          throw new Error(`plugin ${id}: mountApp needs a prefix (entry.prefix or opts.prefix)`);
        }
        if (mountPrefix !== prefix && !ctx.appPaths.includes(mountPrefix)) {
          ctx.appPaths.push(mountPrefix); // exempt a secondary mount too
        }
        await fastify.register(async (scope) => {
          scope.removeAllContentTypeParsers();
          scope.addContentTypeParser('*', (req, payload, done) => done(null, payload));
          // After hijack() Fastify sends nothing, so a handler bug must not
          // hang the client or become an unhandled rejection (same contract
          // as ws.route below): log, answer 500 if nothing went out yet,
          // else drop the one affected socket.
          const fail = (res, err) => {
            log.error({ err }, `plugin ${id}: mounted app handler failed`);
            if (!res.headersSent && !res.writableEnded) {
              res.statusCode = 500;
              res.end();
            } else {
              res.destroy();
            }
          };
          const wrapped = (request, reply) => {
            reply.hijack();
            try {
              Promise.resolve(handler(request.raw, reply.raw))
                .catch((err) => fail(reply.raw, err));
            } catch (err) {
              fail(reply.raw, err);
            }
          };
          scope.all(mountPrefix, wrapped);
          scope.all(mountPrefix + '/*', wrapped);
        });
      },
      ws: {
        async route(wsPath, handler) {
          if (typeof wsPath !== 'string' || !wsPath.startsWith('/')) {
            throw new Error(`plugin ${id}: ws.route path must start with '/'`);
          }
          if (!fastify.websocketServer) {
            await fastify.register(websocket);
          }
          fastify.get(wsPath, { websocket: true }, (connection, request) => {
            // @fastify/websocket v8 hands a SocketStream; the ws socket is
            // .socket. Later majors hand the socket directly — accept both.
            const socket = connection.socket ?? connection;
            // A plugin bug here must not become an unhandled rejection that
            // takes the host down: log it and close the one affected socket.
            try {
              Promise.resolve(handler(socket, request)).catch((err) => {
                log.error({ err }, `plugin ${id}: ws handler failed`);
                socket.terminate?.();
              });
            } catch (err) {
              log.error({ err }, `plugin ${id}: ws handler failed`);
              socket.terminate?.();
            }
          });
        },
      },
    };

    let result;
    try {
      result = await activate(api);
    } catch (err) {
      throw new Error(`plugin ${id}: activate() failed: ${err.message}`);
    }
    if (result && typeof result.deactivate === 'function') {
      fastify.addHook('onClose', async () => {
        try {
          await result.deactivate();
        } catch (err) {
          log.warn(`plugin ${id}: deactivate() failed: ${err.message}`);
        }
      });
    }
    log.info(`plugin ${id} active${prefix ? ` at ${prefix}` : ''}`);
  }
}
