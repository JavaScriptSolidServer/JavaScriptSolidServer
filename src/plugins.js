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

/** Same normalization appPaths applies: no trailing slash, must be '/x…'. */
export function normalizePrefix(p) {
  if (typeof p !== 'string') return '';
  const trimmed = p.trim().replace(/\/+$/, '');
  return trimmed.startsWith('/') && trimmed.length > 1 ? trimmed : '';
}

/** Directory-safe plugin id: from entry.id or derived from the module spec. */
export function pluginId(spec) {
  const raw = typeof spec.id === 'string' && spec.id
    ? spec.id
    : path.basename(String(spec.module)).replace(/\.[cm]?js$/, '');
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
  for (const entry of entries) {
    const spec = typeof entry === 'string' ? { module: entry } : entry;
    if (!spec || typeof spec.module !== 'string' || !spec.module) {
      throw new Error('plugins: each entry needs a module (import specifier or path)');
    }
    const id = pluginId(spec);

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

    const prefix = normalizePrefix(spec.prefix);
    if (spec.prefix && !prefix) {
      throw new Error(`plugin ${id}: invalid prefix ${JSON.stringify(spec.prefix)} (must start with '/')`);
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
            handler(connection.socket ?? connection, request);
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
