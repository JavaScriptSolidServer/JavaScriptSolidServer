/**
 * ActivityPub Plugin for JSS
 * Adds federation support via the ActivityPub protocol
 */

import { webfinger } from 'microfed'
import websocket from '@fastify/websocket'
import { getWebIdFromRequestAsync } from '../auth/token.js'
import { loadOrCreateKeypair, getKeyId, getDefaultKeyPath } from './keys.js'
import { initStore } from './store.js'
import { createInboxHandler } from './routes/inbox.js'
import { createOutboxHandler, createOutboxPostHandler, createPostObjectHandler } from './routes/outbox.js'
import { createCollectionsHandler } from './routes/collections.js'
import { createActorHandler } from './routes/actor.js'
import { createAppsHandler, createVerifyCredentialsHandler, createUpdateCredentialsHandler, createAccountLookupHandler, createAccountsSearchHandler, createPreferencesHandler, createListsHandler, createAccountListsHandler, createRelationshipsHandler, createInstanceHandler, createInstanceV2Handler, createSearchHandler, createTimelinesHomeHandler, createPostStatusHandler, createGetStatusHandler, createFavouriteStatusHandler, createUpdateStatusHandler, createGetAccountHandler, createGetAccountStatusesHandler, createFollowAccountHandler, createGetNotificationsHandler, getProfileMediaBuffer } from './routes/mastodon.js'
import { createAuthorizeHandler, createAuthorizePostHandler, createTokenHandler } from './routes/oauth.js'

// Shared state for actor handler (accessed by server.js)
let sharedActorHandler = null
export function getActorHandler() { return sharedActorHandler }

/**
 * ActivityPub Fastify plugin
 * @param {FastifyInstance} fastify
 * @param {object} options
 * @param {string} options.username - Default username for single-user mode
 * @param {string} options.displayName - Display name
 * @param {string} options.summary - Bio/description
 * @param {string} options.nostrPubkey - Nostr public key (hex) for identity linking
 */
export async function activityPubPlugin(fastify, options = {}) {
  const defaultUsername = options.username || 'me'
  await initStore(undefined, defaultUsername)

  // Register WebSocket support for Mastodon streaming API if not already present.
  if (!fastify.websocketServer) {
    await fastify.register(websocket)
  }

  const subdomains = options.subdomains || false
  const baseDomain = options.baseDomain || null

  // Single-user fallback config (used when not in subdomain mode)
  const defaultConfig = {
    username: defaultUsername,
    displayName: options.displayName || defaultUsername,
    summary: options.summary || '',
    nostrPubkey: options.nostrPubkey || null,
    subdomains,
    baseDomain
  }

  // Keypair cache: username → keypair (loaded on demand)
  const keypairCache = new Map()

  const getKeypairForUser = (username) => {
    if (!keypairCache.has(username)) {
      keypairCache.set(username, loadOrCreateKeypair(getDefaultKeyPath(username)))
    }
    return keypairCache.get(username)
  }

  // In single-user mode (no subdomains) pre-load the keypair now.
  // In subdomain mode, keypairs are created on first request per user — no eager load.
  if (!subdomains) {
    defaultConfig.keypair = getKeypairForUser(defaultUsername)
  }

  const getRequestHost = (request) => request.headers['x-forwarded-host'] || request.hostname

  const getUsernameFromWebId = (webId) => {
    if (!webId) return null
    try {
      const url = new URL(webId)
      const hostname = url.hostname
      if (hostname === 'localhost' || /^(127\.|192\.168\.|10\.|::1)/.test(hostname)) {
        const seg = url.pathname.split('/').filter(Boolean)[0]
        return seg || null
      }
      const parts = hostname.split('.')
      return parts.length >= 2 ? parts[0] : (parts[0] || null)
    } catch {
      return null
    }
  }

  /**
   * In subdomain mode, derive the active user from the request subdomain.
   * e.g. alice.pivot-test.local → username "alice"
   * Any subdomain user is automatically a valid AP actor.
   * Falls back to the default (single-user) config.
   */
  const getUserConfig = (request) => {
    if (subdomains && baseDomain) {
      const host = getRequestHost(request)
      const baseDomainHost = baseDomain.includes(':') ? baseDomain.split(':')[0] : baseDomain
      const hostNoPort = host.includes(':') ? host.split(':')[0] : host
      const subdomain = hostNoPort.endsWith('.' + baseDomainHost)
        ? hostNoPort.slice(0, -(baseDomainHost.length + 1))
        : null
      if (subdomain) {
        const keypair = getKeypairForUser(subdomain)
        return {
          keypair,
          username: subdomain,
          displayName: subdomain,
          summary: '',
          nostrPubkey: null,
          subdomains,
          baseDomain
        }
      }
    }
    return defaultConfig
  }

  // Decorate fastify with AP config (default user, for compat)
  fastify.decorate('apConfig', defaultConfig)

  // In subdomain mode, the canonical AP actor host is the AP username subdomain.
  // Example: --ap-username alice + --base-domain pivot-test.local:4443
  // -> actor/profile URLs use alice.pivot-test.local:4443.
  const getActorHost = (request, userConfig) => {
    const uc = userConfig || getUserConfig(request)
    if (uc.subdomains && uc.baseDomain) {
      return `${uc.username}.${uc.baseDomain}`
    }
    return getRequestHost(request)
  }

  // Helper to detect protocol from proxy headers
  const getProtocol = (request) => {
    // Check X-Forwarded-Proto first
    let protocol = request.headers['x-forwarded-proto']
    if (!protocol) {
      // Cloudflare uses cf-visitor: {"scheme":"https"}
      const cfVisitor = request.headers['cf-visitor']
      if (cfVisitor) {
        try {
          const parsed = JSON.parse(cfVisitor)
          protocol = parsed.scheme
        } catch { /* ignore */ }
      }
    }
    // If still no protocol and hostname looks like a public domain, assume https
    const host = getRequestHost(request)
    const hostNoPort = host.includes(':') ? host.split(':')[0] : host
    if (!protocol && hostNoPort && !hostNoPort.match(/^(localhost|127\.|192\.168\.|10\.)/)) {
      protocol = 'https'
    }
    return protocol || request.protocol
  }

  // Helper to build actor ID from request (optionally for a specific user config)
  const getActorId = (request, userConfig) => {
    const protocol = getProtocol(request)
    const host = getActorHost(request, userConfig)
    return `${protocol}://${host}/profile/card.jsonld#me`
  }

  // Helper to get base URL
  const getBaseUrl = (request, actor = false, userConfig) => {
    const protocol = getProtocol(request)
    const host = actor ? getActorHost(request, userConfig) : getRequestHost(request)
    return `${protocol}://${host}`
  }

  // host-meta discovery (used by Mastodon clients like Phanpy)
  fastify.get('/.well-known/host-meta', async (request, reply) => {
    const baseUrl = getBaseUrl(request)
    const xml = `<?xml version="1.0" encoding="UTF-8"?>\n<XRD xmlns="http://docs.oasis-open.org/ns/xri/xrd-1.0">\n  <Link rel="lrdd" type="application/jrd+json" template="${baseUrl}/.well-known/webfinger?resource={uri}"/>\n</XRD>`

    return reply
      .header('Content-Type', 'application/xrd+xml; charset=utf-8')
      .header('Access-Control-Allow-Origin', '*')
      .send(xml)
  })

  fastify.get('/.well-known/host-meta.json', async (request, reply) => {
    const baseUrl = getBaseUrl(request)
    return reply
      .header('Content-Type', 'application/json')
      .header('Access-Control-Allow-Origin', '*')
      .send({
        links: [
          {
            rel: 'lrdd',
            type: 'application/jrd+json',
            template: `${baseUrl}/.well-known/webfinger?resource={uri}`
          }
        ]
      })
  })

  // OAuth 2.0 Authorization Server Metadata (RFC 8414)
  // Used by Mastodon-compatible clients during discovery.
  fastify.get('/.well-known/oauth-authorization-server', async (request, reply) => {
    const baseUrl = getBaseUrl(request)
    return reply
      .header('Content-Type', 'application/json')
      .header('Access-Control-Allow-Origin', '*')
      .send({
        issuer: baseUrl,
        authorization_endpoint: `${baseUrl}/oauth/authorize`,
        token_endpoint: `${baseUrl}/oauth/token`,
        registration_endpoint: `${baseUrl}/api/v1/apps`,
        response_types_supported: ['code'],
        grant_types_supported: ['authorization_code', 'refresh_token'],
        token_endpoint_auth_methods_supported: ['none', 'client_secret_post'],
        code_challenge_methods_supported: ['S256']
      })
  })

  // WebFinger endpoint
  fastify.get('/.well-known/webfinger', async (request, reply) => {
    const resource = request.query.resource
    if (!resource) {
      return reply.code(400).send({ error: 'Missing resource parameter' })
    }

    const parsed = webfinger.parseResource(resource)
    if (!parsed) {
      return reply.code(400).send({ error: 'Invalid resource format' })
    }

    // Check if this is our domain
    const host = getRequestHost(request)
    if (parsed.domain !== host) {
      return reply.code(404).send({ error: 'Not found' })
    }

    // In subdomain mode, any username on this domain is a valid AP actor.
    // In single-user mode, only the configured username is accepted.
    const username = parsed.username
    if (!subdomains && username !== defaultConfig.username) {
      return reply.code(404).send({ error: 'User not found' })
    }

    // Build a minimal config for this user to resolve their actor host
    const matchedUser = subdomains
      ? { username, subdomains, baseDomain }
      : defaultConfig

    const baseUrl = getBaseUrl(request)
    const actorBaseUrl = getBaseUrl(request, true, matchedUser)
    const actorUrl = `${actorBaseUrl}/profile/card.jsonld#me`
    const profileUrl = `${actorBaseUrl}/profile/card.jsonld`

    const response = webfinger.createResponse(
      `${username}@${parsed.domain}`,
      actorUrl,
      { profileUrl }
    )

    // Add remoteStorage link relation
    response.links.push({
      rel: 'http://tools.ietf.org/id/draft-dejong-remotestorage',
      href: `${baseUrl}/storage/${username}/`,
      properties: {
        'http://remotestorage.io/spec/version': 'draft-dejong-remotestorage-22',
        'http://tools.ietf.org/html/rfc6749#section-4.2': `${baseUrl}/oauth/authorize`,
        'http://tools.ietf.org/html/rfc6750#section-2.3': 'Bearer'
      }
    })

    return reply
      .header('Content-Type', 'application/jrd+json')
      .header('Access-Control-Allow-Origin', '*')
      .send(response)
  })

  // NodeInfo discovery (for Mastodon compatibility)
  fastify.get('/.well-known/nodeinfo', async (request, reply) => {
    const baseUrl = getBaseUrl(request)
    return reply
      .header('Content-Type', 'application/json')
      .send({
        links: [
          {
            rel: 'http://nodeinfo.diaspora.software/ns/schema/2.1',
            href: `${baseUrl}/.well-known/nodeinfo/2.1`
          }
        ]
      })
  })

  fastify.get('/.well-known/nodeinfo/2.1', async (request, reply) => {
    const { getPostCount } = await import('./store.js')
    return reply
      .header('Content-Type', 'application/json; profile="http://nodeinfo.diaspora.software/ns/schema/2.1#"')
      .send({
        version: '2.1',
        software: {
          name: 'jss',
          version: '0.0.99',
          repository: 'https://github.com/JavaScriptSolidServer/JavaScriptSolidServer'
        },
        protocols: ['activitypub', 'solid'],
        services: { inbound: [], outbound: [] },
        usage: {
          users: { total: 1, activeMonth: 1, activeHalfyear: 1 },
          localPosts: getPostCount(defaultConfig.username)
        },
        openRegistrations: true,
        metadata: {
          nodeName: config.displayName,
          nodeDescription: 'SAND Stack: Solid + ActivityPub + Nostr + DID'
        }
      })
  })

  // Actor endpoint - build a dispatcher that resolves the right user config per request
  // In subdomain mode each user's subdomain routes here; in single-host mode use primary.
  const actorHandlerDispatch = (request, reply) => {
    const uc = getUserConfig(request)
    return createActorHandler(uc, uc.keypair)(request, reply)
  }

  // Store actorHandler dispatcher in shared state for use by server-level hook
  sharedActorHandler = actorHandlerDispatch

  // Shared inbox (base domain) — use default config
  fastify.post('/inbox', createInboxHandler(defaultConfig, getKeypairForUser(defaultUsername)))

  // Per-user inbox/outbox/collections — same route path, resolved by subdomain
  const inboxDispatch = (request, reply) => {
    const uc = getUserConfig(request)
    return createInboxHandler(uc, uc.keypair)(request, reply)
  }
  const outboxDispatch = (request, reply) => {
    const uc = getUserConfig(request)
    return createOutboxHandler(uc, uc.keypair)(request, reply)
  }
  const outboxPostDispatch = (request, reply) => {
    const uc = getUserConfig(request)
    return createOutboxPostHandler(uc, uc.keypair)(request, reply)
  }
  const postObjectDispatch = (request, reply) => {
    const uc = getUserConfig(request)
    return createPostObjectHandler(uc)(request, reply)
  }
  const collectionsDispatch = (request, reply, type) => {
    const uc = getUserConfig(request)
    return createCollectionsHandler(uc)(request, reply, type)
  }

  fastify.post('/profile/card.jsonld/inbox', inboxDispatch)
  fastify.get('/profile/card.jsonld/outbox', outboxDispatch)
  fastify.post('/profile/card.jsonld/outbox', outboxPostDispatch)
  fastify.get('/posts/:id', postObjectDispatch)
  fastify.get('/profile/avatar.png', async (request, reply) => {
    const uc = getUserConfig(request)
    let mediaUsername = uc.username
    if (!mediaUsername || mediaUsername === 'me') {
      const auth = await getWebIdFromRequestAsync(request)
      mediaUsername = getUsernameFromWebId(auth.webId) || mediaUsername
    }
    const media = getProfileMediaBuffer(mediaUsername, 'avatar')
    if (media) {
      return reply.header('Content-Type', media.contentType).send(media.buffer)
    }
    const png = Buffer.from('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8Xw8AAoMBgNfQh8EAAAAASUVORK5CYII=', 'base64')
    return reply.header('Content-Type', 'image/png').send(png)
  })
  fastify.get('/profile/header.png', async (request, reply) => {
    const uc = getUserConfig(request)
    let mediaUsername = uc.username
    if (!mediaUsername || mediaUsername === 'me') {
      const auth = await getWebIdFromRequestAsync(request)
      mediaUsername = getUsernameFromWebId(auth.webId) || mediaUsername
    }
    const media = getProfileMediaBuffer(mediaUsername, 'header')
    if (media) {
      return reply.header('Content-Type', media.contentType).send(media.buffer)
    }
    const png = Buffer.from('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8Xw8AAoMBgNfQh8EAAAAASUVORK5CYII=', 'base64')
    return reply.header('Content-Type', 'image/png').send(png)
  })
  fastify.get('/profile/card.jsonld/followers', (req, reply) => collectionsDispatch(req, reply, 'followers'))
  fastify.get('/profile/card.jsonld/following', (req, reply) => collectionsDispatch(req, reply, 'following'))

  // Mastodon-compatible API endpoints
  const streamingDispatch = (connection, request) => {
    // Minimal compatibility endpoint for Mastodon clients (Phanpy/Elk):
    // accept connection and keep it alive even when no events are emitted yet.
    const ping = setInterval(() => {
      if (connection.socket.readyState === 1) {
        try {
          connection.socket.ping()
        } catch {
          clearInterval(ping)
        }
      }
    }, 30000)

    connection.socket.on('close', () => clearInterval(ping))
    connection.socket.on('error', () => clearInterval(ping))
  }

  fastify.get('/api/v1/streaming', { websocket: true }, streamingDispatch)
  fastify.get('/api/v1/streaming/', { websocket: true }, streamingDispatch)

  fastify.post('/api/v1/apps', createAppsHandler())
  fastify.get('/api/v1/accounts/verify_credentials', createVerifyCredentialsHandler(getUserConfig))
  fastify.patch('/api/v1/accounts/update_credentials', createUpdateCredentialsHandler())
  fastify.post('/api/v1/accounts/update_credentials', createUpdateCredentialsHandler())
  fastify.get('/api/v1/accounts/lookup', createAccountLookupHandler())
  fastify.get('/api/v1/accounts/search', createAccountsSearchHandler())
  fastify.get('/api/v1/preferences', createPreferencesHandler())
  fastify.get('/api/v1/lists', createListsHandler())
  fastify.get('/api/v1/accounts/relationships', createRelationshipsHandler())
  fastify.get('/api/v1/instance', createInstanceHandler())
  fastify.get('/api/v2/instance', createInstanceV2Handler())
  fastify.get('/api/v2/search', createSearchHandler())
  fastify.get('/api/v1/timelines/home', createTimelinesHomeHandler())
  fastify.post('/api/v1/statuses', createPostStatusHandler())
  fastify.get('/api/v1/statuses/:id', createGetStatusHandler())
  fastify.get('/api/v1/statuses/:id/source', createGetStatusHandler())
  fastify.get('/api/v1/statuses/:id/history', createGetStatusHandler())
  fastify.get('/api/v1/statuses/*', createGetStatusHandler())
  fastify.post('/api/v1/statuses/:id/favourite', createFavouriteStatusHandler(getUserConfig))
  fastify.post('/api/v1/statuses/*', createFavouriteStatusHandler(getUserConfig))
  fastify.put('/api/v1/statuses/:id', createUpdateStatusHandler())
  fastify.put('/api/v1/statuses/*', createUpdateStatusHandler())
  fastify.get('/api/v1/accounts/:id', createGetAccountHandler())
  fastify.get('/api/v1/accounts/:id/lists', createAccountListsHandler())
  fastify.get('/api/v1/accounts/:id/statuses', createGetAccountStatusesHandler())
  fastify.post('/api/v1/accounts/:id/follow', createFollowAccountHandler(getUserConfig))
  fastify.get('/api/v1/notifications', createGetNotificationsHandler(getUserConfig))

  // OAuth 2.0 authorize/token flow (Mastodon clients, remoteStorage, third-party panes)
  fastify.get('/oauth/authorize', createAuthorizeHandler())
  fastify.post('/oauth/authorize', {
    config: {
      rateLimit: {
        max: 10,
        timeWindow: '1 minute',
        keyGenerator: (request) => request.ip
      }
    }
  }, createAuthorizePostHandler())
  fastify.post('/oauth/token', {
    config: {
      rateLimit: {
        max: 10,
        timeWindow: '1 minute',
        keyGenerator: (request) => request.ip
      }
    }
  }, createTokenHandler())
}

export default activityPubPlugin
