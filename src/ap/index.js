/**
 * ActivityPub Plugin for JSS
 * Adds federation support via the ActivityPub protocol
 */

import { webfinger } from 'microfed'
import { loadOrCreateKeypair, getKeyId } from './keys.js'
import { initStore } from './store.js'
import { createInboxHandler } from './routes/inbox.js'
import { createOutboxHandler } from './routes/outbox.js'
import { createCollectionsHandler } from './routes/collections.js'
import { createActorHandler } from './routes/actor.js'

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
  // Initialize storage and keypair
  const keypair = loadOrCreateKeypair()
  initStore()

  // Store config for handlers
  const config = {
    keypair,
    username: options.username || 'me',
    displayName: options.displayName || options.username || 'Anonymous',
    summary: options.summary || '',
    nostrPubkey: options.nostrPubkey || null
  }

  // Decorate fastify with AP config
  fastify.decorate('apConfig', config)

  // Helper to build actor ID from request
  const getActorId = (request) => {
    const protocol = request.headers['x-forwarded-proto'] || request.protocol
    const host = request.headers['x-forwarded-host'] || request.hostname
    return `${protocol}://${host}/profile/card#me`
  }

  // Helper to get base URL
  const getBaseUrl = (request) => {
    const protocol = request.headers['x-forwarded-proto'] || request.protocol
    const host = request.headers['x-forwarded-host'] || request.hostname
    return `${protocol}://${host}`
  }

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

    // Check if this is our user
    const host = request.headers['x-forwarded-host'] || request.hostname
    if (parsed.domain !== host) {
      return reply.code(404).send({ error: 'Not found' })
    }

    // For now, accept any username and map to /profile/card#me
    // In multi-user mode, we'd look up the user
    const baseUrl = getBaseUrl(request)
    const actorUrl = `${baseUrl}/profile/card#me`
    const profileUrl = `${baseUrl}/profile/card`

    const response = webfinger.createResponse(
      `${parsed.username}@${parsed.domain}`,
      actorUrl,
      { profileUrl }
    )

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
          version: '0.0.62',
          repository: 'https://github.com/JavaScriptSolidServer/JavaScriptSolidServer'
        },
        protocols: ['activitypub', 'solid'],
        services: { inbound: [], outbound: [] },
        usage: {
          users: { total: 1, activeMonth: 1, activeHalfyear: 1 },
          localPosts: getPostCount()
        },
        openRegistrations: true,
        metadata: {
          nodeName: config.displayName,
          nodeDescription: 'SAND Stack: Solid + ActivityPub + Nostr + DID'
        }
      })
  })

  // Actor endpoint - handle AP content negotiation for /profile/card
  const actorHandler = createActorHandler(config, keypair)

  // Decorate request to track AP handling
  fastify.decorateRequest('apHandled', false)

  // Register dedicated GET route for /profile/card with AP content negotiation
  // This needs to run BEFORE the wildcard LDP routes
  fastify.get('/profile/card', {
    // Run this handler first, before wildcard routes
    preHandler: async (request, reply) => {
      const accept = request.headers.accept || ''
      const wantsAP = accept.includes('activity+json') ||
                      accept.includes('ld+json; profile="https://www.w3.org/ns/activitystreams"')

      if (wantsAP) {
        const actor = actorHandler(request)
        request.apHandled = true
        return reply
          .header('Content-Type', 'application/activity+json')
          .send(actor)
      }
      // If not AP, skip and let the request continue (but this route won't have a main handler)
      // We return early - the request will 404 on this route but get caught by wildcard
    }
  }, async (request, reply) => {
    // This handler won't be reached if AP was handled
    // For non-AP requests, we need to pass through to LDP
    // But we can't easily do that here, so we'll handle it differently
    reply.callNotFound()
  })

  // Inbox endpoint
  const inboxHandler = createInboxHandler(config, keypair)
  fastify.post('/inbox', inboxHandler)
  fastify.post('/profile/card/inbox', inboxHandler)

  // Outbox endpoint
  const outboxHandler = createOutboxHandler(config, keypair)
  fastify.get('/profile/card/outbox', outboxHandler)

  // Followers/Following collections
  const collectionsHandler = createCollectionsHandler(config)
  fastify.get('/profile/card/followers', (req, reply) => collectionsHandler(req, reply, 'followers'))
  fastify.get('/profile/card/following', (req, reply) => collectionsHandler(req, reply, 'following'))
}

export default activityPubPlugin
