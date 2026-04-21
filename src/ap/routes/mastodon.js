/**
 * Mastodon-compatible API endpoints
 * Allows Mastodon clients (Elk, Phanpy, Ice Cubes) to connect to JSS
 *
 * Step 1: Dynamic client registration + account verification
 * Refs: https://docs.joinmastodon.org/methods/apps/
 *       https://docs.joinmastodon.org/methods/accounts/#verify_credentials
 */

// In-memory client store (replace with persistent storage later)
const clients = new Map()

// Stable instance start time (used for created_at)
const startedAt = new Date().toISOString()

/**
 * Parse request body — handles both JSON and form-urlencoded
 * (JSS uses raw buffer parser for all content types)
 */
function parseBody (request) {
  if (request.body && typeof request.body === 'object' && !Buffer.isBuffer(request.body)) {
    return request.body
  }
  const raw = Buffer.isBuffer(request.body) ? request.body.toString() : String(request.body || '')
  const ct = request.headers['content-type'] || ''
  if (ct.includes('application/json')) {
    try { return JSON.parse(raw) } catch { return {} }
  }
  // Default: parse as form-urlencoded
  return Object.fromEntries(new URLSearchParams(raw))
}

/**
 * POST /api/v1/apps — Dynamic client registration
 * Mastodon clients call this to register before OAuth
 */
export function createAppsHandler () {
  return async (request, reply) => {
    const body = parseBody(request)
    const { client_name, redirect_uris, scopes, website } = body

    if (!client_name || !redirect_uris) {
      return reply.code(422).send({ error: 'client_name and redirect_uris are required' })
    }

    const clientId = crypto.randomUUID()
    const clientSecret = crypto.randomUUID()

    const client = {
      id: clientId,
      name: client_name,
      redirect_uri: redirect_uris,
      client_id: clientId,
      client_secret: clientSecret,
      scopes: scopes || 'read',
      website: website || null
    }

    clients.set(clientId, client)

    return reply.send(client)
  }
}

/**
 * GET /api/v1/accounts/verify_credentials — Who am I?
 * Returns the authenticated user's profile as a Mastodon Account object
 */
export function createVerifyCredentialsHandler (config) {
  return async (request, reply) => {
    const protocol = request.headers['x-forwarded-proto'] || request.protocol
    const host = request.headers['x-forwarded-host'] || request.hostname
    const baseUrl = `${protocol}://${host}`

    const account = {
      id: '1',
      username: config.username,
      acct: config.username,
      display_name: config.displayName,
      note: config.summary ? `<p>${escapeHtml(config.summary)}</p>` : '',
      url: `${baseUrl}/profile/card.jsonld`,
      uri: `${baseUrl}/profile/card.jsonld#me`,
      avatar: `${baseUrl}/profile/avatar.png`,
      header: '',
      locked: false,
      bot: false,
      created_at: startedAt,
      followers_count: 0,
      following_count: 0,
      statuses_count: 0,
      source: {
        privacy: 'public',
        sensitive: false,
        language: 'en',
        note: config.summary || ''
      }
    }

    return reply.send(account)
  }
}

/**
 * GET /api/v1/instance — Instance information
 * Required by most Mastodon clients before login
 */
export function createInstanceHandler (config) {
  return async (request, reply) => {
    const protocol = request.headers['x-forwarded-proto'] || request.protocol
    const host = request.headers['x-forwarded-host'] || request.hostname
    const wsProtocol = protocol === 'https' ? 'wss' : 'ws'

    return reply.send({
      uri: host,
      title: config.displayName || 'JSS',
      description: 'SAND Stack: Solid + ActivityPub + Nostr + DID',
      short_description: 'Solid pod with Mastodon-compatible API',
      version: '4.0.0 (compatible; JSS 0.0.99)',
      urls: {
        streaming_api: `${wsProtocol}://${host}`
      },
      stats: {
        user_count: 1,
        status_count: 0,
        domain_count: 1
      },
      languages: ['en'],
      registrations: false,
      approval_required: false,
      configuration: {
        statuses: { max_characters: 5000 },
        media_attachments: { supported_mime_types: [] }
      }
    })
  }
}

/**
 * Look up a registered client
 */
export function getClient (clientId) {
  return clients.get(clientId) || null
}

function escapeHtml (str) {
  return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;')
}

export default {
  createAppsHandler,
  createVerifyCredentialsHandler,
  createInstanceHandler,
  getClient
}
