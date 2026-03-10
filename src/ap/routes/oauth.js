/**
 * OAuth 2.0 authorize/token flow
 * Shared infrastructure for Mastodon clients, remoteStorage apps, and third-party panes
 *
 * Refs: https://docs.joinmastodon.org/methods/oauth/
 *       https://datatracker.ietf.org/doc/html/rfc6749
 *
 * Related: #158, #159 (Mastodon API), #106 (remoteStorage), #160 (this)
 */

import { getClient } from './mastodon.js'
import { authenticate } from '../../idp/accounts.js'
import { createToken } from '../../auth/token.js'

// Auth codes: code → { clientId, redirectUri, webId, scope, expiresAt }
const authCodes = new Map()

// Clean up expired codes every 60s
setInterval(() => {
  const now = Date.now()
  for (const [code, data] of authCodes) {
    if (data.expiresAt < now) authCodes.delete(code)
  }
}, 60000).unref()

/**
 * Parse request body — handles JSON and form-urlencoded
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
  return Object.fromEntries(new URLSearchParams(raw))
}

/**
 * GET /oauth/authorize — Show login/consent page
 */
export function createAuthorizeHandler () {
  return async (request, reply) => {
    const { client_id, redirect_uri, response_type, scope } = request.query

    if (!client_id || !redirect_uri) {
      return reply.code(400).send({ error: 'Missing client_id or redirect_uri' })
    }

    if (response_type && response_type !== 'code') {
      return reply.code(400).send({ error: 'unsupported_response_type', error_description: 'Only response_type=code is supported' })
    }

    const client = getClient(client_id)
    if (!client) {
      return reply.code(400).send({ error: 'invalid_client', error_description: 'Unknown client_id. Register via POST /api/v1/apps first.' })
    }

    return reply.type('text/html').send(
      loginPage({ clientId: client_id, redirectUri: redirect_uri, scope: scope || 'read', clientName: client.name })
    )
  }
}

/**
 * POST /oauth/authorize — Process login form
 */
export function createAuthorizePostHandler () {
  return async (request, reply) => {
    const body = parseBody(request)
    const { username, password, client_id, redirect_uri, scope } = body

    if (!username || !password) {
      return reply.type('text/html').send(
        loginPage({ clientId: client_id, redirectUri: redirect_uri, scope, error: 'Username and password are required' })
      )
    }

    const account = await authenticate(username, password)
    if (!account) {
      return reply.type('text/html').send(
        loginPage({ clientId: client_id, redirectUri: redirect_uri, scope, error: 'Invalid username or password' })
      )
    }

    // Generate one-time auth code (10 min TTL)
    const code = crypto.randomUUID()
    authCodes.set(code, {
      clientId: client_id,
      redirectUri: redirect_uri,
      webId: account.webId,
      scope: scope || 'read',
      expiresAt: Date.now() + 600_000
    })

    // Redirect back to client with code
    const url = new URL(redirect_uri)
    url.searchParams.set('code', code)
    return reply.redirect(url.toString())
  }
}

/**
 * POST /oauth/token — Exchange auth code for Bearer token
 */
export function createTokenHandler () {
  return async (request, reply) => {
    const body = parseBody(request)
    const { grant_type, code, client_id, client_secret, redirect_uri } = body

    if (grant_type !== 'authorization_code') {
      return reply.code(400).send({ error: 'unsupported_grant_type' })
    }

    if (!code) {
      return reply.code(400).send({ error: 'invalid_request', error_description: 'Missing code' })
    }

    // Look up and validate auth code
    const authCode = authCodes.get(code)
    if (!authCode || authCode.expiresAt < Date.now()) {
      authCodes.delete(code)
      return reply.code(400).send({ error: 'invalid_grant', error_description: 'Code expired or invalid' })
    }

    if (authCode.clientId !== client_id) {
      return reply.code(400).send({ error: 'invalid_client' })
    }

    if (authCode.redirectUri !== redirect_uri) {
      return reply.code(400).send({ error: 'invalid_grant', error_description: 'redirect_uri mismatch' })
    }

    // Consume code (one-time use)
    authCodes.delete(code)

    // Generate Bearer token using existing token infrastructure
    const accessToken = createToken(authCode.webId)

    return reply.send({
      access_token: accessToken,
      token_type: 'Bearer',
      scope: authCode.scope,
      created_at: Math.floor(Date.now() / 1000)
    })
  }
}

/**
 * Minimal login page HTML
 */
function loginPage ({ clientId, redirectUri, scope, clientName, error }) {
  const escapedError = error ? escapeHtml(error) : ''
  const escapedName = escapeHtml(clientName || clientId || 'Unknown app')

  return `<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Authorize ${escapedName}</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: -apple-system, BlinkMacSystemFont, system-ui, sans-serif; background: #f5f5f5; display: flex; justify-content: center; align-items: center; min-height: 100vh; }
    .card { background: white; border-radius: 12px; padding: 2rem; max-width: 400px; width: 90%; box-shadow: 0 2px 8px rgba(0,0,0,0.1); }
    h1 { font-size: 1.25rem; margin-bottom: 0.5rem; }
    .subtitle { color: #666; margin-bottom: 1.5rem; font-size: 0.9rem; }
    .scope { background: #f0f0f0; padding: 0.5rem 0.75rem; border-radius: 6px; margin-bottom: 1.5rem; font-size: 0.85rem; color: #444; }
    label { display: block; font-size: 0.85rem; font-weight: 500; margin-bottom: 0.25rem; color: #333; }
    input[type="text"], input[type="password"] { width: 100%; padding: 0.6rem; border: 1px solid #ddd; border-radius: 6px; font-size: 1rem; margin-bottom: 1rem; }
    input:focus { outline: none; border-color: #4a9eff; box-shadow: 0 0 0 2px rgba(74,158,255,0.2); }
    button { width: 100%; padding: 0.7rem; background: #4a9eff; color: white; border: none; border-radius: 6px; font-size: 1rem; font-weight: 500; cursor: pointer; }
    button:hover { background: #3a8eef; }
    .error { background: #fee; color: #c00; padding: 0.6rem; border-radius: 6px; margin-bottom: 1rem; font-size: 0.85rem; }
  </style>
</head>
<body>
  <div class="card">
    <h1>Authorize</h1>
    <p class="subtitle"><strong>${escapedName}</strong> wants access to your account</p>
    <div class="scope">Scope: ${escapeHtml(scope || 'read')}</div>
    ${escapedError ? `<div class="error">${escapedError}</div>` : ''}
    <form method="POST" action="/oauth/authorize">
      <input type="hidden" name="client_id" value="${escapeHtml(clientId || '')}">
      <input type="hidden" name="redirect_uri" value="${escapeHtml(redirectUri || '')}">
      <input type="hidden" name="scope" value="${escapeHtml(scope || 'read')}">
      <label for="username">Username</label>
      <input type="text" id="username" name="username" required autocomplete="username">
      <label for="password">Password</label>
      <input type="password" id="password" name="password" required autocomplete="current-password">
      <button type="submit">Authorize</button>
    </form>
  </div>
</body>
</html>`
}

function escapeHtml (str) {
  return String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;')
}

export default {
  createAuthorizeHandler,
  createAuthorizePostHandler,
  createTokenHandler
}
