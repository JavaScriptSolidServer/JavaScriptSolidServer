/**
 * Mastodon-compatible API endpoints
 * Allows Mastodon clients (Elk, Phanpy, Ice Cubes) to connect to JSS
 *
 * Step 1: Dynamic client registration + account verification
 * Refs: https://docs.joinmastodon.org/methods/apps/
 *       https://docs.joinmastodon.org/methods/accounts/#verify_credentials
 */

import { createSign, randomUUID } from 'crypto'
import { existsSync, mkdirSync, readFileSync, readdirSync, unlinkSync, writeFileSync } from 'fs'
import { dirname, join } from 'path'
import { Agent } from 'undici'
import { getWebIdFromRequestAsync } from '../../auth/token.js'
import { safeFetch } from '../../utils/ssrf.js'
import {
  getPosts,
  getPost,
  getPostById,
  updatePost,
  getFollowers,
  getFollowing,
  getFollowerCount,
  getFollowingCount,
  addFollowing,
  addFollower,
  acceptFollowing,
  cacheActor,
  getCachedActor
} from '../store.js'

// Allow self-signed certs when delivering activities to local/dev servers
const insecureAgent = new Agent({ connect: { rejectUnauthorized: false } })

/**
 * Send a signed ActivityPub activity to a remote inbox
 */
async function sendSignedActivity (activity, inboxUrl, actorId, keypair, log) {
  const body = JSON.stringify(activity)
  const url = new URL(inboxUrl)
  const date = new Date().toUTCString()
  const digest = `SHA-256=${Buffer.from(
    await crypto.subtle.digest('SHA-256', new TextEncoder().encode(body))
  ).toString('base64')}`
  const signingString = `(request-target): post ${url.pathname}\nhost: ${url.host}\ndate: ${date}\ndigest: ${digest}`
  const signer = createSign('RSA-SHA256')
  signer.update(signingString)
  const signature = signer.sign(keypair.privateKey, 'base64')
  const keyId = `${actorId}#main-key`
  const signatureHeader = `keyId="${keyId}",algorithm="rsa-sha256",headers="(request-target) host date digest",signature="${signature}"`

  try {
    const res = await fetch(inboxUrl, {
      method: 'POST',
      dispatcher: insecureAgent,
      headers: {
        'Content-Type': 'application/activity+json',
        'Accept': 'application/activity+json',
        'Date': date,
        'Digest': digest,
        'Signature': signatureHeader
      },
      body
    })
    if (log) log.info(`Sent ${activity.type} to ${inboxUrl} — ${res.status}`)
    return res.status
  } catch (err) {
    if (log) log.error(`Failed to send ${activity.type} to ${inboxUrl}: ${err.message}`)
    return null
  }
}

// In-memory client store (replace with persistent storage later)
const clients = new Map()
let clientsLoaded = false

// Per-account profile overrides (display_name, note) persisted to disk
const profileOverrides = new Map()
const loadedProfiles = new Set()

function getClientsFilePath () {
  const root = process.env.DATA_ROOT || './data'
  return join(root, '.idp', 'ap', 'oauth-clients.json')
}

function ensureClientsLoaded () {
  if (clientsLoaded) return
  clientsLoaded = true

  const filePath = getClientsFilePath()
  try {
    if (!existsSync(filePath)) return
    const raw = readFileSync(filePath, 'utf8')
    const list = JSON.parse(raw)
    if (Array.isArray(list)) {
      for (const c of list) {
        if (c?.client_id) clients.set(c.client_id, c)
      }
    }
  } catch {
    // Ignore malformed/missing file and continue with empty registry
  }
}

function persistClients () {
  const filePath = getClientsFilePath()
  try {
    mkdirSync(dirname(filePath), { recursive: true })
    writeFileSync(filePath, JSON.stringify(Array.from(clients.values()), null, 2), 'utf8')
  } catch {
    // If persistence fails, keep in-memory behavior rather than failing requests
  }
}

function getPodApDir (username) {
  const root = process.env.DATA_ROOT || './data'
  return join(root, username, '.ap')
}

function getProfilesFilePath (username) {
  return join(getPodApDir(username), 'profile-overrides.json')
}

function ensureProfileLoaded (username) {
  if (loadedProfiles.has(username)) return
  loadedProfiles.add(username)

  const filePath = getProfilesFilePath(username)
  try {
    if (!existsSync(filePath)) return
    const raw = readFileSync(filePath, 'utf8')
    const data = JSON.parse(raw)
    if (data && typeof data === 'object') profileOverrides.set(username, data)
  } catch {
    // Ignore malformed/missing file and continue with defaults
  }
}

function persistProfile (username) {
  const filePath = getProfilesFilePath(username)
  try {
    mkdirSync(dirname(filePath), { recursive: true })
    writeFileSync(filePath, JSON.stringify(profileOverrides.get(username) || {}, null, 2), 'utf8')
  } catch {
    // Keep server functional even if persistence fails
  }
}

function getProfileOverride (username) {
  ensureProfileLoaded(username)
  return profileOverrides.get(username) || null
}

function getProfileMediaDir (username) {
  return join(getPodApDir(username), 'profile-media')
}

function getProfileMediaPath (username, kind, ext) {
  return join(getProfileMediaDir(username), `${kind}.${ext}`)
}

function cleanupProfileMedia (username, kind) {
  const dir = getProfileMediaDir(username)
  if (!existsSync(dir)) return
  for (const file of readdirSync(dir)) {
    if (file.startsWith(`${kind}.`)) {
      try { unlinkSync(join(dir, file)) } catch {}
    }
  }
}

function getProfileMediaPart (request, fieldName) {
  const ct = request.headers['content-type'] || ''
  const boundaryMatch = ct.match(/boundary=(?:"([^"]+)"|([^;]+))/i)
  const boundary = boundaryMatch?.[1] || boundaryMatch?.[2]
  if (!boundary) return null

  const bodyBuffer = Buffer.isBuffer(request.body)
    ? request.body
    : Buffer.from(String(request.body || ''), 'utf8')

  // latin1 keeps 1-byte index mapping between string and buffer offsets.
  const raw = bodyBuffer.toString('latin1')
  const boundaryToken = `--${boundary}`
  let pos = raw.indexOf(boundaryToken)

  while (pos !== -1) {
    let partStart = pos + boundaryToken.length
    if (raw.slice(partStart, partStart + 2) === '--') break
    if (raw.slice(partStart, partStart + 2) === '\r\n') partStart += 2

    const headerEnd = raw.indexOf('\r\n\r\n', partStart)
    if (headerEnd === -1) break

    const headers = raw.slice(partStart, headerEnd)
    const contentStart = headerEnd + 4
    const nextBoundary = raw.indexOf(`\r\n${boundaryToken}`, contentStart)
    if (nextBoundary === -1) break

    const disposition = headers.split('\r\n').find(h => /^content-disposition:/i.test(h)) || ''
    const nameMatch = disposition.match(/name="([^"]+)"/i)
    const filenameMatch = disposition.match(/filename="([^"]*)"/i)
    const contentTypeMatch = headers.match(/content-type:\s*([^\r\n]+)/i)

    const name = nameMatch?.[1]
    const filename = filenameMatch?.[1] || ''
    const contentType = (contentTypeMatch?.[1] || '').trim().toLowerCase()

    if (name === fieldName && filename) {
      const buffer = bodyBuffer.subarray(contentStart, nextBoundary)
      return { filename, contentType, buffer }
    }

    pos = nextBoundary + 2
  }

  // Fallback parser path for client variations in multipart layout.
  try {
    const escapedBoundary = boundary.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
    const re = new RegExp(
      `name="${fieldName}"; filename="([^"]*)"[\\s\\S]*?Content-Type:\\s*([^\\r\\n]+)\\r\\n\\r\\n([\\s\\S]*?)\\r\\n--${escapedBoundary}`,
      'i'
    )
    const match = raw.match(re)
    if (match && match[1]) {
      return {
        filename: match[1],
        contentType: (match[2] || '').trim().toLowerCase(),
        buffer: Buffer.from(match[3] || '', 'latin1')
      }
    }
  } catch {
    // Ignore fallback parse errors
  }

  return null
}

function getAnyProfileMediaPart (request, preferredFieldNames = []) {
  for (const name of preferredFieldNames) {
    const part = getProfileMediaPart(request, name)
    if (part) return part
  }

  // Last-resort: pick the first file-like multipart section.
  const ct = request.headers['content-type'] || ''
  const boundaryMatch = ct.match(/boundary=(?:"([^"]+)"|([^;]+))/i)
  const boundary = boundaryMatch?.[1] || boundaryMatch?.[2]
  if (!boundary) return null

  const bodyBuffer = Buffer.isBuffer(request.body)
    ? request.body
    : Buffer.from(String(request.body || ''), 'utf8')
  const raw = bodyBuffer.toString('latin1')
  const escapedBoundary = boundary.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')

  try {
    const re = new RegExp(
      `name="([^"]+)"; filename="([^"]*)"[\\s\\S]*?Content-Type:\\s*([^\\r\\n]+)\\r\\n\\r\\n([\\s\\S]*?)\\r\\n--${escapedBoundary}`,
      'i'
    )
    const match = raw.match(re)
    if (match && match[2]) {
      return {
        filename: match[2],
        contentType: (match[3] || '').trim().toLowerCase(),
        buffer: Buffer.from(match[4] || '', 'latin1')
      }
    }
  } catch {
    // ignore parse fallback errors
  }

  return null
}

function saveProfileMedia (username, kind, filePart) {
  if (!filePart || !filePart.buffer || filePart.buffer.length === 0) return null

  const typeToExt = {
    'image/jpeg': 'jpg',
    'image/jpg': 'jpg',
    'image/png': 'png',
    'image/webp': 'webp',
    'image/gif': 'gif'
  }

  let ext = typeToExt[filePart.contentType]
  if (!ext && filePart.filename.includes('.')) {
    ext = filePart.filename.split('.').pop().toLowerCase()
  }

  if (!ext || !['jpg', 'jpeg', 'png', 'webp', 'gif'].includes(ext)) {
    return null
  }
  if (ext === 'jpeg') ext = 'jpg'

  const mediaDir = getProfileMediaDir(username)
  mkdirSync(mediaDir, { recursive: true })
  cleanupProfileMedia(username, kind)

  const filePath = getProfileMediaPath(username, kind, ext)
  writeFileSync(filePath, filePart.buffer)
  return `${kind}.${ext}`
}

function findProfileMediaPath (username, kind) {
  const dir = getProfileMediaDir(username)
  if (!existsSync(dir)) return null
  for (const file of readdirSync(dir)) {
    if (file.startsWith(`${kind}.`)) {
      return join(dir, file)
    }
  }

  return null
}

export function getProfileMediaBuffer (username, kind) {
  const path = findProfileMediaPath(username, kind)
  if (!path || !existsSync(path)) return null

  const ext = path.split('.').pop().toLowerCase()
  const contentType = ext === 'jpg' || ext === 'jpeg'
    ? 'image/jpeg'
    : ext === 'png'
      ? 'image/png'
      : ext === 'webp'
        ? 'image/webp'
        : ext === 'gif'
          ? 'image/gif'
          : 'application/octet-stream'

  return { buffer: readFileSync(path), contentType }
}

function parseMultipartTextFields (request) {
  const ct = request.headers['content-type'] || ''
  const boundaryMatch = ct.match(/boundary=(?:"([^"]+)"|([^;]+))/i)
  const boundary = boundaryMatch?.[1] || boundaryMatch?.[2]
  if (!boundary) return {}

  const raw = Buffer.isBuffer(request.body) ? request.body.toString() : String(request.body || '')
  const parts = raw.split(`--${boundary}`)
  const out = {}

  for (const part of parts) {
    if (!part || part === '--' || part.trim() === '') continue
    const splitAt = part.indexOf('\r\n\r\n')
    if (splitAt === -1) continue

    const headerBlock = part.slice(0, splitAt)
    const contentDisposition = headerBlock
      .split('\r\n')
      .find(h => /^content-disposition:/i.test(h))
    if (!contentDisposition) continue

    const nameMatch = contentDisposition.match(/name="([^"]+)"/i)
    if (!nameMatch) continue
    const field = nameMatch[1]

    // Ignore binary file parts for now.
    if (/filename="/i.test(contentDisposition)) continue

    let value = part.slice(splitAt + 4)
    value = value.replace(/\r\n--$/, '').replace(/\r\n$/, '')
    out[field] = value
  }

  return out
}

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
  if (ct.includes('multipart/form-data')) {
    return parseMultipartTextFields(request)
  }
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
    ensureClientsLoaded()
    const body = parseBody(request)
    const { client_name, redirect_uris, scopes, website } = body

    if (!client_name || !redirect_uris) {
      return reply.code(422).send({ error: 'client_name and redirect_uris are required' })
    }

    const clientId = randomUUID()
    const clientSecret = randomUUID()

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
    persistClients()

    return reply.send(client)
  }
}

/**
 * GET /api/v1/accounts/verify_credentials — Who am I?
 * Returns the authenticated user's profile as a Mastodon Account object
 */
export function createVerifyCredentialsHandler (getUserConfig) {
  return async (request, reply) => {
    const auth = await getWebIdFromRequestAsync(request)
    if (!auth.webId) {
      return reply.code(401).send({ error: 'Unauthorized' })
    }

    const protocol = request.headers['x-forwarded-proto'] || request.protocol
    const host = request.headers['x-forwarded-host'] || request.hostname
    const baseUrl = `${protocol}://${host}`
    const uc = typeof getUserConfig === 'function' ? getUserConfig(request) : getUserConfig
    // In single-host mode uc.username may be the default 'me' — override with token webId
    const username = (uc.username && uc.username !== 'me')
      ? uc.username
      : (getUsernameFromWebId(auth.webId) || uc.username)

    const profile = getProfileOverride(username)
    const displayName = profile?.display_name || uc.displayName || username
    const notePlain = profile?.note || uc.summary || ''

    const account = {
      ...buildAccount(username, baseUrl),
      display_name: displayName,
      note: notePlain ? `<p>${escapeHtml(notePlain)}</p>` : '',
      avatar: `${baseUrl}/profile/avatar.png`,
      avatar_static: `${baseUrl}/profile/avatar.png`,
      header: `${baseUrl}/profile/header.png`,
      header_static: `${baseUrl}/profile/header.png`,
      source: {
        privacy: 'public',
        sensitive: false,
        language: 'en',
        note: notePlain,
        fields: []
      }
    }

    return reply.send(account)
  }
}

/**
 * PATCH /api/v1/accounts/update_credentials
 * Update current user's profile fields for Mastodon clients.
 */
export function createUpdateCredentialsHandler () {
  return async (request, reply) => {
    const auth = await getWebIdFromRequestAsync(request)
    if (!auth.webId) {
      return reply.code(401).send({ error: 'Unauthorized' })
    }

    const username = getUsernameFromWebId(auth.webId)
    if (!username) {
      return reply.code(400).send({ error: 'Invalid WebID' })
    }

    const protocol = request.headers['x-forwarded-proto'] || request.protocol
    const host = request.headers['x-forwarded-host'] || request.hostname
    const baseUrl = `${protocol}://${host}`

    const body = parseBody(request)
    const avatarPart = getAnyProfileMediaPart(request, ['avatar', 'avatar[]', 'avatar_file'])
    const headerPart = getAnyProfileMediaPart(request, ['header', 'header[]', 'header_file'])
    const avatarFile = saveProfileMedia(username, 'avatar', avatarPart)
    const headerFile = saveProfileMedia(username, 'header', headerPart)

    const prev = getProfileOverride(username) || {}
    const next = {
      ...prev,
      ...(typeof body.display_name === 'string' ? { display_name: body.display_name } : {}),
      ...(typeof body.note === 'string' ? { note: body.note } : {}),
      ...(avatarFile ? { avatar_file: avatarFile } : {}),
      ...(headerFile ? { header_file: headerFile } : {}),
      updated_at: new Date().toISOString()
    }

    profileOverrides.set(username, next)
    persistProfile(username)

    const account = {
      ...buildAccount(username, baseUrl),
      display_name: next.display_name || username,
      note: next.note ? `<p>${escapeHtml(next.note)}</p>` : '',
      avatar: `${baseUrl}/profile/avatar.png`,
      avatar_static: `${baseUrl}/profile/avatar.png`,
      header: `${baseUrl}/profile/header.png`,
      header_static: `${baseUrl}/profile/header.png`,
      source: {
        privacy: 'public',
        sensitive: false,
        language: body.language || 'en',
        note: next.note || '',
        fields: []
      }
    }

    return reply.send(account)
  }
}

/**
 * GET /api/v1/accounts/lookup?acct=alice or alice@example.org
 */
export function createAccountLookupHandler () {
  return async (request, reply) => {
    const acct = (request.query?.acct || '').trim()
    if (!acct) {
      return reply.code(422).send({ error: 'acct is required' })
    }

    const protocol = request.headers['x-forwarded-proto'] || request.protocol
    const host = request.headers['x-forwarded-host'] || request.hostname
    const parsed = parseAccountIdentifier(acct)
    if (!parsed) {
      return reply.code(404).send({ error: 'Account not found' })
    }

    if (parsed.domain && !isLocalAccountDomain(parsed.domain, host)) {
      const remote = await resolveRemoteAccount(parsed)
      if (!remote) {
        return reply.code(404).send({ error: 'Remote account not found' })
      }
      return reply.send(remote)
    }

    const baseUrl = `${protocol}://${host}`

    return reply.send(buildAccount(parsed.username, baseUrl))
  }
}

/**
 * Shared instance data builder
 */
function buildInstanceData (host, wsProtocol) {
  return {
    uri: host,
    domain: host,
    title: 'JSS',
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
      media_attachments: { supported_mime_types: [] },
      polls: { max_options: 4, max_characters_per_option: 50, min_expiration: 300, max_expiration: 2629746 }
    },
    contact: { email: 'admin@example.com', account: null },
    rules: []
  }
}

/**
 * GET /api/v1/instance — Instance information
 * Required by most Mastodon clients before login
 */
export function createInstanceHandler () {
  return async (request, reply) => {
    const protocol = request.headers['x-forwarded-proto'] || request.protocol
    const host = request.headers['x-forwarded-host'] || request.hostname
    const wsProtocol = protocol === 'https' ? 'wss' : 'ws'
    return reply.send(buildInstanceData(host, wsProtocol))
  }
}

/**
 * GET /api/v2/instance — Instance information (v2 format for Elk/Phanpy)
 */
export function createInstanceV2Handler () {
  return async (request, reply) => {
    const protocol = request.headers['x-forwarded-proto'] || request.protocol
    const host = request.headers['x-forwarded-host'] || request.hostname
    const wsProtocol = protocol === 'https' ? 'wss' : 'ws'
    const data = buildInstanceData(host, wsProtocol)
    // v2 moves stats → usage, adds thumbnail
    const v2 = {
      ...data,
      usage: { users: { active_month: data.stats.user_count } },
      thumbnail: { url: null },
      registrations: { enabled: false, approval_required: false, message: null }
    }
    delete v2.stats
    return reply.send(v2)
  }
}

/**
 * Extract username from webId
 * Subdomain mode: https://alice.pivot-test.local:4443/profile/card#me → alice
 * Path mode (test/single-host): http://127.0.0.1:PORT/alice/profile/card#me → alice
 */
function getUsernameFromWebId (webId) {
  if (!webId) return null
  try {
    const url = new URL(webId)
    const hostname = url.hostname
    // IP address or localhost — extract from first path segment
    if (hostname === 'localhost' || /^(127\.|192\.168\.|10\.|::1)/.test(hostname)) {
      const seg = url.pathname.split('/').filter(Boolean)[0]
      return seg || null
    }
    // Subdomain mode — first hostname segment
    const parts = hostname.split('.')
    if (parts.length >= 2) {
      return parts[0] !== 'www' ? parts[0] : null
    }
    return parts[0] || null
  } catch {
    return null
  }
}

/**
 * Build a Mastodon-compatible Account object
 * baseUrl is used to derive the domain/port; username replaces the subdomain.
 */
function buildAccount (username, baseUrl) {
  // Build the account's own base URL using its subdomain, not the requester's
  let accountBaseUrl = baseUrl
  let accountHost = null
  try {
    const u = new URL(baseUrl)
    const hostParts = u.hostname.split('.')
    // Replace first segment (subdomain) with this account's username
    if (hostParts.length >= 2) {
      hostParts[0] = username
      u.hostname = hostParts.join('.')
      accountBaseUrl = u.origin
    }
    accountHost = u.host
  } catch { /* keep baseUrl as-is */ }

  if (!accountHost) {
    try {
      accountHost = new URL(accountBaseUrl).host
    } catch {
      accountHost = null
    }
  }

  const postCount = getPosts(username, 1000).length
  const account = {
    id: username,
    username,
    acct: accountHost ? `${username}@${accountHost}` : username,
    display_name: username,
    locked: false,
    bot: false,
    discoverable: true,
    group: false,
    created_at: startedAt,
    note: '',
    url: `${accountBaseUrl}/profile/card.jsonld`,
    avatar: `${accountBaseUrl}/profile/avatar.png`,
    avatar_static: `${accountBaseUrl}/profile/avatar.png`,
    header: `${accountBaseUrl}/profile/header.png`,
    header_static: `${accountBaseUrl}/profile/header.png`,
    followers_count: getFollowerCount(username),
    following_count: getFollowingCount(username),
    statuses_count: postCount,
    last_status_at: postCount > 0 ? new Date().toISOString().split('T')[0] : null,
    emojis: [],
    fields: []
  }

  const profile = getProfileOverride(username)
  if (profile) {
    if (typeof profile.display_name === 'string') account.display_name = profile.display_name
    if (typeof profile.note === 'string') account.note = profile.note
  }

  return account
}

/**
 * Build a Mastodon-compatible Status object
 */
function buildStatus (post, username, baseUrl) {
  return {
    id: post.id,
    created_at: post.published,
    in_reply_to_id: post.in_reply_to || null,
    in_reply_to_account_id: null,
    sensitive: false,
    spoiler_text: '',
    visibility: 'public',
    language: 'en',
    uri: post.id,
    url: post.id,
    replies_count: 0,
    reblogs_count: 0,
    favourites_count: 0,
    edited_at: null,
    content: post.content,
    reblog: null,
    application: null,
    account: buildAccount(username, baseUrl),
    media_attachments: [],
    mentions: [],
    tags: [],
    emojis: [],
    card: null,
    poll: null
  }
}

function parseAccountIdentifier (idOrAcct) {
  if (!idOrAcct) return null

  const raw = String(idOrAcct).trim()
  if (!raw) return null

  if (raw.startsWith('http://') || raw.startsWith('https://')) {
    try {
      const url = new URL(raw)
      const username = getUsernameFromWebId(raw)
      if (!username) return null
      return { username, domain: url.host }
    } catch {
      return null
    }
  }

  let value = raw
  if (value.startsWith('@')) value = value.slice(1)

  if (!value) return null

  const at = value.indexOf('@')
  if (at === -1) {
    return { username: value, domain: null }
  }

  const username = value.slice(0, at)
  const domain = value.slice(at + 1)
  if (!username || !domain) return null
  return { username, domain }
}

function isLocalAccountDomain (domain, requestHost) {
  if (!domain) return true

  const norm = String(domain).toLowerCase()
  const host = String(requestHost || '').toLowerCase()
  if (!host) return false

  const hostNoPort = host.includes(':') ? host.split(':')[0] : host
  if (hostNoPort === 'localhost' || /^(127\.|10\.|192\.168\.|::1)/.test(hostNoPort)) {
    // In local/dev mode (IP or localhost host headers), allow acct domains.
    return true
  }

  if (norm === host) return true

  // In subdomain mode allow sibling pod hosts under the same base domain.
  const firstDot = host.indexOf('.')
  if (firstDot === -1 || firstDot === host.length - 1) return false
  const base = host.slice(firstDot + 1)
  return norm.endsWith(`.${base}`)
}

function normalizeAccountIdentifier (idOrAcct) {
  const parsed = parseAccountIdentifier(idOrAcct)
  return parsed?.username || null
}

function getActorUrlFromWebfinger (resource) {
  const links = Array.isArray(resource?.links) ? resource.links : []
  const self = links.find((l) => {
    if (l?.rel !== 'self' || !l?.href) return false
    const t = String(l.type || '').toLowerCase()
    return t.includes('activity+json') || t.includes('application/ld+json')
  })
  return self?.href || null
}

function buildRemoteAccountFromActor (actor, parsed) {
  const actorId = actor?.id || actor?.url || ''
  const profileUrl = typeof actor?.url === 'string'
    ? actor.url
    : String(actorId || '').replace(/#.*$/, '')

  const username = actor?.preferredUsername || parsed.username
  const acct = `${username}@${parsed.domain}`
  const iconUrl = actor?.icon?.url || null
  const imageUrl = actor?.image?.url || null

  return {
    id: acct,
    username,
    acct,
    display_name: actor?.name || username,
    locked: false,
    bot: false,
    discoverable: true,
    group: false,
    created_at: startedAt,
    note: actor?.summary || '',
    url: profileUrl || actorId || null,
    avatar: iconUrl,
    avatar_static: iconUrl,
    header: imageUrl,
    header_static: imageUrl,
    followers_count: 0,
    following_count: 0,
    statuses_count: 0,
    last_status_at: null,
    emojis: [],
    fields: [],
    _remote: {
      actorId,
      inbox: actor?.inbox || actor?.endpoints?.sharedInbox || null
    }
  }
}

async function resolveRemoteAccount (parsed) {
  const resource = `acct:${parsed.username}@${parsed.domain}`
  const wfUrl = `https://${parsed.domain}/.well-known/webfinger?resource=${encodeURIComponent(resource)}`

  let wfJson = null
  try {
    const wf = await safeFetch(wfUrl, {
      headers: { Accept: 'application/jrd+json, application/json' }
    }, { requireHttps: true, blockPrivateIPs: true, resolveDNS: true })
    if (!wf.ok) return null
    wfJson = await wf.json()
  } catch {
    return null
  }

  const actorUrl = getActorUrlFromWebfinger(wfJson)
  if (!actorUrl) return null

  let actor = getCachedActor(actorUrl)
  if (!actor) {
    try {
      const actorRes = await safeFetch(actorUrl, {
        headers: {
          Accept: 'application/activity+json, application/ld+json; profile="https://www.w3.org/ns/activitystreams", application/json'
        }
      }, { requireHttps: true, blockPrivateIPs: true, resolveDNS: true })
      if (!actorRes.ok) return null
      actor = await actorRes.json()
      if (actor?.id) cacheActor(actor)
    } catch {
      return null
    }
  }

  if (!actor || typeof actor !== 'object') return null
  return buildRemoteAccountFromActor(actor, parsed)
}

/**
 * GET /api/v1/timelines/home
 * Return authenticated user's federated timeline
 */
export function createTimelinesHomeHandler () {
  return async (request, reply) => {
    const auth = await getWebIdFromRequestAsync(request)
    if (!auth.webId) {
      return reply.code(401).send({ error: 'Unauthorized' })
    }

    const username = getUsernameFromWebId(auth.webId)
    if (!username) {
      return reply.code(400).send({ error: 'Invalid WebID' })
    }

    const protocol = request.headers['x-forwarded-proto'] || request.protocol
    const host = request.headers['x-forwarded-host'] || request.hostname
    const baseUrl = `${protocol}://${host}`

    // Get posts from accounts this user follows
    const following = getFollowing(username)
    const statuses = []

    for (const follow of following) {
      const actor = follow.actor
      // Extract username from actor URL
      try {
        const actorUrl = new URL(actor)
        const followedUsername = actorUrl.hostname.split('.')[0]
        const posts = getPosts(followedUsername, 50)
        statuses.push(...posts.map(p => buildStatus(p, followedUsername, baseUrl)))
      } catch {
        // Skip invalid actor URLs
      }
    }

    // Also include own posts
    const ownPosts = getPosts(username, 50)
    statuses.push(...ownPosts.map(p => buildStatus(p, username, baseUrl)))

    // Sort by date descending
    statuses.sort((a, b) => new Date(b.created_at) - new Date(a.created_at))

    // Limit to 20 latest
    return reply.send(statuses.slice(0, 20))
  }
}

/**
 * POST /api/v1/statuses
 * Create a new status (post/note)
 */
export function createPostStatusHandler () {
  return async (request, reply) => {
    const auth = await getWebIdFromRequestAsync(request)
    if (!auth.webId) {
      return reply.code(401).send({ error: 'Unauthorized' })
    }

    const username = getUsernameFromWebId(auth.webId)
    if (!username) {
      return reply.code(400).send({ error: 'Invalid WebID' })
    }

    const protocol = request.headers['x-forwarded-proto'] || request.protocol
    const host = request.headers['x-forwarded-host'] || request.hostname
    const baseUrl = `${protocol}://${host}`

    const body = parseBody(request)
    const { status, in_reply_to_id } = body
    if (!status) {
      return reply.code(422).send({ error: 'status is required' })
    }

    const postId = `${baseUrl}/posts/${randomUUID()}`
    const now = new Date().toISOString()

    // Save to AP store
    const { savePost } = await import('../store.js')
    savePost(username, postId, status, in_reply_to_id || null)

    // Return Mastodon status object
    const post = {
      id: postId,
      content: status,
      published: now,
      in_reply_to: in_reply_to_id || null
    }

    return reply.code(200).send(buildStatus(post, username, baseUrl))
  }
}

/**
 * Resolve status identifier from request params.
 * Supports both /api/v1/statuses/:id and wildcard /api/v1/statuses/* forms.
 */
function getStatusIdParam (request) {
  return request.params?.id || request.params?.['*'] || null
}

function resolvePostByStatusId (rawId, baseUrl) {
  if (!rawId) return null

  // /source and /history suffixes are endpoint modifiers
  let normalized = rawId
  if (normalized.endsWith('/source')) normalized = normalized.slice(0, -('/source'.length))
  if (normalized.endsWith('/history')) normalized = normalized.slice(0, -('/history'.length))

  // Full URL IDs are canonical in our store
  if (normalized.startsWith('http://') || normalized.startsWith('https://')) {
    return getPostById(normalized)
  }

  // Bare ID fallback
  const canonical = `${baseUrl}/posts/${normalized}`
  return getPostById(canonical) || getPostById(normalized)
}

function deriveActorFromPostUrl (statusId) {
  try {
    const parsed = new URL(statusId)
    const pathParts = parsed.pathname.split('/').filter(Boolean)
    if (pathParts.length < 2 || pathParts[0] !== 'posts') return null

    // In subdomain mode: bob.example.org/posts/uuid -> actor bob.example.org/profile/card.jsonld#me
    const hostParts = parsed.hostname.split('.')
    if (hostParts.length < 2) return null
    const actorBase = `${parsed.protocol}//${parsed.host}`
    return {
      actorId: `${actorBase}/profile/card.jsonld#me`,
      inbox: `${actorBase}/profile/card.jsonld/inbox`
    }
  } catch {
    return null
  }
}

/**
 * GET /api/v1/statuses/:id and /api/v1/statuses/:id/source
 * Returns a status object, or source payload for editing.
 */
export function createGetStatusHandler () {
  return async (request, reply) => {
    const protocol = request.headers['x-forwarded-proto'] || request.protocol
    const host = request.headers['x-forwarded-host'] || request.hostname
    const baseUrl = `${protocol}://${host}`

    const rawId = getStatusIdParam(request)
    if (!rawId) {
      return reply.code(400).send({ error: 'Status ID is required' })
    }

    const sourceMode = rawId.endsWith('/source')
    const historyMode = rawId.endsWith('/history')
    const post = resolvePostByStatusId(rawId, baseUrl)
    if (!post) {
      return reply.code(404).send({ error: 'Status not found' })
    }

    if (historyMode) {
      return reply.send([
        {
          content: post.content,
          spoiler_text: '',
          sensitive: false,
          created_at: post.published || new Date().toISOString(),
          account: buildAccount(post.username, baseUrl)
        }
      ])
    }

    if (!sourceMode) {
      return reply.send(buildStatus(post, post.username, baseUrl))
    }

    // /source is for editing own posts: require auth and ownership.
    const auth = await getWebIdFromRequestAsync(request)
    if (!auth.webId) {
      return reply.code(401).send({ error: 'Unauthorized' })
    }
    const username = getUsernameFromWebId(auth.webId)
    if (!username || username !== post.username) {
      return reply.code(404).send({ error: 'Status not found' })
    }

    return reply.send({
      id: post.id,
      text: post.content,
      spoiler_text: '',
      sensitive: false
    })
  }
}


/**
 * PUT /api/v1/statuses/:id
 * Edit a status content.
 */
export function createUpdateStatusHandler () {
  return async (request, reply) => {
    const auth = await getWebIdFromRequestAsync(request)
    if (!auth.webId) {
      return reply.code(401).send({ error: 'Unauthorized' })
    }

    const username = getUsernameFromWebId(auth.webId)
    if (!username) {
      return reply.code(400).send({ error: 'Invalid WebID' })
    }

    const protocol = request.headers['x-forwarded-proto'] || request.protocol
    const host = request.headers['x-forwarded-host'] || request.hostname
    const baseUrl = `${protocol}://${host}`

    const rawId = getStatusIdParam(request)
    if (!rawId) {
      return reply.code(400).send({ error: 'Status ID is required' })
    }

    const body = parseBody(request)
    const { status } = body
    if (!status) {
      return reply.code(422).send({ error: 'status is required' })
    }

    // Accept both canonical URL IDs and bare IDs.
    let postId = rawId
    if (!postId.startsWith('http://') && !postId.startsWith('https://')) {
      postId = `${baseUrl}/posts/${postId}`
    }

    let post = getPost(username, postId)
    if (!post) {
      // Fallback for edge cases where host/protocol differs from request host.
      post = getPostById(rawId) || getPostById(postId)
      if (!post || post.username !== username) {
        return reply.code(404).send({ error: 'Status not found' })
      }
      postId = post.id
    }

    updatePost(username, postId, status)
    const updated = getPost(username, postId)

    return reply.send(buildStatus(updated || { ...post, content: status }, username, baseUrl))
  }
}

/**
 * POST /api/v1/statuses/:id/favourite
 * Favourite (Like) a status.
 */
export function createFavouriteStatusHandler (getUserConfig) {
  return async (request, reply) => {
    const auth = await getWebIdFromRequestAsync(request)
    if (!auth.webId) {
      return reply.code(401).send({ error: 'Unauthorized' })
    }

    const username = getUsernameFromWebId(auth.webId)
    if (!username) {
      return reply.code(400).send({ error: 'Invalid WebID' })
    }

    const protocol = request.headers['x-forwarded-proto'] || request.protocol
    const host = request.headers['x-forwarded-host'] || request.hostname
    const baseUrl = `${protocol}://${host}`

    let rawId = getStatusIdParam(request)
    if (!rawId) {
      return reply.code(400).send({ error: 'Status ID is required' })
    }
    if (rawId.endsWith('/favourite')) {
      rawId = rawId.slice(0, -('/favourite'.length))
    }

    const targetStatusId = (rawId.startsWith('http://') || rawId.startsWith('https://'))
      ? rawId
      : `${baseUrl}/posts/${rawId}`

    const localPost = resolvePostByStatusId(rawId, baseUrl)

    // Best-effort AP Like delivery for remote posts.
    const requesterActorId = `${baseUrl}/profile/card.jsonld#me`
    const requesterConfig = typeof getUserConfig === 'function' ? getUserConfig(request) : {}
    const requesterKeypair = requesterConfig?.keypair
    const remoteTarget = deriveActorFromPostUrl(targetStatusId)
    if (requesterKeypair && remoteTarget?.inbox && !targetStatusId.startsWith(`${baseUrl}/`)) {
      const likeActivity = {
        '@context': 'https://www.w3.org/ns/activitystreams',
        id: `${requesterActorId}/activities/${randomUUID()}`,
        type: 'Like',
        actor: requesterActorId,
        object: targetStatusId
      }
      sendSignedActivity(likeActivity, remoteTarget.inbox, requesterActorId, requesterKeypair, request.log)
    }

    if (localPost) {
      const status = buildStatus(localPost, localPost.username, baseUrl)
      return reply.send({
        ...status,
        favourited: true,
        favourites_count: Number(status.favourites_count || 0) + 1
      })
    }

    const accountId = targetStatusId.startsWith('http')
      ? (() => {
          try {
            return new URL(targetStatusId).hostname.split('.')[0] || 'unknown'
          } catch {
            return 'unknown'
          }
        })()
      : 'unknown'

    return reply.send({
      id: targetStatusId,
      uri: targetStatusId,
      url: targetStatusId,
      created_at: new Date().toISOString(),
      account: buildAccount(accountId, baseUrl),
      content: '',
      visibility: 'public',
      reblogs_count: 0,
      favourites_count: 1,
      replies_count: 0,
      favourited: true,
      reblogged: false,
      muted: false,
      bookmarked: false,
      pinned: false,
      language: 'en',
      text: '',
      edited_at: null,
      poll: null,
      card: null
    })
  }
}

/**
 * GET /api/v1/accounts/:id
 * Get account info by username or ID
 */
export function createGetAccountHandler () {
  return async (request, reply) => {
    const { id } = request.params
    const accountId = normalizeAccountIdentifier(id)
    if (!accountId) {
      return reply.code(400).send({ error: 'ID is required' })
    }

    const protocol = request.headers['x-forwarded-proto'] || request.protocol
    const host = request.headers['x-forwarded-host'] || request.hostname
    const baseUrl = `${protocol}://${host}`

    return reply.send(buildAccount(accountId, baseUrl))
  }
}

/**
 * GET /api/v1/accounts/:id/statuses
 * Get statuses for a user
 */
export function createGetAccountStatusesHandler () {
  return async (request, reply) => {
    const { id } = request.params
    const accountId = normalizeAccountIdentifier(id)
    if (!accountId) {
      return reply.code(400).send({ error: 'ID is required' })
    }

    const protocol = request.headers['x-forwarded-proto'] || request.protocol
    const host = request.headers['x-forwarded-host'] || request.hostname
    const baseUrl = `${protocol}://${host}`

    const posts = getPosts(accountId, 20)
    const statuses = posts.map(p => buildStatus(p, accountId, baseUrl))

    return reply.send(statuses)
  }
}

/**
 * GET /api/v1/preferences
 * Minimal preference payload for Mastodon clients.
 */
export function createPreferencesHandler () {
  return async (request, reply) => {
    const auth = await getWebIdFromRequestAsync(request)
    if (!auth.webId) {
      return reply.code(401).send({ error: 'Unauthorized' })
    }

    return reply.send({
      'posting:default:visibility': 'public',
      'posting:default:sensitive': false,
      'posting:default:language': 'en',
      'reading:expand:media': 'default',
      'reading:expand:spoilers': false
    })
  }
}

/**
 * GET /api/v1/accounts/relationships?id[]=...
 */
export function createRelationshipsHandler () {
  return async (request, reply) => {
    const auth = await getWebIdFromRequestAsync(request)
    if (!auth.webId) {
      return reply.code(401).send({ error: 'Unauthorized' })
    }

    const username = getUsernameFromWebId(auth.webId)
    if (!username) {
      return reply.code(400).send({ error: 'Invalid WebID' })
    }

    const raw = request.query?.id ?? request.query?.['id[]']
    const ids = Array.isArray(raw) ? raw : (raw ? [raw] : [])

    const following = new Set(
      getFollowing(username)
        .map(f => normalizeAccountIdentifier(f.actor))
        .filter(Boolean)
    )

    const followers = new Set(
      getFollowers(username)
        .map(f => normalizeAccountIdentifier(f.actor))
        .filter(Boolean)
    )

    const relationships = ids.map((id) => {
      const normalized = normalizeAccountIdentifier(id)
      return {
        id,
        following: normalized ? following.has(normalized) : false,
        showing_reblogs: true,
        notifying: false,
        followed_by: normalized ? followers.has(normalized) : false,
        blocking: false,
        blocked_by: false,
        muting: false,
        muting_notifications: false,
        requested: false,
        domain_blocking: false,
        endorsed: false,
        note: ''
      }
    })

    return reply.send(relationships)
  }
}

/**
 * GET /api/v1/lists
 * Minimal compatibility: return no lists.
 */
export function createListsHandler () {
  return async (request, reply) => {
    const auth = await getWebIdFromRequestAsync(request)
    if (!auth.webId) {
      return reply.code(401).send({ error: 'Unauthorized' })
    }
    return reply.send([])
  }
}

/**
 * GET /api/v1/accounts/:id/lists
 * Minimal compatibility: account is not in any lists.
 */
export function createAccountListsHandler () {
  return async (request, reply) => {
    const auth = await getWebIdFromRequestAsync(request)
    if (!auth.webId) {
      return reply.code(401).send({ error: 'Unauthorized' })
    }
    return reply.send([])
  }
}

/**
 * Extract a canonical URL from Mastodon search query text.
 * Supports raw URLs and Phanpy-style wrapped links like:
 *   alice.host/s/https://alice.host/posts/<id>
 */
function extractSearchUrl (query) {
  if (!query || typeof query !== 'string') return null

  // If query embeds "https://" in the middle (Phanpy /s/ form), keep the URL part.
  const embeddedHttps = query.indexOf('https://')
  if (embeddedHttps > 0) {
    return query.slice(embeddedHttps)
  }

  // Regular URL query
  if (query.startsWith('http://') || query.startsWith('https://')) {
    return query
  }

  return null
}

/**
 * GET /api/v2/search
 * Minimal Mastodon search implementation for clients resolving status URLs and accounts.
 */
export function createSearchHandler () {
  return async (request, reply) => {
    const q = request.query?.q || ''
    const protocol = request.headers['x-forwarded-proto'] || request.protocol
    const host = request.headers['x-forwarded-host'] || request.hostname
    const baseUrl = `${protocol}://${host}`

    const result = {
      accounts: [],
      statuses: [],
      hashtags: []
    }

    // Account lookup fallback for plain handles/acct strings (bob, @bob, bob@example.org)
    const parsed = parseAccountIdentifier(String(q).trim())
    if (parsed) {
      if (isLocalAccountDomain(parsed.domain, host)) {
        result.accounts.push(buildAccount(parsed.username, baseUrl))
      } else {
        const remote = await resolveRemoteAccount(parsed)
        if (remote) result.accounts.push(remote)
      }
    }

    const targetUrl = extractSearchUrl(q)
    if (!targetUrl) {
      return reply.send(result)
    }

    // Try direct ID match first (posts are stored as full URL IDs)
    let post = getPostById(targetUrl)

    // Fallback: if URL path is /posts/:id, reconstruct canonical ID with origin
    if (!post) {
      try {
        const u = new URL(targetUrl)
        const match = u.pathname.match(/^\/posts\/([^/?#]+)$/)
        if (match) {
          const canonical = `${u.origin}/posts/${match[1]}`
          post = getPostById(canonical)
        }
      } catch {
        // Ignore invalid URLs and return empty result below
      }
    }

    if (!post) {
      return reply.send(result)
    }

    result.statuses.push(buildStatus(post, post.username, baseUrl))
    return reply.send(result)
  }
}

/**
 * GET /api/v1/accounts/search
 * Minimal account search used by some Mastodon clients.
 */
export function createAccountsSearchHandler () {
  return async (request, reply) => {
    const q = String(request.query?.q || '').trim()
    if (!q) return reply.send([])

    const protocol = request.headers['x-forwarded-proto'] || request.protocol
    const host = request.headers['x-forwarded-host'] || request.hostname
    const parsed = parseAccountIdentifier(q)
    if (!parsed) return reply.send([])

    const baseUrl = `${protocol}://${host}`
    if (!isLocalAccountDomain(parsed.domain, host)) {
      const remote = await resolveRemoteAccount(parsed)
      return reply.send(remote ? [remote] : [])
    }

    return reply.send([buildAccount(parsed.username, baseUrl)])
  }
}

/**
 * POST /api/v1/accounts/:id/follow
 * Follow a user
 */
export function createFollowAccountHandler (getUserConfig) {
  return async (request, reply) => {
    const auth = await getWebIdFromRequestAsync(request)
    if (!auth.webId) {
      return reply.code(401).send({ error: 'Unauthorized' })
    }

    const { id: rawTargetId } = request.params
    if (!rawTargetId) {
      return reply.code(400).send({ error: 'Target ID is required' })
    }

    // Derive requester identity from request subdomain (reliable in subdomain mode)
    // This is more reliable than extracting from the token webId which may vary
    const protocol = request.headers['x-forwarded-proto'] || request.protocol
    const uc = typeof getUserConfig === 'function' ? getUserConfig(request) : {}
    // In single-host mode uc.username may be 'me' — override with token webId
    const username = (uc.username && uc.username !== 'me')
      ? uc.username
      : (getUsernameFromWebId(auth.webId) || uc.username)
    if (!username) {
      return reply.code(400).send({ error: 'Cannot determine requester identity' })
    }
    const baseDomain = uc.baseDomain || request.headers['x-forwarded-host'] || request.hostname
    const subdomains = uc.subdomains || false
    const host = request.headers['x-forwarded-host'] || request.hostname

    const targetParsed = parseAccountIdentifier(rawTargetId)
    if (!targetParsed) {
      return reply.code(400).send({ error: 'Invalid target account identifier' })
    }

    const isLocalTarget = isLocalAccountDomain(targetParsed.domain, host)

    // Build actor URLs — in subdomain mode use subdomain-style, otherwise path-based
    let targetActorId, requesterActorId, requesterInbox
    if (subdomains && baseDomain) {
      requesterActorId = `${protocol}://${username}.${baseDomain}/profile/card.jsonld#me`
      requesterInbox = `${protocol}://${username}.${baseDomain}/profile/card.jsonld/inbox`
    } else {
      requesterActorId = `${protocol}://${host}/${username}/profile/card.jsonld#me`
      requesterInbox = `${protocol}://${host}/${username}/profile/card.jsonld/inbox`
    }

    let remoteInbox = null
    if (isLocalTarget) {
      const targetUsername = targetParsed.username
      if (subdomains && baseDomain) {
        targetActorId = `${protocol}://${targetUsername}.${baseDomain}/profile/card.jsonld#me`
      } else {
        targetActorId = `${protocol}://${host}/${targetUsername}/profile/card.jsonld#me`
      }
    } else {
      const remote = await resolveRemoteAccount(targetParsed)
      if (!remote?._remote?.actorId) {
        return reply.code(404).send({ error: 'Remote account not found' })
      }
      targetActorId = remote._remote.actorId
      remoteInbox = remote._remote.inbox || null
    }

    // Add to requester's following list (pending until Accept received for remote)
    addFollowing(username, targetActorId, isLocalTarget)

    // Add to target's followers list only for local targets.
    if (isLocalTarget) {
      addFollower(targetParsed.username, requesterActorId, requesterInbox)
    } else if (remoteInbox) {
      // Deliver outbound Follow activity to remote actor's inbox
      const uc = typeof getUserConfig === 'function' ? getUserConfig(request) : {}
      const keypair = uc.keypair
      if (keypair) {
        const followActivity = {
          '@context': 'https://www.w3.org/ns/activitystreams',
          id: `${requesterActorId}/activities/${randomUUID()}`,
          type: 'Follow',
          actor: requesterActorId,
          object: targetActorId
        }
        sendSignedActivity(followActivity, remoteInbox, requesterActorId, keypair, request.log)
      }
    }

    // Return relationship
    return reply.send({
      id: rawTargetId,
      following: true,
      showing_reblogs: true,
      notifying: false,
      languages: ['en'],
      blocked: false,
      blocking: false,
      muting: false,
      muting_notifications: false,
      requested: false,
      domain_blocking: false
    })
  }
}

/**
 * GET /api/v1/notifications
 * Get notifications (follows, likes, etc)
 * For now, return empty - would need extended AP model
 */
export function createGetNotificationsHandler (getUserConfig) {
  return async (request, reply) => {
    const auth = await getWebIdFromRequestAsync(request)
    if (!auth.webId) {
      return reply.code(401).send({ error: 'Unauthorized' })
    }

    const protocol = request.headers['x-forwarded-proto'] || request.protocol
    const host = request.headers['x-forwarded-host'] || request.hostname
    const baseUrl = `${protocol}://${host}`
    const uc = typeof getUserConfig === 'function' ? getUserConfig(request) : getUserConfig
    const currentUsername = (uc.username && uc.username !== 'me')
      ? uc.username
      : (getUsernameFromWebId(auth.webId) || uc.username)

    // Build follow notifications from the followers table
    const followers = getFollowers(currentUsername)
    const notifications = followers
      .map((f, i) => {
        // actor may be "https://bob.host/profile/card.jsonld#me" — strip fragment first
        let actorUrl = f.actor || ''
        try { actorUrl = actorUrl.split('#')[0] } catch { /* keep */ }
        // Use getUsernameFromWebId which handles both subdomain and path-based WebIDs
        const followerUsername = getUsernameFromWebId(actorUrl + '#me') || getUsernameFromWebId(actorUrl)
        // Skip if we can't determine follower or it's the user themselves
        if (!followerUsername || followerUsername === currentUsername) return null
        const followerBase = (() => {
          try {
            const u = new URL(actorUrl)
            return `${u.protocol}//${u.host}`
          } catch { return baseUrl }
        })()
        return {
          id: String(i + 1),
          type: 'follow',
          created_at: f.created_at ? new Date(f.created_at).toISOString() : new Date().toISOString(),
          account: buildAccount(followerUsername, followerBase)
        }
      })
      .filter(Boolean)

    return reply.send(notifications)
  }
}

/**
 * Look up a registered client
 */
export function getClient (clientId) {
  ensureClientsLoaded()
  return clients.get(clientId) || null
}

function escapeHtml (str) {
  return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;')
}

export default {
  createAppsHandler,
  createVerifyCredentialsHandler,
  createUpdateCredentialsHandler,
  createAccountLookupHandler,
  createAccountsSearchHandler,
  createPreferencesHandler,
  createListsHandler,
  createAccountListsHandler,
  createRelationshipsHandler,
  createInstanceHandler,
  createSearchHandler,
  createFavouriteStatusHandler,
  createUpdateStatusHandler,
  getClient
}
