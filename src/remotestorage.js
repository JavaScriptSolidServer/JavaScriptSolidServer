/**
 * remoteStorage plugin for JSS
 * Implements draft-dejong-remotestorage protocol on top of existing storage
 *
 * No new dependencies — reuses filesystem storage, OAuth, and WebFinger.
 * Always on — no flag needed.
 *
 * Ref: https://remotestorage.io/spec/draft-dejong-remotestorage-22
 * Related: #106, #160 (OAuth), #159 (Mastodon API)
 */

import * as storage from './storage/filesystem.js'
import { getContentType } from './utils/url.js'
import { getWebIdFromRequestAsync } from './auth/token.js'
import { checkIfMatch, checkIfNoneMatchForGet, checkIfNoneMatchForWrite } from './utils/conditional.js'

// Dotfiles that must never be exposed via remoteStorage
const BLOCKED_NAMES = new Set(['.acl', '.meta', '.pods'])

/**
 * remoteStorage Fastify plugin
 * @param {FastifyInstance} fastify
 * @param {object} options
 * @param {string} options.username - Storage owner username
 * @param {string} options.ownerWebId - WebID of the storage owner
 */
export async function remoteStoragePlugin (fastify, options = {}) {
  const username = options.username || 'me'
  const ownerWebId = options.ownerWebId || null

  /**
   * Extract the storage path from the URL
   * /storage/me/photos/vacation.jpg → /photos/vacation.jpg
   */
  function getStoragePath (request) {
    const wildcard = request.params['*'] || ''
    return '/' + wildcard
  }

  /**
   * Check if the :user param matches the configured username
   */
  function checkUsername (request, reply) {
    if (request.params.user !== username) {
      reply.code(404).send({ error: 'Unknown user' })
      return false
    }
    return true
  }

  /**
   * Check if any path segment is a blocked dotfile
   */
  function hasDotfile (storagePath) {
    const segments = storagePath.split('/')
    return segments.some(s => s.startsWith('.') && s.length > 1)
  }

  /**
   * Check if request is authorized for the given method
   * Public folder is readable without auth
   */
  async function checkAuth (request, method) {
    const storagePath = getStoragePath(request)

    // Public folder: readable without auth
    if (storagePath.startsWith('/public/') && (method === 'GET' || method === 'HEAD')) {
      return { authorized: true, webId: null }
    }

    const { webId, error } = await getWebIdFromRequestAsync(request)
    if (!webId) {
      return { authorized: false, webId: null, error: error || 'Unauthorized', status: 401 }
    }

    // If ownerWebId is set, only the owner can access storage
    if (ownerWebId && webId !== ownerWebId) {
      return { authorized: false, webId, error: 'Forbidden', status: 403 }
    }

    return { authorized: true, webId }
  }

  // GET /storage/:user/* — read file or folder
  fastify.get('/storage/:user/*', async (request, reply) => {
    if (!checkUsername(request, reply)) return

    const storagePath = getStoragePath(request)

    // Block dotfile access
    if (hasDotfile(storagePath)) {
      return reply.code(404).send({ error: 'Not found' })
    }

    const { authorized, error, status } = await checkAuth(request, 'GET')
    if (!authorized) {
      const code = status || 401
      if (code === 401) reply.header('WWW-Authenticate', 'Bearer')
      return reply.code(code).send({ error })
    }

    const info = await storage.stat(storagePath)
    if (!info) {
      return reply.code(404).send({ error: 'Not found' })
    }

    // Conditional GET — use shared utility
    const cond = checkIfNoneMatchForGet(request.headers['if-none-match'], info.etag)
    if (!cond.ok) {
      return reply.code(304).send()
    }

    // Directory listing
    if (info.isDirectory) {
      const entries = await storage.listContainer(storagePath)
      if (!entries) {
        return reply.code(404).send({ error: 'Not found' })
      }

      const items = {}
      for (const entry of entries) {
        // Skip dotfiles (ACLs, metadata, etc.)
        if (entry.name.startsWith('.')) continue

        const childPath = storagePath.endsWith('/') ? storagePath + entry.name : storagePath + '/' + entry.name
        const childStat = await storage.stat(entry.isDirectory ? childPath + '/' : childPath)

        if (entry.isDirectory) {
          items[entry.name + '/'] = {
            ETag: childStat?.etag?.replace(/"/g, '') || ''
          }
        } else {
          items[entry.name] = {
            ETag: childStat?.etag?.replace(/"/g, '') || '',
            'Content-Type': getContentType(entry.name),
            'Content-Length': childStat?.size || 0
          }
        }
      }

      return reply
        .header('Content-Type', 'application/ld+json')
        .header('ETag', info.etag)
        .header('Cache-Control', 'no-cache')
        .send({
          '@context': 'http://remotestorage.io/spec/folder-description',
          items
        })
    }

    // File — stream instead of buffering
    const result = storage.createReadStream(storagePath)
    if (!result) {
      return reply.code(404).send({ error: 'Not found' })
    }

    return reply
      .header('Content-Type', getContentType(storagePath))
      .header('Content-Length', info.size)
      .header('ETag', info.etag)
      .header('Cache-Control', 'no-cache')
      .send(result.stream)
  })

  // HEAD /storage/:user/* — metadata only
  fastify.head('/storage/:user/*', async (request, reply) => {
    if (!checkUsername(request, reply)) return

    const storagePath = getStoragePath(request)

    if (hasDotfile(storagePath)) {
      return reply.code(404).send()
    }

    const { authorized, error, status } = await checkAuth(request, 'HEAD')
    if (!authorized) {
      const code = status || 401
      if (code === 401) reply.header('WWW-Authenticate', 'Bearer')
      return reply.code(code).send()
    }

    const info = await storage.stat(storagePath)
    if (!info) {
      return reply.code(404).send()
    }

    // Conditional HEAD
    const cond = checkIfNoneMatchForGet(request.headers['if-none-match'], info.etag)
    if (!cond.ok) {
      return reply.code(304).send()
    }

    reply
      .header('Content-Type', info.isDirectory ? 'application/ld+json' : getContentType(storagePath))
      .header('ETag', info.etag)
      .header('Cache-Control', 'no-cache')

    if (!info.isDirectory) {
      reply.header('Content-Length', info.size)
    }

    return reply.code(200).send()
  })

  // PUT /storage/:user/* — write file
  fastify.put('/storage/:user/*', async (request, reply) => {
    if (!checkUsername(request, reply)) return

    // Respect readOnly mode
    if (request.config?.readOnly) {
      return reply.code(405).send({ error: 'Method Not Allowed', message: 'Server is in read-only mode' })
    }

    const storagePath = getStoragePath(request)

    if (hasDotfile(storagePath)) {
      return reply.code(403).send({ error: 'Cannot write to dotfiles' })
    }

    const { authorized, error, status } = await checkAuth(request, 'PUT')
    if (!authorized) {
      const code = status || 401
      if (code === 401) reply.header('WWW-Authenticate', 'Bearer')
      return reply.code(code).send({ error })
    }

    // Directories end with / — can't PUT to a directory
    if (storagePath.endsWith('/')) {
      return reply.code(400).send({ error: 'Cannot PUT to a folder path' })
    }

    // Conditional write — use shared utilities
    const existing = await storage.stat(storagePath)

    const ifMatchResult = checkIfMatch(request.headers['if-match'], existing?.etag || null)
    if (!ifMatchResult.ok) {
      return reply.code(ifMatchResult.status).send({ error: ifMatchResult.error })
    }

    const ifNoneMatchResult = checkIfNoneMatchForWrite(request.headers['if-none-match'], existing?.etag || null)
    if (!ifNoneMatchResult.ok) {
      return reply.code(ifNoneMatchResult.status).send({ error: ifNoneMatchResult.error })
    }

    const content = Buffer.isBuffer(request.body) ? request.body : Buffer.from(request.body || '')
    const success = await storage.write(storagePath, content)
    if (!success) {
      return reply.code(500).send({ error: 'Write failed' })
    }

    const newStat = await storage.stat(storagePath)
    const statusCode = existing ? 200 : 201

    return reply
      .code(statusCode)
      .header('ETag', newStat?.etag || '')
      .send()
  })

  // DELETE /storage/:user/* — delete file
  fastify.delete('/storage/:user/*', async (request, reply) => {
    if (!checkUsername(request, reply)) return

    // Respect readOnly mode
    if (request.config?.readOnly) {
      return reply.code(405).send({ error: 'Method Not Allowed', message: 'Server is in read-only mode' })
    }

    const storagePath = getStoragePath(request)

    if (hasDotfile(storagePath)) {
      return reply.code(403).send({ error: 'Cannot delete dotfiles' })
    }

    const { authorized, error, status } = await checkAuth(request, 'DELETE')
    if (!authorized) {
      const code = status || 401
      if (code === 401) reply.header('WWW-Authenticate', 'Bearer')
      return reply.code(code).send({ error })
    }

    const existing = await storage.stat(storagePath)
    if (!existing) {
      return reply.code(404).send({ error: 'Not found' })
    }

    // Conditional delete — use shared utility
    const ifMatchResult = checkIfMatch(request.headers['if-match'], existing.etag)
    if (!ifMatchResult.ok) {
      return reply.code(ifMatchResult.status).send({ error: ifMatchResult.error })
    }

    const success = await storage.remove(storagePath)
    if (!success) {
      return reply.code(500).send({ error: 'Delete failed' })
    }

    return reply
      .code(200)
      .header('ETag', existing.etag)
      .send()
  })

  fastify.log.info(`remoteStorage enabled for user: ${username}`)
}

export default remoteStoragePlugin
