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
      return { authorized: false, webId: null, error: error || 'Unauthorized' }
    }

    // If ownerWebId is set, only the owner can access storage
    if (ownerWebId && webId !== ownerWebId) {
      return { authorized: false, webId, error: 'Forbidden' }
    }

    return { authorized: true, webId }
  }

  // GET /storage/:user/* — read file or folder
  fastify.get('/storage/:user/*', async (request, reply) => {
    const storagePath = getStoragePath(request)

    const { authorized, error } = await checkAuth(request, 'GET')
    if (!authorized) {
      return reply.code(401).header('WWW-Authenticate', 'Bearer').send({ error })
    }

    const info = await storage.stat(storagePath)
    if (!info) {
      return reply.code(404).send({ error: 'Not found' })
    }

    // Conditional GET
    const ifNoneMatch = request.headers['if-none-match']
    if (ifNoneMatch && ifNoneMatch === info.etag) {
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
        // Skip hidden files (ACLs, metadata)
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

    // File
    const content = await storage.read(storagePath)
    if (content === null) {
      return reply.code(404).send({ error: 'Not found' })
    }

    return reply
      .header('Content-Type', getContentType(storagePath))
      .header('Content-Length', content.length)
      .header('ETag', info.etag)
      .header('Cache-Control', 'no-cache')
      .send(content)
  })

  // HEAD /storage/:user/* — metadata only
  fastify.head('/storage/:user/*', async (request, reply) => {
    const storagePath = getStoragePath(request)

    const { authorized, error } = await checkAuth(request, 'HEAD')
    if (!authorized) {
      return reply.code(401).header('WWW-Authenticate', 'Bearer').send()
    }

    const info = await storage.stat(storagePath)
    if (!info) {
      return reply.code(404).send()
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
    const storagePath = getStoragePath(request)

    const { authorized, error } = await checkAuth(request, 'PUT')
    if (!authorized) {
      return reply.code(401).header('WWW-Authenticate', 'Bearer').send({ error })
    }

    // Directories end with / — can't PUT to a directory
    if (storagePath.endsWith('/')) {
      return reply.code(400).send({ error: 'Cannot PUT to a folder path' })
    }

    // Conditional write
    const ifMatch = request.headers['if-match']
    const ifNoneMatch = request.headers['if-none-match']
    const existing = await storage.stat(storagePath)

    if (ifMatch && (!existing || existing.etag !== ifMatch)) {
      return reply.code(412).send({ error: 'Precondition failed' })
    }
    if (ifNoneMatch === '*' && existing) {
      return reply.code(412).send({ error: 'Resource already exists' })
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
    const storagePath = getStoragePath(request)

    const { authorized, error } = await checkAuth(request, 'DELETE')
    if (!authorized) {
      return reply.code(401).header('WWW-Authenticate', 'Bearer').send({ error })
    }

    const existing = await storage.stat(storagePath)
    if (!existing) {
      return reply.code(404).send({ error: 'Not found' })
    }

    // Conditional delete
    const ifMatch = request.headers['if-match']
    if (ifMatch && existing.etag !== ifMatch) {
      return reply.code(412).send({ error: 'Precondition failed' })
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
