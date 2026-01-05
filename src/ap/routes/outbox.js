/**
 * Outbox endpoint handler
 * Returns user's activities as OrderedCollection
 */

import { getPosts } from '../store.js'

/**
 * Create outbox handler
 * @param {object} config - AP configuration
 * @param {object} keypair - RSA keypair
 * @returns {Function} Fastify handler
 */
export function createOutboxHandler(config, keypair) {
  return async (request, reply) => {
    const protocol = request.headers['x-forwarded-proto'] || request.protocol
    const host = request.headers['x-forwarded-host'] || request.hostname
    const baseUrl = `${protocol}://${host}`
    const profileUrl = `${baseUrl}/profile/card`
    const actorId = `${profileUrl}#me`

    const posts = getPosts(20)

    const collection = {
      '@context': 'https://www.w3.org/ns/activitystreams',
      type: 'OrderedCollection',
      id: `${profileUrl}/outbox`,
      totalItems: posts.length,
      orderedItems: posts.map(p => ({
        type: 'Create',
        actor: actorId,
        published: p.published,
        object: {
          type: 'Note',
          id: p.id,
          content: p.content,
          published: p.published,
          attributedTo: actorId,
          to: ['https://www.w3.org/ns/activitystreams#Public'],
          cc: [`${profileUrl}/followers`],
          ...(p.in_reply_to ? { inReplyTo: p.in_reply_to } : {})
        }
      }))
    }

    return reply
      .header('Content-Type', 'application/activity+json')
      .send(collection)
  }
}

export default { createOutboxHandler }
