/**
 * Outbox endpoint handler
 * Returns user's activities as OrderedCollection
 * Accepts POST to create new posts and deliver to followers
 */

import { outbox } from 'microfed'
import { getPosts, savePost, getFollowerInboxes } from '../store.js'
import { randomUUID } from 'crypto'

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

/**
 * Create outbox POST handler for creating new posts
 * @param {object} config - AP configuration
 * @param {object} keypair - RSA keypair
 * @returns {Function} Fastify handler
 */
export function createOutboxPostHandler(config, keypair) {
  return async (request, reply) => {
    const protocol = request.headers['x-forwarded-proto'] || request.protocol
    const host = request.headers['x-forwarded-host'] || request.hostname
    const baseUrl = `${protocol}://${host}`
    const profileUrl = `${baseUrl}/profile/card`
    const actorId = `${profileUrl}#me`

    // Parse body
    let activity
    try {
      activity = typeof request.body === 'string'
        ? JSON.parse(request.body)
        : request.body
    } catch {
      return reply.code(400).send({ error: 'Invalid JSON' })
    }

    // Handle direct Note posting (convenience)
    if (activity.type === 'Note' || (!activity.type && activity.content)) {
      const noteId = `${baseUrl}/posts/${randomUUID()}`
      const now = new Date().toISOString()

      const note = {
        '@context': 'https://www.w3.org/ns/activitystreams',
        type: 'Note',
        id: noteId,
        content: activity.content,
        published: now,
        attributedTo: actorId,
        to: ['https://www.w3.org/ns/activitystreams#Public'],
        cc: [`${profileUrl}/followers`],
        ...(activity.inReplyTo ? { inReplyTo: activity.inReplyTo } : {})
      }

      activity = {
        '@context': 'https://www.w3.org/ns/activitystreams',
        type: 'Create',
        id: `${noteId}/activity`,
        actor: actorId,
        published: now,
        object: note,
        to: note.to,
        cc: note.cc
      }
    }

    // Save post
    if (activity.type === 'Create' && activity.object?.type === 'Note') {
      savePost(
        activity.object.id,
        activity.object.content,
        activity.object.inReplyTo || null
      )
    }

    // Deliver to followers
    const inboxes = getFollowerInboxes()
    request.log.info(`Delivering to ${inboxes.length} follower(s)`)

    const keyId = `${profileUrl}#main-key`
    const deliveryResults = await Promise.allSettled(
      inboxes.map(inbox =>
        outbox.send({
          activity,
          inbox,
          privateKey: keypair.privateKey,
          keyId
        })
      )
    )

    const succeeded = deliveryResults.filter(r => r.status === 'fulfilled').length
    const failed = deliveryResults.filter(r => r.status === 'rejected').length

    if (failed > 0) {
      request.log.warn(`Delivery: ${succeeded} succeeded, ${failed} failed`)
    } else {
      request.log.info(`Delivered to ${succeeded} inbox(es)`)
    }

    return reply
      .code(201)
      .header('Location', activity.object?.id || activity.id)
      .send(activity)
  }
}

export default { createOutboxHandler, createOutboxPostHandler }
