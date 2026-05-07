/**
 * Outbox endpoint handler
 * Returns user's activities as OrderedCollection
 * Accepts POST to create new posts and deliver to followers
 */

import { outbox } from 'microfed'
import { Agent } from 'undici'
import { createSign, randomUUID } from 'crypto'
import { getPosts, getPost, getPostById, savePost, getFollowerInboxes } from '../store.js'

// Allow self-signed certs when delivering to local inboxes
const insecureAgent = new Agent({ connect: { rejectUnauthorized: false } })

/**
 * Send a signed ActivityPub POST to an inbox, tolerating self-signed TLS
 */
async function sendSigned(inbox, activity, privateKey, keyId) {
  const body = JSON.stringify(activity)
  const inboxUrl = new URL(inbox)
  const date = new Date().toUTCString()
  const digest = `SHA-256=${Buffer.from(
    await crypto.subtle.digest('SHA-256', new TextEncoder().encode(body))
  ).toString('base64')}`
  const signingString = `(request-target): post ${inboxUrl.pathname}\nhost: ${inboxUrl.host}\ndate: ${date}\ndigest: ${digest}`
  const signer = createSign('RSA-SHA256')
  signer.update(signingString)
  const signature = signer.sign(privateKey, 'base64')
  const signatureHeader = `keyId="${keyId}",algorithm="rsa-sha256",headers="(request-target) host date digest",signature="${signature}"`

  return fetch(inbox, {
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
}

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
    const profileUrl = `${baseUrl}/profile/card.jsonld`
    const actorId = `${profileUrl}#me`

    const posts = getPosts(config.username, 20)

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
    const profileUrl = `${baseUrl}/profile/card.jsonld`
    const actorId = `${profileUrl}#me`

    // Parse body
    let activity
    try {
      const raw = typeof request.body === 'string'
        ? request.body
        : request.body.toString()
      activity = JSON.parse(raw)
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
        config.username,
        activity.object.id,
        activity.object.content,
        activity.object.inReplyTo || null
      )
    }

    // Deliver to followers
    const inboxes = getFollowerInboxes(config.username)
    request.log.info(`Delivering to ${inboxes.length} follower(s)`)

    const keyId = `${profileUrl}#main-key`
    const deliveryResults = await Promise.allSettled(
      inboxes.map(inbox => sendSigned(inbox, activity, keypair.privateKey, keyId))
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

/**
 * Create post object handler
 * GET /posts/:id returns ActivityStreams Note object for permalink fetches.
 *
 * @param {object} config - AP configuration
 * @returns {Function} Fastify handler
 */
export function createPostObjectHandler(config) {
  return async (request, reply) => {
    const postId = `${request.params.id}`
    const protocol = request.headers['x-forwarded-proto'] || request.protocol
    const host = request.headers['x-forwarded-host'] || request.hostname
    const baseUrl = `${protocol}://${host}`
    const profileUrl = `${baseUrl}/profile/card.jsonld`
    const actorId = `${profileUrl}#me`

    // Stored post IDs are full URLs. Try direct URL match first, then fallback.
    const fullId = `${baseUrl}/posts/${postId}`
    let post = getPost(config.username, fullId)
    if (!post) post = getPost(config.username, postId)
    if (!post) post = getPostById(fullId)
    if (!post) post = getPostById(postId)

    if (!post) {
      return reply.code(404).send({ error: 'Post not found' })
    }

    const note = {
      '@context': 'https://www.w3.org/ns/activitystreams',
      type: 'Note',
      id: post.id,
      content: post.content,
      published: post.published,
      attributedTo: actorId,
      to: ['https://www.w3.org/ns/activitystreams#Public'],
      cc: [`${profileUrl}/followers`],
      ...(post.in_reply_to ? { inReplyTo: post.in_reply_to } : {})
    }

    return reply
      .header('Content-Type', 'application/activity+json')
      .send(note)
  }
}

export default { createOutboxHandler, createOutboxPostHandler, createPostObjectHandler }
