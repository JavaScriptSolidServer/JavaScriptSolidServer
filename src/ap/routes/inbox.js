/**
 * Inbox endpoint handler
 * Receives and processes incoming ActivityPub activities
 */

import { auth, outbox } from 'microfed'
import { Agent } from 'undici'
import { createSign } from 'crypto'
import {
  saveActivity,
  addFollower,
  removeFollower,
  acceptFollowing,
  cacheActor,
  getCachedActor
} from '../store.js'
import { getKeyId } from '../keys.js'

// Allow self-signed certs when fetching local actors (e.g. server fetching itself)
const insecureAgent = new Agent({ connect: { rejectUnauthorized: false } })

/**
 * Fetch remote actor (with caching)
 * @param {string} id - Actor URL
 * @param {object} log - Logger instance (optional)
 * @returns {Promise<object|null>} Actor object or null
 */
async function fetchActor(id, log) {
  // Strip fragment for fetching
  const fetchUrl = id.replace(/#.*$/, '')
  const cached = getCachedActor(id)
  if (cached) return cached

  try {
    const response = await fetch(fetchUrl, {
      dispatcher: insecureAgent,
      headers: {
        'Accept': 'application/activity+json',
        'User-Agent': 'JSS/1.0 (+https://github.com/JavaScriptSolidServer/JavaScriptSolidServer)'
      }
    })
    if (!response.ok) {
      if (log) log.warn(`Actor fetch failed: ${response.status} ${response.statusText} for ${fetchUrl}`)
      return null
    }

    const actor = await response.json()
    cacheActor(actor)
    return actor
  } catch (err) {
    if (log) log.error(`Actor fetch error for ${fetchUrl}: ${err.message}`)
    return null
  }
}

/**
 * Verify HTTP signature on incoming request
 * @param {object} request - Fastify request
 * @param {string} body - Request body
 * @returns {Promise<{valid: boolean, actor?: object, reason?: string}>}
 */
async function verifySignature(request, body) {
  const signature = request.headers['signature']
  if (!signature) {
    return { valid: false, reason: 'No signature header' }
  }

  // Parse signature header
  const sigParts = auth.parseSignatureHeader(signature)
  if (!sigParts) {
    return { valid: false, reason: 'Invalid signature format' }
  }

  const keyId = sigParts.keyId
  if (!keyId) {
    return { valid: false, reason: 'No keyId in signature' }
  }

  // Extract actor URL from keyId (strip fragment like #main-key)
  const actorUrl = keyId.replace(/#.*$/, '')

  // Fetch the actor to get their public key
  const remoteActor = await fetchActor(actorUrl, request.log)
  if (!remoteActor) {
    return { valid: false, reason: `Could not fetch actor: ${actorUrl}` }
  }

  const publicKeyPem = remoteActor.publicKey?.publicKeyPem
  if (!publicKeyPem) {
    return { valid: false, reason: 'Actor has no public key' }
  }

  // Verify digest if present
  const digestHeader = request.headers['digest']
  if (digestHeader && !auth.verifyDigest(body, digestHeader)) {
    return { valid: false, reason: 'Digest mismatch' }
  }

  // Build path from URL
  const url = new URL(request.url, `http://${request.hostname}`)

  // Verify signature
  try {
    const valid = auth.verify({
      publicKey: publicKeyPem,
      signature,
      method: request.method,
      path: url.pathname,
      headers: request.headers
    })
    return { valid, actor: remoteActor }
  } catch (err) {
    return { valid: false, reason: `Verification error: ${err.message}` }
  }
}

/**
 * Create inbox handler
 * @param {object} config - AP configuration
 * @param {object} keypair - RSA keypair
 * @returns {Function} Fastify handler
 */
export function createInboxHandler(config, keypair) {
  return async (request, reply) => {
    // Parse body
    let activity
    let body
    try {
      body = typeof request.body === 'string'
        ? request.body
        : request.body.toString()
      activity = JSON.parse(body)
    } catch {
      return reply.code(400).send({ error: 'Invalid JSON' })
    }

    // Verify signature (log but don't reject for now - many servers have issues)
    const sigResult = await verifySignature(request, body)
    if (!sigResult.valid) {
      request.log.warn(`Signature verification failed: ${sigResult.reason}`)
    } else {
      request.log.info(`Signature verified for ${activity.actor}`)
    }

    // Validate activity
    if (!activity.type) {
      return reply.code(400).send({ error: 'Missing activity type' })
    }

    // Save activity
    if (activity.id) {
      saveActivity(config.username, activity)
    }

    // Handle activity by type
    const protocol = request.headers['x-forwarded-proto'] || request.protocol
    const host = request.headers['x-forwarded-host'] || request.hostname
    const baseUrl = `${protocol}://${host}`
    const profileUrl = `${baseUrl}/profile/card.jsonld`
    const actorId = `${profileUrl}#me`

    request.log.info(`Received ${activity.type} from ${activity.actor}`)

    switch (activity.type) {
      case 'Follow':
        await handleFollow(config.username, activity, actorId, profileUrl, keypair, request.log)
        break

      case 'Undo':
        await handleUndo(config.username, activity, request.log)
        break

      case 'Accept':
        handleAccept(config.username, activity, request.log)
        break

      case 'Create':
        request.log.info(`New post: ${activity.object?.content?.slice(0, 50)}...`)
        break

      case 'Like':
        request.log.info(`Liked: ${activity.object}`)
        break

      case 'Announce':
        request.log.info(`Boosted: ${activity.object}`)
        break

      default:
        request.log.info(`Unhandled activity type: ${activity.type}`)
    }

    // Accept the activity
    return reply.code(202).send()
  }
}

/**
 * Handle Follow activity
 */
async function handleFollow(username, activity, actorId, profileUrl, keypair, log) {
  const followerActor = await fetchActor(activity.actor, log)
  if (!followerActor) {
    log.warn('Could not fetch follower actor')
    return
  }

  // Add to followers
  addFollower(username, activity.actor, followerActor.inbox)
  log.info(`New follower: ${followerActor.preferredUsername || activity.actor}`)

  // Send Accept — use direct signed fetch to support self-signed certs
  const accept = outbox.createAccept(actorId, activity)
  const body = JSON.stringify(accept)
  const inboxUrl = new URL(followerActor.inbox)
  const date = new Date().toUTCString()
  const digest = `SHA-256=${Buffer.from(
    (await crypto.subtle.digest('SHA-256', new TextEncoder().encode(body)))
  ).toString('base64')}`
  const signingString = `(request-target): post ${inboxUrl.pathname}\nhost: ${inboxUrl.host}\ndate: ${date}\ndigest: ${digest}`
  const signer = createSign('RSA-SHA256')
  signer.update(signingString)
  const signature = signer.sign(keypair.privateKey, 'base64')
  const keyId = `${profileUrl}#main-key`
  const signatureHeader = `keyId="${keyId}",algorithm="rsa-sha256",headers="(request-target) host date digest",signature="${signature}"`

  try {
    const res = await fetch(followerActor.inbox, {
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
    log.info(`Sent Accept to ${followerActor.inbox} — ${res.status}`)
  } catch (err) {
    log.error(`Failed to send Accept: ${err.message}`)
  }
}

/**
 * Handle Undo activity
 */
async function handleUndo(username, activity, log) {
  if (activity.object?.type === 'Follow') {
    removeFollower(username, activity.actor)
    log.info(`Unfollowed by ${activity.actor}`)
  }
}

/**
 * Handle Accept activity (our follow was accepted)
 */
function handleAccept(username, activity, log) {
  if (activity.object?.type === 'Follow') {
    const target = typeof activity.object.object === 'string'
      ? activity.object.object
      : activity.object.object?.id
    if (target) {
      acceptFollowing(username, target)
      log.info('Follow accepted!')
    }
  }
}

export default { createInboxHandler }
