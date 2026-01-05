/**
 * Collections endpoint handler
 * Returns followers/following as OrderedCollection
 */

import { getFollowers, getFollowing, getFollowerCount, getFollowingCount } from '../store.js'

/**
 * Create collections handler
 * @param {object} config - AP configuration
 * @returns {Function} Fastify handler
 */
export function createCollectionsHandler(config) {
  return async (request, reply, collectionType) => {
    const protocol = request.headers['x-forwarded-proto'] || request.protocol
    const host = request.headers['x-forwarded-host'] || request.hostname
    const baseUrl = `${protocol}://${host}`
    const profileUrl = `${baseUrl}/profile/card`

    let items, totalItems

    if (collectionType === 'followers') {
      const followers = getFollowers()
      items = followers.map(f => f.actor)
      totalItems = getFollowerCount()
    } else {
      const following = getFollowing()
      items = following.map(f => f.actor)
      totalItems = getFollowingCount()
    }

    const collection = {
      '@context': 'https://www.w3.org/ns/activitystreams',
      type: 'OrderedCollection',
      id: `${profileUrl}/${collectionType}`,
      totalItems,
      orderedItems: items
    }

    return reply
      .header('Content-Type', 'application/activity+json')
      .send(collection)
  }
}

export default { createCollectionsHandler }
