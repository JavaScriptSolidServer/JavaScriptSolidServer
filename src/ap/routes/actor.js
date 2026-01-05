/**
 * Actor endpoint handler
 * Returns ActivityPub Actor JSON-LD for content negotiation
 */

/**
 * Create actor handler
 * @param {object} config - AP configuration
 * @param {object} keypair - RSA keypair
 * @returns {Function} Handler function
 */
export function createActorHandler(config, keypair) {
  return (request) => {
    // Check various proxy headers for protocol detection
    let protocol = request.headers['x-forwarded-proto']
    if (!protocol) {
      // Cloudflare uses cf-visitor: {"scheme":"https"}
      const cfVisitor = request.headers['cf-visitor']
      if (cfVisitor) {
        try {
          const parsed = JSON.parse(cfVisitor)
          protocol = parsed.scheme
        } catch { /* ignore */ }
      }
    }
    // If still no protocol and hostname looks like a public domain, assume https
    const host = request.headers['x-forwarded-host'] || request.hostname
    if (!protocol && host && !host.match(/^(localhost|127\.|192\.168\.|10\.)/)) {
      protocol = 'https'
    }
    protocol = protocol || request.protocol
    const baseUrl = `${protocol}://${host}`
    const profileUrl = `${baseUrl}/profile/card`
    const actorId = `${profileUrl}#me`

    const actor = {
      '@context': [
        'https://www.w3.org/ns/activitystreams',
        'https://w3id.org/security/v1'
      ],
      type: 'Person',
      id: actorId,
      url: profileUrl,
      preferredUsername: config.username,
      name: config.displayName,
      summary: config.summary ? `<p>${config.summary}</p>` : '',
      inbox: `${profileUrl}/inbox`,
      outbox: `${profileUrl}/outbox`,
      followers: `${profileUrl}/followers`,
      following: `${profileUrl}/following`,
      endpoints: {
        sharedInbox: `${baseUrl}/inbox`
      },
      publicKey: {
        id: `${profileUrl}#main-key`,
        owner: actorId,
        publicKeyPem: keypair.publicKey
      }
    }

    // Add Nostr identity linking via alsoKnownAs
    if (config.nostrPubkey) {
      actor.alsoKnownAs = [`did:nostr:${config.nostrPubkey}`]
    }

    return actor
  }
}

export default { createActorHandler }
