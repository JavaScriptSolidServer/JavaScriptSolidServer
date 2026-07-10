/**
 * Public authentication api (#584).
 *
 * The stable import path for applications that authenticate their own
 * traffic — app plugins mounted via `appPaths` (#582), external Fastify
 * compositions, MCP-adjacent tooling. Everything in src/ is internal and
 * may move; this file is the contract.
 *
 *   import { getAgent } from 'javascript-solid-server/auth.js';
 *
 *   const agent = await getAgent(request);   // string | null
 *
 * Covers every credential scheme the server itself accepts, uniformly:
 * IdP-issued Bearer tokens, Solid-OIDC DPoP, Nostr NIP-98 signatures,
 * LWS10-CID, and WebID-TLS client certificates.
 * The returned identifier is usually an HTTP(S) WebID;
 * for NIP-98 it can be a `did:nostr:...` DID when no WebID mapping
 * exists — DID agents are first-class here, which is why this is
 * getAgent and not getWebId. Key your app's users on the string.
 *
 * Authentication only — deliberately not authorization:
 * apps under an appPaths prefix own their own permissioning (WAC stays
 * out of their jurisdiction, and `request.webId` is never set there).
 *
 * This is the pre-loader shape of the seam; when the plugin loader (#206)
 * lands, `api.auth.getAgent` will be this same function handed to
 * `activate(api)`.
 */

import { getWebIdFromRequestAsync } from './src/auth/token.js';

/**
 * Resolve the authenticated agent of a request.
 * @param {object} request - a Fastify request. Pass the real request object:
 *   Bearer verification only reads `headers`, but DPoP (Solid-OIDC),
 *   NIP-98 and LWS-CID verification also read `method`, `url`, `protocol`
 *   and `hostname` to check what the credential was signed over.
 * @returns {Promise<string|null>} the verified agent identifier — an
 *   HTTP(S) WebID, or a `did:nostr:` DID for NIP-98 agents without a
 *   WebID mapping — or null when anonymous / invalid. Never throws on
 *   bad credentials.
 */
export async function getAgent(request) {
  try {
    const { webId } = await getWebIdFromRequestAsync(request);
    return webId || null;
  } catch {
    return null;
  }
}
