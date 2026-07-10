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
 *   const webId = await getAgent(request);   // string | null
 *
 * Covers every token scheme the server itself accepts, uniformly:
 * IdP-issued Bearer tokens, Solid-OIDC DPoP, Nostr NIP-98 signatures,
 * and LWS10-CID. Authentication only — deliberately not authorization:
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
 * @param {object} request - Fastify request (or any object with `headers`)
 * @returns {Promise<string|null>} verified WebID, or null when anonymous /
 *   invalid — never throws on bad credentials
 */
export async function getAgent(request) {
  try {
    const { webId } = await getWebIdFromRequestAsync(request);
    return webId || null;
  } catch {
    return null;
  }
}
