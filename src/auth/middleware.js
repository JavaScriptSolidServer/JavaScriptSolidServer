/**
 * Authorization middleware
 * Combines authentication (token verification) with WAC checking
 * Supports both simple Bearer tokens and Solid-OIDC DPoP tokens
 */

import { getWebIdFromRequestAsync } from './token.js';
import { checkAccess, getRequiredMode } from '../wac/checker.js';
import * as storage from '../storage/filesystem.js';

/**
 * Check if request is authorized
 * @param {object} request - Fastify request
 * @param {object} reply - Fastify reply
 * @returns {Promise<{authorized: boolean, webId: string|null, wacAllow: string, authError: string|null}>}
 */
export async function authorize(request, reply) {
  const urlPath = request.url.split('?')[0];
  const method = request.method;

  // Skip auth for .acl files (they need special handling)
  // and for OPTIONS (CORS preflight)
  if (urlPath.endsWith('.acl') || method === 'OPTIONS') {
    return { authorized: true, webId: null, wacAllow: 'user="read write append control", public="read write append"', authError: null };
  }

  // Get WebID from token (supports both simple and Solid-OIDC tokens)
  const { webId, error: authError } = await getWebIdFromRequestAsync(request);

  // Get resource info
  const stats = await storage.stat(urlPath);
  const resourceExists = stats !== null;
  const isContainer = stats?.isDirectory || urlPath.endsWith('/');

  // Build resource URL
  const resourceUrl = `${request.protocol}://${request.hostname}${urlPath}`;

  // Get required access mode for this method
  const requiredMode = getRequiredMode(method);

  // For write operations on non-existent resources, check parent container
  let checkPath = urlPath;
  let checkUrl = resourceUrl;
  let checkIsContainer = isContainer;

  if (!resourceExists && (method === 'PUT' || method === 'POST' || method === 'PATCH')) {
    // Check write permission on parent container
    const parentPath = getParentPath(urlPath);
    checkPath = parentPath;
    checkUrl = `${request.protocol}://${request.hostname}${parentPath}`;
    checkIsContainer = true;
  }

  // Check WAC permissions
  const { allowed, wacAllow } = await checkAccess({
    resourceUrl: checkUrl,
    resourcePath: checkPath,
    isContainer: checkIsContainer,
    agentWebId: webId,
    requiredMode
  });

  return { authorized: allowed, webId, wacAllow, authError };
}

/**
 * Get parent container path
 */
function getParentPath(path) {
  const normalized = path.endsWith('/') ? path.slice(0, -1) : path;
  const lastSlash = normalized.lastIndexOf('/');
  if (lastSlash <= 0) return '/';
  return normalized.substring(0, lastSlash + 1);
}

/**
 * Handle unauthorized request
 * @param {object} reply - Fastify reply
 * @param {boolean} isAuthenticated - Whether user is authenticated
 * @param {string} wacAllow - WAC-Allow header value
 * @param {string|null} authError - Authentication error message (for DPoP failures)
 * @param {string|null} issuer - IdP issuer URL for WWW-Authenticate header
 */
export function handleUnauthorized(reply, isAuthenticated, wacAllow, authError = null, issuer = null) {
  reply.header('WAC-Allow', wacAllow);

  if (!isAuthenticated) {
    // Not authenticated - return 401 with WWW-Authenticate header
    // Solid-OIDC requires DPoP authentication
    const realm = issuer || 'Solid';
    reply.header('WWW-Authenticate', `DPoP realm="${realm}", Bearer realm="${realm}"`);
    return reply.code(401).send({
      error: 'Unauthorized',
      message: authError || 'Authentication required'
    });
  } else {
    // Authenticated but not authorized - return 403
    return reply.code(403).send({
      error: 'Forbidden',
      message: 'Access denied'
    });
  }
}
