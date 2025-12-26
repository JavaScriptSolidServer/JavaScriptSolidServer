/**
 * Authorization middleware
 * Combines authentication (token verification) with WAC checking
 */

import { getWebIdFromRequest } from './token.js';
import { checkAccess, getRequiredMode } from '../wac/checker.js';
import * as storage from '../storage/filesystem.js';

/**
 * Check if request is authorized
 * @param {object} request - Fastify request
 * @param {object} reply - Fastify reply
 * @returns {Promise<{authorized: boolean, webId: string|null, wacAllow: string}>}
 */
export async function authorize(request, reply) {
  const urlPath = request.url.split('?')[0];
  const method = request.method;

  // Skip auth for .acl files (they need special handling)
  // and for OPTIONS (CORS preflight)
  if (urlPath.endsWith('.acl') || method === 'OPTIONS') {
    return { authorized: true, webId: null, wacAllow: 'user="read write append control", public="read write append"' };
  }

  // Get WebID from token (null if not authenticated)
  const webId = getWebIdFromRequest(request);

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

  return { authorized: allowed, webId, wacAllow };
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
 */
export function handleUnauthorized(reply, isAuthenticated, wacAllow) {
  reply.header('WAC-Allow', wacAllow);

  if (!isAuthenticated) {
    // Not authenticated - return 401
    return reply.code(401).send({
      error: 'Unauthorized',
      message: 'Authentication required'
    });
  } else {
    // Authenticated but not authorized - return 403
    return reply.code(403).send({
      error: 'Forbidden',
      message: 'Access denied'
    });
  }
}
