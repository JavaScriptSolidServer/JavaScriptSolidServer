/**
 * Authorization middleware
 * Combines authentication (token verification) with WAC checking
 * Supports both simple Bearer tokens and Solid-OIDC DPoP tokens
 */

import { getWebIdFromRequestAsync } from './token.js';
import { checkAccess, getRequiredMode } from '../wac/checker.js';
import { AccessMode } from '../wac/parser.js';
import * as storage from '../storage/filesystem.js';
import { getEffectiveUrlPath } from '../utils/url.js';

/**
 * Check if request is authorized
 * @param {object} request - Fastify request
 * @param {object} reply - Fastify reply
 * @param {object} options - Optional settings
 * @param {string} options.requiredMode - Override the required access mode (e.g., 'Write' for git push)
 * @returns {Promise<{authorized: boolean, webId: string|null, wacAllow: string, authError: string|null}>}
 */
export async function authorize(request, reply, options = {}) {
  const urlPath = request.url.split('?')[0];
  const method = request.method;

  // OPTIONS is always allowed (CORS preflight)
  if (method === 'OPTIONS') {
    return { authorized: true, webId: null, wacAllow: 'user="read write append control", public="read write append"', authError: null };
  }

  // Get WebID from token (supports both simple and Solid-OIDC tokens)
  const { webId, error: authError } = await getWebIdFromRequestAsync(request);

  // ACL files require special handling - check Control permission on protected resource
  if (urlPath.endsWith('.acl')) {
    return authorizeAclAccess(request, urlPath, method, webId, authError);
  }

  // Log auth failures for debugging
  if (authError) {
    request.log.warn({ authError, method, urlPath, hasAuth: !!request.headers.authorization }, 'Auth error');
  }

  // Get effective storage path (includes pod name in subdomain mode)
  const storagePath = getEffectiveUrlPath(request);

  // Get resource info
  const stats = await storage.stat(storagePath);
  const resourceExists = stats !== null;
  const isContainer = stats?.isDirectory || urlPath.endsWith('/');

  // Build resource URL (uses actual request hostname which may be subdomain)
  const resourceUrl = `${request.protocol}://${request.hostname}${urlPath}`;

  // Get required access mode - use override if provided, otherwise derive from method
  const requiredMode = options.requiredMode || getRequiredMode(method);

  // For write operations on non-existent resources, check parent container
  let checkPath = storagePath;
  let checkUrl = resourceUrl;
  let checkIsContainer = isContainer;

  if (!resourceExists && (method === 'PUT' || method === 'POST' || method === 'PATCH')) {
    // Check write permission on parent container
    const parentPath = getParentPath(storagePath);
    checkPath = parentPath;
    // For URL, also need to get parent
    const parentUrlPath = getParentPath(urlPath);
    checkUrl = `${request.protocol}://${request.hostname}${parentUrlPath}`;
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

/**
 * Authorize access to ACL files
 * ACL files require acl:Control permission on the resource they protect
 *
 * @param {object} request - Fastify request
 * @param {string} urlPath - URL path to the ACL file
 * @param {string} method - HTTP method
 * @param {string|null} webId - Authenticated user's WebID
 * @param {string|null} authError - Authentication error if any
 * @returns {Promise<{authorized: boolean, webId: string|null, wacAllow: string, authError: string|null}>}
 */
async function authorizeAclAccess(request, urlPath, method, webId, authError) {
  // Determine the protected resource URL
  // /foo/.acl protects /foo/ (container)
  // /foo/bar.acl protects /foo/bar (resource)
  const protectedPath = urlPath.replace(/\.acl$/, '');
  const isProtectedContainer = protectedPath.endsWith('/');
  const protectedUrl = `${request.protocol}://${request.hostname}${protectedPath}`;

  // Get storage path for the protected resource
  const storagePath = getEffectiveUrlPath(request).replace(/\.acl$/, '');

  // All ACL operations require Control permission on the protected resource
  // This is stricter than the Solid spec (which allows Read for reading ACLs)
  // but simpler and more secure
  const { allowed, wacAllow } = await checkAccess({
    resourceUrl: protectedUrl,
    resourcePath: storagePath,
    isContainer: isProtectedContainer,
    agentWebId: webId,
    requiredMode: AccessMode.CONTROL
  });

  return { authorized: allowed, webId, wacAllow, authError };
}
