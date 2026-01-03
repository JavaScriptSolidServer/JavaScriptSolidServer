/**
 * WAC (Web Access Control) Checker
 * Checks if an agent has permission to access a resource
 */

import * as storage from '../storage/filesystem.js';
import { parseAcl, AccessMode, AgentClass } from './parser.js';
import { getAclUrl } from '../ldp/headers.js';

/**
 * Check if agent has required access mode for resource
 * @param {object} options
 * @param {string} options.resourceUrl - Full URL of the resource
 * @param {string} options.resourcePath - Path portion of the resource URL
 * @param {boolean} options.isContainer - Whether resource is a container
 * @param {string|null} options.agentWebId - WebID of the agent (null for unauthenticated)
 * @param {string} options.requiredMode - Required access mode (from AccessMode)
 * @returns {Promise<{allowed: boolean, wacAllow: string}>}
 */
export async function checkAccess({
  resourceUrl,
  resourcePath,
  isContainer,
  agentWebId,
  requiredMode
}) {
  // Find applicable ACL
  const aclResult = await findApplicableAcl(resourceUrl, resourcePath, isContainer);

  if (!aclResult) {
    // No ACL found - deny by default (restrictive mode)
    // Security: Require explicit ACL for any access
    return { allowed: false, wacAllow: 'user="", public=""' };
  }

  const { authorizations, isDefault, targetUrl: aclContainerUrl } = aclResult;

  // Check authorizations
  // Note: For default ACLs, we check if the ACL's default rules apply to the actual resource URL
  const allowed = checkAuthorizations(
    authorizations,
    resourceUrl,  // Use actual resource URL, not the ACL container URL
    agentWebId,
    requiredMode,
    isDefault
  );

  // Calculate WAC-Allow header
  const wacAllow = calculateWacAllow(authorizations, resourceUrl, agentWebId, isDefault);

  return { allowed, wacAllow };
}

/**
 * Find the applicable ACL for a resource
 * Walks up the path hierarchy looking for .acl files
 */
async function findApplicableAcl(resourceUrl, resourcePath, isContainer) {
  // First check for resource-specific ACL
  const resourceAclPath = isContainer
    ? (resourcePath.endsWith('/') ? resourcePath : resourcePath + '/') + '.acl'
    : resourcePath + '.acl';

  if (await storage.exists(resourceAclPath)) {
    const content = await storage.read(resourceAclPath);
    if (content) {
      const aclUrl = getAclUrl(resourceUrl, isContainer);
      const authorizations = await parseAcl(content.toString(), aclUrl);
      return { authorizations, isDefault: false, targetUrl: resourceUrl };
    }
  }

  // Walk up the hierarchy looking for default ACLs
  // Track both storage path (for file lookup) and URL path (for URL construction)
  let currentStoragePath = resourcePath;
  let currentUrlPath = new URL(resourceUrl).pathname;

  while (currentStoragePath && currentStoragePath !== '/') {
    // Get parent container
    const parentStoragePath = getParentPath(currentStoragePath);
    const parentAclPath = parentStoragePath + '.acl';

    if (await storage.exists(parentAclPath)) {
      const content = await storage.read(parentAclPath);
      if (content) {
        // Get parent URL path and construct full URL
        const parentUrlPath = getParentPath(currentUrlPath);
        const origin = resourceUrl.substring(0, resourceUrl.indexOf('/', 8));
        const parentUrl = origin + parentUrlPath;
        const parentAclUrl = getAclUrl(parentUrl, true); // Container ACL URL
        const authorizations = await parseAcl(content.toString(), parentAclUrl);
        return { authorizations, isDefault: true, targetUrl: parentUrl };
      }
    }

    currentStoragePath = parentStoragePath;
    currentUrlPath = getParentPath(currentUrlPath);
  }

  // Check root ACL
  if (await storage.exists('/.acl')) {
    const content = await storage.read('/.acl');
    if (content) {
      const rootUrl = resourceUrl.substring(0, resourceUrl.indexOf('/', 8) + 1);
      const rootAclUrl = getAclUrl(rootUrl, true); // Root container ACL URL
      const authorizations = await parseAcl(content.toString(), rootAclUrl);
      return { authorizations, isDefault: true, targetUrl: rootUrl };
    }
  }

  return null;
}

/**
 * Get parent container path
 */
function getParentPath(path) {
  // Remove trailing slash
  const normalized = path.endsWith('/') ? path.slice(0, -1) : path;
  const lastSlash = normalized.lastIndexOf('/');
  if (lastSlash <= 0) return '/';
  return normalized.substring(0, lastSlash + 1);
}

/**
 * Check if any authorization grants the required mode
 */
function checkAuthorizations(authorizations, targetUrl, agentWebId, requiredMode, isDefault) {
  for (const auth of authorizations) {
    // For default ACLs, check if auth has default rules and matches target
    // For direct ACLs, check if accessTo matches target
    if (isDefault) {
      // Skip if no default rules defined
      if (auth.default.length === 0) continue;
      // Skip if target URL doesn't match any default URL prefix
      if (!auth.default.some(d => urlMatches(d, targetUrl, true))) continue;
    } else {
      // Skip if accessTo doesn't match target
      if (!auth.accessTo.some(a => urlMatches(a, targetUrl))) continue;
    }

    // Check if agent is authorized
    const agentAuthorized = isAgentAuthorized(auth, agentWebId);
    if (!agentAuthorized) continue;

    // Check if mode is granted
    if (auth.modes.includes(requiredMode)) {
      return true;
    }

    // Write implies Append
    if (requiredMode === AccessMode.APPEND && auth.modes.includes(AccessMode.WRITE)) {
      return true;
    }
  }

  return false;
}

/**
 * Check if the agent is authorized by an authorization rule
 */
function isAgentAuthorized(auth, agentWebId) {
  // Check specific agent
  if (agentWebId && auth.agents.includes(agentWebId)) {
    return true;
  }

  // Check agent classes
  for (const agentClass of auth.agentClasses) {
    // foaf:Agent - everyone (including unauthenticated)
    if (agentClass === AgentClass.AGENT || agentClass === 'foaf:Agent') {
      return true;
    }

    // acl:AuthenticatedAgent - any authenticated user
    if (agentWebId && (agentClass === AgentClass.AUTHENTICATED || agentClass === 'acl:AuthenticatedAgent')) {
      return true;
    }
  }

  // TODO: Check agent groups (requires fetching and parsing group documents)

  return false;
}

/**
 * Check if URLs match (handles trailing slashes)
 * @param {string} pattern - The ACL URL pattern
 * @param {string} url - The target URL to check
 * @param {boolean} prefixMatch - If true, check if url starts with pattern (for acl:default)
 */
function urlMatches(pattern, url, prefixMatch = false) {
  const normalizedPattern = pattern.replace(/\/$/, '');
  const normalizedUrl = url.replace(/\/$/, '');

  if (prefixMatch) {
    // For default ACLs: target must be same as or under the pattern
    return normalizedUrl === normalizedPattern ||
           normalizedUrl.startsWith(normalizedPattern + '/');
  }

  return normalizedPattern === normalizedUrl;
}

/**
 * Calculate WAC-Allow header value
 */
function calculateWacAllow(authorizations, targetUrl, agentWebId, isDefault) {
  const userModes = new Set();
  const publicModes = new Set();

  for (const auth of authorizations) {
    // Check if applies to resource - use same logic as checkAuthorizations
    if (isDefault) {
      if (auth.default.length === 0) continue;
      if (!auth.default.some(d => urlMatches(d, targetUrl, true))) continue;
    } else {
      if (!auth.accessTo.some(a => urlMatches(a, targetUrl))) continue;
    }

    // Check what modes this grants
    const modes = auth.modes.map(m => {
      if (m === AccessMode.READ || m === 'acl:Read') return 'read';
      if (m === AccessMode.WRITE || m === 'acl:Write') return 'write';
      if (m === AccessMode.APPEND || m === 'acl:Append') return 'append';
      if (m === AccessMode.CONTROL || m === 'acl:Control') return 'control';
      return null;
    }).filter(Boolean);

    // Check if public
    const isPublic = auth.agentClasses.some(c =>
      c === AgentClass.AGENT || c === 'foaf:Agent'
    );

    if (isPublic) {
      modes.forEach(m => publicModes.add(m));
    }

    // Check if user-specific
    if (agentWebId && auth.agents.includes(agentWebId)) {
      modes.forEach(m => userModes.add(m));
    }

    // Check authenticated class
    if (agentWebId && auth.agentClasses.some(c =>
      c === AgentClass.AUTHENTICATED || c === 'acl:AuthenticatedAgent'
    )) {
      modes.forEach(m => userModes.add(m));
    }
  }

  // User also gets public modes
  publicModes.forEach(m => userModes.add(m));

  const userStr = Array.from(userModes).join(' ');
  const publicStr = Array.from(publicModes).join(' ');

  return `user="${userStr}", public="${publicStr}"`;
}

/**
 * Get the required access mode for an HTTP method
 * @param {string} method - HTTP method
 * @returns {string} Access mode
 */
export function getRequiredMode(method) {
  switch (method.toUpperCase()) {
    case 'GET':
    case 'HEAD':
    case 'OPTIONS':
      return AccessMode.READ;
    case 'POST':
      return AccessMode.APPEND;
    case 'PUT':
    case 'PATCH':
    case 'DELETE':
      return AccessMode.WRITE;
    default:
      return AccessMode.READ;
  }
}
