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
import { generateDatabrowserHtml, generateSolidosUiHtml } from '../mashlib/index.js';

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

  // Public mode - skip all WAC checks, allow unauthenticated access
  if (request.config?.public) {
    const modes = request.config?.readOnly ? 'read' : 'read write append';
    return { authorized: true, webId: null, wacAllow: `public="${modes}"`, authError: null };
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
 * @param {object} request - Fastify request
 * @param {object} reply - Fastify reply
 * @param {boolean} isAuthenticated - Whether user is authenticated
 * @param {string} wacAllow - WAC-Allow header value
 * @param {string|null} authError - Authentication error message (for DPoP failures)
 * @param {string|null} issuer - IdP issuer URL for WWW-Authenticate header
 */
export function handleUnauthorized(request, reply, isAuthenticated, wacAllow, authError = null, issuer = null) {
  reply.header('WAC-Allow', wacAllow);

  const statusCode = isAuthenticated ? 403 : 401;
  const realm = issuer || 'Solid';

  if (!isAuthenticated) {
    reply.header('WWW-Authenticate', `DPoP realm="${realm}", Bearer realm="${realm}"`);
  }

  // Check if browser wants HTML
  const accept = request.headers.accept || '';
  if (accept.includes('text/html')) {
    // If mashlib is enabled, serve mashlib instead of static error page
    // Mashlib has built-in login functionality via panes.runDataBrowser()
    if (request.mashlibEnabled) {
      // Use SolidOS UI if enabled, otherwise fallback to classic mashlib
      const html = request.solidosUiEnabled
        ? generateSolidosUiHtml()
        : generateDatabrowserHtml(request.url, request.mashlibCdn ? request.mashlibVersion : null);
      return reply.code(statusCode).type('text/html').send(html);
    }
    return reply.code(statusCode).type('text/html').send(getErrorPage(statusCode, isAuthenticated, request));
  }

  // Return JSON for API clients
  if (!isAuthenticated) {
    return reply.code(401).send({
      error: 'Unauthorized',
      message: authError || 'Authentication required'
    });
  } else {
    return reply.code(403).send({
      error: 'Forbidden',
      message: 'Access denied'
    });
  }
}

/**
 * Generate a beautiful error page for browsers
 */
function getErrorPage(statusCode, isAuthenticated, request) {
  const is401 = statusCode === 401;
  const title = is401 ? 'Authentication Required' : 'Access Denied';
  const subtitle = is401
    ? "This resource is protected. You'll need to sign in to continue."
    : "You're signed in, but you don't have permission to view this resource.";

  const baseUrl = `${request.protocol}://${request.hostname}`;

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>${title} - Solid Server</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }

    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      background: linear-gradient(135deg, #f5f7fa 0%, #e4e8ec 100%);
      padding: 2rem;
      color: #374151;
    }

    .container {
      max-width: 540px;
      width: 100%;
      text-align: center;
    }

    .card {
      background: white;
      border-radius: 16px;
      padding: 3rem 2.5rem;
      box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -1px rgba(0, 0, 0, 0.06);
    }

    .icon {
      width: 80px;
      height: 80px;
      margin: 0 auto 1.5rem;
      background: ${is401 ? '#fef3c7' : '#fee2e2'};
      border-radius: 50%;
      display: flex;
      align-items: center;
      justify-content: center;
      font-size: 2.5rem;
    }

    h1 {
      font-size: 1.75rem;
      font-weight: 600;
      color: #111827;
      margin-bottom: 0.75rem;
    }

    .subtitle {
      color: #6b7280;
      font-size: 1.05rem;
      line-height: 1.6;
      margin-bottom: 2rem;
    }

    .actions {
      display: flex;
      flex-direction: column;
      gap: 0.75rem;
    }

    .btn {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      gap: 0.5rem;
      padding: 0.875rem 1.5rem;
      border-radius: 10px;
      font-size: 1rem;
      font-weight: 500;
      text-decoration: none;
      transition: all 0.2s ease;
      cursor: pointer;
      border: none;
    }

    .btn-primary {
      background: linear-gradient(135deg, #7c3aed 0%, #6366f1 100%);
      color: white;
    }

    .btn-primary:hover {
      transform: translateY(-1px);
      box-shadow: 0 4px 12px rgba(124, 58, 237, 0.4);
    }

    .btn-secondary {
      background: #f3f4f6;
      color: #374151;
    }

    .btn-secondary:hover {
      background: #e5e7eb;
    }

    .divider {
      display: flex;
      align-items: center;
      margin: 2rem 0;
      color: #9ca3af;
      font-size: 0.875rem;
    }

    .divider::before,
    .divider::after {
      content: '';
      flex: 1;
      height: 1px;
      background: #e5e7eb;
    }

    .divider span {
      padding: 0 1rem;
    }

    .info-box {
      background: #f0fdf4;
      border: 1px solid #bbf7d0;
      border-radius: 10px;
      padding: 1.25rem;
      text-align: left;
    }

    .info-box h3 {
      font-size: 0.9rem;
      font-weight: 600;
      color: #166534;
      margin-bottom: 0.5rem;
      display: flex;
      align-items: center;
      gap: 0.5rem;
    }

    .info-box p {
      font-size: 0.875rem;
      color: #15803d;
      line-height: 1.5;
    }

    .footer {
      margin-top: 2rem;
      font-size: 0.8rem;
      color: #9ca3af;
    }

    .footer a {
      color: #7c3aed;
      text-decoration: none;
    }

    .footer a:hover {
      text-decoration: underline;
    }

    .status-code {
      font-size: 0.75rem;
      color: #9ca3af;
      margin-top: 1rem;
    }
  </style>
</head>
<body>
  <div class="container">
    <div class="card">
      <div class="icon">${is401 ? '🔐' : '🚫'}</div>
      <h1>${title}</h1>
      <p class="subtitle">${subtitle}</p>

      <div class="actions">
        ${is401 ? `<a href="https://solidos.solidcommunity.net/?uri=${encodeURIComponent(baseUrl + request.url)}" class="btn btn-primary">
          Open in Data Browser
        </a>` : ''}
        <a href="${baseUrl}/" class="btn btn-secondary">
          Go to Homepage
        </a>
      </div>

      <div class="divider"><span>What is this?</span></div>

      <div class="info-box">
        <h3>🏖️ Welcome to Solid</h3>
        <p>
          This is a <strong>Solid Pod</strong> — a personal data store where you control your own data.
          Resources can be private, shared with specific people, or public.
          ${is401 ? "The Data Browser lets you sign in with your WebID to access protected content." : 'Ask the owner to grant you access.'}
        </p>
      </div>

      <p class="status-code">HTTP ${statusCode} • ${request.url}</p>
    </div>

    <p class="footer">
      Powered by <a href="https://sandy-mount.com">Sandymount</a> •
      <a href="https://solidproject.org">Learn about Solid</a>
    </p>
  </div>
</body>
</html>`;
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
