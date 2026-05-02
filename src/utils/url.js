import path from 'path';

// Base directory for storing all pods
// Use a getter function to read env var at runtime (not import time)
// This is necessary because ES modules are loaded before the CLI sets the env var
export function getDataRoot() {
  return process.env.DATA_ROOT || './data';
}

// Legacy export - kept for compatibility, but callers should use getDataRoot()
export let DATA_ROOT = './data';

// Update DATA_ROOT when env var is set (called from storage init)
export function updateDataRoot() {
  DATA_ROOT = getDataRoot();
}

/**
 * Convert URL path to filesystem path
 * @param {string} urlPath - The URL path (e.g., /alice/profile/)
 * @returns {string} - Filesystem path
 * @throws {Error} - If path traversal is detected
 */
export function urlToPath(urlPath) {
  // Normalize: remove leading slash, decode URI
  let normalized = urlPath.startsWith('/') ? urlPath.slice(1) : urlPath;
  normalized = decodeURIComponent(normalized);

  // Security: remove path traversal attempts (multiple passes for ....// bypass)
  let previous;
  do {
    previous = normalized;
    normalized = normalized.replace(/\.\./g, '');
  } while (normalized !== previous);

  // Resolve to absolute path and verify it's within DATA_ROOT
  const dataRoot = path.resolve(getDataRoot());
  const resolved = path.resolve(dataRoot, normalized);

  // Ensure resolved path is within dataRoot (prevent traversal via path.resolve tricks)
  if (!resolved.startsWith(dataRoot + path.sep) && resolved !== dataRoot) {
    throw new Error('Path traversal detected');
  }

  return resolved;
}

/**
 * Convert URL path to filesystem path in subdomain mode
 * In subdomain mode, the pod is determined by the hostname, not the path
 * @param {string} urlPath - The URL path (e.g., /public/file.txt)
 * @param {string} podName - The pod name from subdomain (e.g., "alice")
 * @returns {string} - Filesystem path (e.g., DATA_ROOT/alice/public/file.txt)
 * @throws {Error} - If path traversal is detected
 */
export function urlToPathWithPod(urlPath, podName) {
  // Normalize: remove leading slash, decode URI
  let normalized = urlPath.startsWith('/') ? urlPath.slice(1) : urlPath;
  normalized = decodeURIComponent(normalized);

  // Security: remove path traversal attempts (multiple passes for ....// bypass)
  let previous;
  do {
    previous = normalized;
    normalized = normalized.replace(/\.\./g, '');
  } while (normalized !== previous);

  // Also sanitize podName (multiple passes for ....// bypass)
  let safePodName = podName;
  let previousPod;
  do {
    previousPod = safePodName;
    safePodName = safePodName.replace(/\.\./g, '');
  } while (safePodName !== previousPod);

  // Resolve to absolute path and verify it's within DATA_ROOT
  const dataRoot = path.resolve(getDataRoot());
  const resolved = path.resolve(dataRoot, safePodName, normalized);

  // Ensure resolved path is within dataRoot (prevent traversal via path.resolve tricks)
  if (!resolved.startsWith(dataRoot + path.sep) && resolved !== dataRoot) {
    throw new Error('Path traversal detected');
  }

  return resolved;
}

/**
 * Get the effective path for a request (subdomain-aware)
 * @param {object} request - Fastify request object
 * @returns {string} - Filesystem path
 */
export function getPathFromRequest(request) {
  const urlPath = request.url.split('?')[0];

  // In subdomain mode with a recognized pod subdomain
  if (request.subdomainsEnabled && request.podName) {
    return urlToPathWithPod(urlPath, request.podName);
  }

  // Path-based mode (default)
  return urlToPath(urlPath);
}

/**
 * Get the effective URL path for a request (with pod prefix in subdomain mode)
 * @param {object} request - Fastify request object
 * @returns {string} - URL path with pod prefix if needed
 */
export function getEffectiveUrlPath(request) {
  const urlPath = request.url.split('?')[0];

  // In subdomain mode with a recognized pod subdomain, prepend pod name
  if (request.subdomainsEnabled && request.podName) {
    return '/' + request.podName + urlPath;
  }

  return urlPath;
}

/**
 * Check if URL path represents a container (ends with /)
 * @param {string} urlPath
 * @returns {boolean}
 */
export function isContainer(urlPath) {
  return urlPath.endsWith('/');
}

/**
 * Get the parent container path
 * @param {string} urlPath
 * @returns {string}
 */
export function getParentContainer(urlPath) {
  const parts = urlPath.replace(/\/$/, '').split('/');
  parts.pop();
  return parts.join('/') + '/';
}

/**
 * Get resource name from URL path
 * @param {string} urlPath
 * @returns {string}
 */
export function getResourceName(urlPath) {
  const parts = urlPath.replace(/\/$/, '').split('/');
  return parts[parts.length - 1];
}

/**
 * Extract the hostname-only part of a baseDomain that may include a port.
 * Used for routing comparisons against request.hostname (which never has port).
 *
 * Examples:
 *   'example.com'        → 'example.com'
 *   'example.com:3100'   → 'example.com'
 *   '[::1]:3100'         → '[::1]'
 *
 * @param {string} baseDomain - The configured baseDomain (may include :port)
 * @returns {string}
 */
export function getBaseDomainHost(baseDomain) {
  if (!baseDomain) return baseDomain;

  let value = String(baseDomain).trim();
  if (!value) return value;

  // Accept defensive forms like "https://example.com:3100/".
  if (!value.includes('://')) {
    value = `http://${value}`;
  }

  try {
    const parsed = new URL(value);
    return parsed.hostname;
  } catch {
    // Fallback for malformed values: best-effort host extraction.
    const candidate = value.replace(/^[a-z][a-z0-9+.-]*:\/\//i, '').replace(/\/.*$/, '');

    // Bracketed IPv6
    if (candidate.startsWith('[')) {
      const end = candidate.indexOf(']');
      return end === -1 ? candidate : candidate.slice(0, end + 1);
    }

    const colon = candidate.lastIndexOf(':');
    if (colon === -1) return candidate;
    const maybePort = candidate.slice(colon + 1);
    return /^\d+$/.test(maybePort) ? candidate.slice(0, colon) : candidate;
  }
}


/**
 * Extract pod name from URL path or request
 *
 * Resolves to one of four shapes, by deployment mode:
 *
 * - Subdomain mode with a recognized subdomain → `request.podName` (from hostname).
 * - Subdomain mode with no recognized subdomain → `null` (base-domain access;
 *   callers guard with `if (podName)` and skip pod-scoped side effects).
 * - Single-user, root-pod (`singleUserName` empty or '/') → `'.'` so
 *   `path.join(dataRoot, '.', QUOTA_FILE)` collapses to `<dataRoot>/QUOTA_FILE`.
 * - Single-user, named pod → `singleUserName` (all requests share the one pod,
 *   independent of URL — avoids mistaking a URL segment like `index.html`
 *   for a pod name).
 * - Path-based multi-pod (default, no flags) → first URL segment, or `null`
 *   for requests at `/` that aren't inside any pod.
 *
 * Background: before this function knew about single-user mode, a
 * `PUT /index.html` on a single-user root-pod deployment produced a pod name
 * of `"index.html"`, and the quota sidecar landed at
 * `<dataRoot>/index.html/.quota.json` → `ENOTDIR` (index.html is a file).
 *
 * @param {string|object} pathOrRequest - URL path string or Fastify request object
 * @returns {string|null} - Pod name, `'.'` for root-pod, or `null` when no pod applies
 */
export function getPodName(pathOrRequest) {
  if (typeof pathOrRequest === 'object' && pathOrRequest !== null) {
    // Subdomain mode: hostname drives it. Unrecognized host → no pod.
    if (pathOrRequest.subdomainsEnabled) {
      return pathOrRequest.podName || null;
    }
    // Single-user mode: always the one pod, regardless of URL path.
    if (pathOrRequest.singleUser) {
      const name = pathOrRequest.singleUserName;
      return (!name || name === '/') ? '.' : name;
    }
    // Path-based multi-pod: first URL segment.
    const urlPath = pathOrRequest.url?.split('?')[0] || '';
    return getPodNameFromPath(urlPath);
  }

  // String form: path-based pod extraction.
  return getPodNameFromPath(pathOrRequest);
}

/**
 * Extract pod name from URL path
 * @param {string} urlPath - URL path (e.g., /alice/public/file.txt)
 * @returns {string|null} - Pod name or null
 */
function getPodNameFromPath(urlPath) {
  const parts = urlPath.split('/').filter(Boolean);
  if (parts.length === 0) return null;

  // First segment is the pod name (skip system paths)
  const firstPart = parts[0];
  if (firstPart.startsWith('.')) return null; // .well-known, .acl, etc.

  return firstPart;
}

/**
 * Determine content type from file extension
 * @param {string} filePath
 * @returns {string}
 */
export function getContentType(filePath) {
  const ext = path.extname(filePath).toLowerCase();
  const types = {
    '.jsonld': 'application/ld+json',
    '.json': 'application/json',
    '.html': 'text/html',
    '.txt': 'text/plain',
    '.css': 'text/css',
    '.js': 'application/javascript',
    '.png': 'image/png',
    '.jpg': 'image/jpeg',
    '.jpeg': 'image/jpeg',
    '.gif': 'image/gif',
    '.svg': 'image/svg+xml',
    '.pdf': 'application/pdf',
    '.ttl': 'text/turtle',
    '.n3': 'text/n3',
    '.nt': 'application/n-triples',
    '.rdf': 'application/rdf+xml',
    '.nq': 'application/n-quads',
    '.trig': 'application/trig',
    '.md': 'text/markdown',
    '.m3u': 'audio/mpegurl',
    '.m3u8': 'application/vnd.apple.mpegurl',
    '.pls': 'audio/x-scpls',
    // Solid ACL/meta as extensions (e.g. publicTypeIndex.jsonld.acl)
    '.acl': 'application/ld+json',
    '.meta': 'application/ld+json'
  };

  // Solid convention dotfiles (.acl, .meta) are RDF resources. path.extname
  // returns '' for leading-dot names, so the map lookup above misses them;
  // fall back to a basename check and tag them as JSON-LD — the format JSS
  // writes them in via serializeAcl() / createPodStructure(). Content
  // negotiation then handles Turtle-native clients (umai, Soukai-based apps,
  // older Solid tooling) via handleGet's conneg branch.
  const base = path.basename(filePath);
  if (base === '.acl' || base === '.meta') return 'application/ld+json';

  return types[ext] || 'application/octet-stream';
}

/**
 * Check if content type is RDF
 * @param {string} contentType
 * @returns {boolean}
 */
export function isRdfContentType(contentType) {
  const rdfTypes = [
    'application/ld+json',
    'application/json',
    'text/turtle',
    'text/n3',
    'application/n-triples',
    'application/rdf+xml',
    'application/n-quads',
    'application/trig'
  ];
  return rdfTypes.includes(contentType);
}

// Security: Maximum JSON size for parsing (10MB)
const MAX_JSON_SIZE = 10 * 1024 * 1024;

/**
 * Safely parse JSON with size limit to prevent DoS
 * @param {string} jsonString - The JSON string to parse
 * @param {number} maxSize - Maximum allowed size (default 10MB)
 * @returns {object} - Parsed JSON object
 * @throws {Error} - If JSON is too large or invalid
 */
export function safeJsonParse(jsonString, maxSize = MAX_JSON_SIZE) {
  if (jsonString.length > maxSize) {
    throw new Error(`JSON exceeds maximum size of ${maxSize} bytes`);
  }
  return JSON.parse(jsonString);
}
