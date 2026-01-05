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
 * Extract pod name from URL path or request
 * @param {string|object} pathOrRequest - URL path string or Fastify request object
 * @returns {string|null} - Pod name or null if not found
 */
export function getPodName(pathOrRequest) {
  // If it's a request object
  if (typeof pathOrRequest === 'object') {
    // Subdomain mode: pod name from hostname
    if (pathOrRequest.subdomainsEnabled && pathOrRequest.podName) {
      return pathOrRequest.podName;
    }
    // Path mode: extract from URL
    const urlPath = pathOrRequest.url?.split('?')[0] || '';
    return getPodNameFromPath(urlPath);
  }

  // If it's a string path
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
    '.trig': 'application/trig'
  };
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
