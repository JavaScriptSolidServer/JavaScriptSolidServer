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
 */
export function urlToPath(urlPath) {
  // Normalize: remove leading slash, decode URI
  let normalized = urlPath.startsWith('/') ? urlPath.slice(1) : urlPath;
  normalized = decodeURIComponent(normalized);

  // Security: prevent path traversal
  normalized = normalized.replace(/\.\./g, '');

  return path.join(getDataRoot(), normalized);
}

/**
 * Convert URL path to filesystem path in subdomain mode
 * In subdomain mode, the pod is determined by the hostname, not the path
 * @param {string} urlPath - The URL path (e.g., /public/file.txt)
 * @param {string} podName - The pod name from subdomain (e.g., "alice")
 * @returns {string} - Filesystem path (e.g., DATA_ROOT/alice/public/file.txt)
 */
export function urlToPathWithPod(urlPath, podName) {
  // Normalize: remove leading slash, decode URI
  let normalized = urlPath.startsWith('/') ? urlPath.slice(1) : urlPath;
  normalized = decodeURIComponent(normalized);

  // Security: prevent path traversal
  normalized = normalized.replace(/\.\./g, '');

  // Prepend pod name to path
  return path.join(getDataRoot(), podName, normalized);
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
