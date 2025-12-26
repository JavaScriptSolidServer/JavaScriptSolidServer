import path from 'path';

// Base directory for storing all pods
export const DATA_ROOT = process.env.DATA_ROOT || './data';

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

  return path.join(DATA_ROOT, normalized);
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
    '.pdf': 'application/pdf'
  };
  return types[ext] || 'application/octet-stream';
}

/**
 * Check if content type is RDF
 * @param {string} contentType
 * @returns {boolean}
 */
export function isRdfContentType(contentType) {
  return contentType === 'application/ld+json' || contentType === 'application/json';
}
