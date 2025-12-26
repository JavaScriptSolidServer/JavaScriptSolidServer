/**
 * LDP (Linked Data Platform) header utilities
 */

const LDP = 'http://www.w3.org/ns/ldp#';

/**
 * Get Link headers for a resource
 * @param {boolean} isContainer
 * @param {string} aclUrl - URL to the ACL resource
 * @returns {string}
 */
export function getLinkHeader(isContainer, aclUrl = null) {
  const links = [`<${LDP}Resource>; rel="type"`];

  if (isContainer) {
    links.push(`<${LDP}Container>; rel="type"`);
    links.push(`<${LDP}BasicContainer>; rel="type"`);
  }

  // Add acl link for auxiliary resource discovery
  if (aclUrl) {
    links.push(`<${aclUrl}>; rel="acl"`);
  }

  return links.join(', ');
}

/**
 * Get the ACL URL for a resource
 * @param {string} resourceUrl - Full URL of the resource
 * @param {boolean} isContainer - Whether the resource is a container
 * @returns {string} ACL URL
 */
export function getAclUrl(resourceUrl, isContainer) {
  if (isContainer) {
    // Container ACL: /path/.acl
    const base = resourceUrl.endsWith('/') ? resourceUrl : resourceUrl + '/';
    return base + '.acl';
  }
  // Resource ACL: /path/file.acl
  return resourceUrl + '.acl';
}

/**
 * Get standard LDP response headers
 * @param {object} options
 * @returns {object}
 */
export function getResponseHeaders({ isContainer = false, etag = null, contentType = null, resourceUrl = null, wacAllow = null }) {
  // Calculate ACL URL if resource URL provided
  const aclUrl = resourceUrl ? getAclUrl(resourceUrl, isContainer) : null;

  const headers = {
    'Link': getLinkHeader(isContainer, aclUrl),
    'WAC-Allow': wacAllow || 'user="read write append control", public="read write append"',
    'Accept-Patch': 'application/sparql-update',
    'Allow': 'GET, HEAD, PUT, DELETE, OPTIONS' + (isContainer ? ', POST' : ''),
    'Vary': 'Accept, Authorization, Origin'
  };

  if (isContainer) {
    headers['Accept-Post'] = '*/*';
  }

  if (etag) {
    headers['ETag'] = etag;
  }

  if (contentType) {
    headers['Content-Type'] = contentType;
  }

  return headers;
}

/**
 * Get CORS headers
 * @param {string} origin
 * @returns {object}
 */
export function getCorsHeaders(origin) {
  return {
    'Access-Control-Allow-Origin': origin || '*',
    'Access-Control-Allow-Methods': 'GET, HEAD, POST, PUT, DELETE, PATCH, OPTIONS',
    'Access-Control-Allow-Headers': 'Accept, Authorization, Content-Type, If-Match, If-None-Match, Link, Slug, Origin',
    'Access-Control-Expose-Headers': 'Accept-Patch, Accept-Post, Allow, Content-Type, ETag, Link, Location, WAC-Allow',
    'Access-Control-Allow-Credentials': 'true',
    'Access-Control-Max-Age': '86400'
  };
}

/**
 * Get all headers combined
 * @param {object} options
 * @returns {object}
 */
export function getAllHeaders({ isContainer = false, etag = null, contentType = null, origin = null, resourceUrl = null, wacAllow = null }) {
  return {
    ...getResponseHeaders({ isContainer, etag, contentType, resourceUrl, wacAllow }),
    ...getCorsHeaders(origin)
  };
}
