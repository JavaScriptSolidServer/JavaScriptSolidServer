/**
 * LDP (Linked Data Platform) header utilities
 */

const LDP = 'http://www.w3.org/ns/ldp#';

/**
 * Get Link headers for a resource
 * @param {boolean} isContainer
 * @returns {string}
 */
export function getLinkHeader(isContainer) {
  const links = [`<${LDP}Resource>; rel="type"`];

  if (isContainer) {
    links.push(`<${LDP}Container>; rel="type"`);
    links.push(`<${LDP}BasicContainer>; rel="type"`);
  }

  return links.join(', ');
}

/**
 * Get standard LDP response headers
 * @param {object} options
 * @returns {object}
 */
export function getResponseHeaders({ isContainer = false, etag = null, contentType = null }) {
  const headers = {
    'Link': getLinkHeader(isContainer),
    'WAC-Allow': 'user="read write append control", public="read write append"',
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
export function getAllHeaders({ isContainer = false, etag = null, contentType = null, origin = null }) {
  return {
    ...getResponseHeaders({ isContainer, etag, contentType }),
    ...getCorsHeaders(origin)
  };
}
