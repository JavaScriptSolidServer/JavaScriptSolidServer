/**
 * Content Negotiation for RDF Resources
 *
 * Handles Accept header parsing and format selection.
 * OFF by default - this is a JSON-LD native implementation.
 * Enable with { conneg: true } in server options.
 */

import { turtleToJsonLd, jsonLdToTurtle } from './turtle.js';
import { safeJsonParse } from '../utils/url.js';

// RDF content types we support
export const RDF_TYPES = {
  JSON_LD: 'application/ld+json',
  TURTLE: 'text/turtle',
  N3: 'text/n3',
  NTRIPLES: 'application/n-triples',
  RDF_XML: 'application/rdf+xml'  // Not supported, but recognized
};

// Content types we can serve (when conneg enabled)
const SUPPORTED_OUTPUT = [RDF_TYPES.JSON_LD, RDF_TYPES.TURTLE];

// Content types we can accept for input (when conneg enabled)
const SUPPORTED_INPUT = [RDF_TYPES.JSON_LD, RDF_TYPES.TURTLE, RDF_TYPES.N3];

/**
 * Parse Accept header and select best content type
 * @param {string} acceptHeader - Accept header value
 * @param {boolean} connegEnabled - Whether content negotiation is enabled
 * @returns {string} Selected content type
 */
export function selectContentType(acceptHeader, connegEnabled = false) {
  // If conneg disabled, always return JSON-LD
  if (!connegEnabled) {
    return RDF_TYPES.JSON_LD;
  }

  if (!acceptHeader) {
    return RDF_TYPES.JSON_LD;
  }

  // Parse Accept header
  const accepts = parseAcceptHeader(acceptHeader);

  // Find best match
  for (const { type } of accepts) {
    if (type === '*/*' || type === 'application/*') {
      return RDF_TYPES.JSON_LD;
    }
    if (SUPPORTED_OUTPUT.includes(type)) {
      return type;
    }
    // Handle text/* preference
    if (type === 'text/*') {
      return RDF_TYPES.TURTLE;
    }
  }

  // Default to JSON-LD
  return RDF_TYPES.JSON_LD;
}

/**
 * Parse Accept header into sorted list
 */
function parseAcceptHeader(header) {
  const types = header.split(',').map(part => {
    const [type, ...params] = part.trim().split(';');
    let q = 1;

    for (const param of params) {
      const [key, value] = param.trim().split('=');
      if (key === 'q') {
        q = parseFloat(value) || 0;
      }
    }

    return { type: type.trim().toLowerCase(), q };
  });

  // Sort by q value descending
  return types.sort((a, b) => b.q - a.q);
}

/**
 * Check if content type is RDF
 */
export function isRdfType(contentType) {
  if (!contentType) return false;
  const type = contentType.split(';')[0].trim().toLowerCase();
  return Object.values(RDF_TYPES).includes(type) ||
         type === 'application/json'; // Treat as JSON-LD
}

/**
 * Check if we can accept this input type for RDF resources
 * Non-RDF content types are always accepted (passthrough)
 */
export function canAcceptInput(contentType, connegEnabled = false) {
  if (!contentType) return true; // No content type = accept

  const type = contentType.split(';')[0].trim().toLowerCase();

  // Always accept JSON-LD and JSON
  if (type === RDF_TYPES.JSON_LD || type === 'application/json') {
    return true;
  }

  // Check if it's an RDF type we need to handle
  const isRdf = Object.values(RDF_TYPES).includes(type);

  // Non-RDF types are accepted as-is (passthrough)
  if (!isRdf) {
    return true;
  }

  // RDF types other than JSON-LD only if conneg enabled
  if (connegEnabled) {
    return SUPPORTED_INPUT.includes(type);
  }

  // RDF type but conneg disabled - reject (should use JSON-LD)
  return false;
}

/**
 * Convert content to JSON-LD (internal storage format)
 * @param {Buffer|string} content - Input content
 * @param {string} contentType - Content-Type header
 * @param {string} baseUri - Base URI
 * @param {boolean} connegEnabled - Whether conneg is enabled
 * @returns {Promise<object>} JSON-LD document
 */
export async function toJsonLd(content, contentType, baseUri, connegEnabled = false) {
  const type = (contentType || '').split(';')[0].trim().toLowerCase();
  const text = Buffer.isBuffer(content) ? content.toString() : content;

  // JSON-LD or JSON
  if (type === RDF_TYPES.JSON_LD || type === 'application/json' || !type) {
    return safeJsonParse(text);
  }

  // Turtle/N3 - only if conneg enabled
  if (connegEnabled && (type === RDF_TYPES.TURTLE || type === RDF_TYPES.N3)) {
    return turtleToJsonLd(text, baseUri);
  }

  throw new Error(`Unsupported content type: ${type}`);
}

/**
 * Convert JSON-LD to requested format
 * @param {object} jsonLd - JSON-LD document
 * @param {string} targetType - Target content type
 * @param {string} baseUri - Base URI
 * @param {boolean} connegEnabled - Whether conneg is enabled
 * @returns {Promise<{content: string, contentType: string}>}
 */
export async function fromJsonLd(jsonLd, targetType, baseUri, connegEnabled = false) {
  // If conneg disabled, always output JSON-LD
  if (!connegEnabled) {
    return {
      content: JSON.stringify(jsonLd, null, 2),
      contentType: RDF_TYPES.JSON_LD
    };
  }

  // JSON-LD
  if (targetType === RDF_TYPES.JSON_LD || !targetType) {
    return {
      content: JSON.stringify(jsonLd, null, 2),
      contentType: RDF_TYPES.JSON_LD
    };
  }

  // Turtle
  if (targetType === RDF_TYPES.TURTLE) {
    const turtle = await jsonLdToTurtle(jsonLd, baseUri);
    return { content: turtle, contentType: RDF_TYPES.TURTLE };
  }

  // Fallback to JSON-LD
  return {
    content: JSON.stringify(jsonLd, null, 2),
    contentType: RDF_TYPES.JSON_LD
  };
}

/**
 * Get Vary header value for content negotiation
 * Include Accept when conneg or mashlib is enabled (response varies by Accept header)
 */
export function getVaryHeader(connegEnabled, mashlibEnabled = false) {
  return (connegEnabled || mashlibEnabled) ? 'Accept, Origin' : 'Origin';
}

/**
 * Get Accept-* headers for responses
 */
export function getAcceptHeaders(connegEnabled, isContainer = false) {
  const headers = {};

  if (isContainer) {
    headers['Accept-Post'] = connegEnabled
      ? `${RDF_TYPES.JSON_LD}, ${RDF_TYPES.TURTLE}, */*`
      : `${RDF_TYPES.JSON_LD}, */*`;
  }

  headers['Accept-Put'] = connegEnabled
    ? `${RDF_TYPES.JSON_LD}, ${RDF_TYPES.TURTLE}, */*`
    : `${RDF_TYPES.JSON_LD}, */*`;

  headers['Accept-Patch'] = 'text/n3, application/sparql-update';

  return headers;
}
