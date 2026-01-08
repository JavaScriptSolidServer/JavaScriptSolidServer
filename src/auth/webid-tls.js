/**
 * WebID-TLS Authentication
 *
 * Authenticates clients via TLS client certificates.
 * The certificate's SubjectAlternativeName (SAN) contains a WebID URI.
 * The server fetches the WebID profile and verifies the certificate's
 * public key matches one published in the profile.
 *
 * References:
 * - https://dvcs.w3.org/hg/WebID/raw-file/tip/spec/tls-respec.html
 * - https://www.w3.org/ns/auth/cert#
 */

import { turtleToJsonLd } from '../rdf/turtle.js';

// cert: ontology namespace
const CERT_NS = 'http://www.w3.org/ns/auth/cert#';

// Cache for verified WebIDs (reduces profile fetches)
const cache = new Map();
const CACHE_TTL = 5 * 60 * 1000; // 5 minutes

/**
 * Fetch with timeout
 */
async function fetchWithTimeout(url, options = {}, timeout = 5000) {
  const controller = new AbortController();
  const id = setTimeout(() => controller.abort(), timeout);
  try {
    const response = await fetch(url, { ...options, signal: controller.signal });
    clearTimeout(id);
    return response;
  } catch (err) {
    clearTimeout(id);
    throw err;
  }
}

/**
 * Extract WebID URI from certificate's SubjectAlternativeName
 * @param {string} subjectaltname - Certificate's SAN field
 * @returns {string|null} WebID URI or null
 */
export function extractWebIdFromSAN(subjectaltname) {
  if (!subjectaltname) return null;

  // SAN format: "URI:https://alice.example/card#me, DNS:example.com"
  const match = subjectaltname.match(/URI:([^,\s]+)/);
  return match ? match[1] : null;
}

/**
 * Parse certificate keys from WebID profile (JSON-LD format)
 * Handles both inline objects and arrays
 * @param {object|Array} jsonLd - Parsed JSON-LD profile
 * @param {string} webId - The WebID to find keys for
 * @returns {Array<{modulus: string, exponent: string}>} Array of keys
 */
function extractCertKeys(jsonLd, webId) {
  const keys = [];

  // Normalize to array
  const nodes = Array.isArray(jsonLd) ? jsonLd : [jsonLd];

  for (const node of nodes) {
    // Check if this node is the WebID subject
    const nodeId = node['@id'];
    if (nodeId && !nodeId.endsWith('#me') && nodeId !== webId) {
      continue;
    }

    // Look for cert:key property (various forms)
    const keyProps = [
      node['cert:key'],
      node[CERT_NS + 'key'],
      node['http://www.w3.org/ns/auth/cert#key']
    ];

    for (const keyProp of keyProps) {
      if (!keyProp) continue;

      const keyValues = Array.isArray(keyProp) ? keyProp : [keyProp];
      for (const keyValue of keyValues) {
        const key = parseKeyObject(keyValue);
        if (key) {
          keys.push(key);
        }
      }
    }
  }

  return keys;
}

/**
 * Parse a single key object from JSON-LD
 * @param {object} keyObj - Key object (may be nested or have @id)
 * @returns {{modulus: string, exponent: string}|null}
 */
function parseKeyObject(keyObj) {
  if (!keyObj || typeof keyObj !== 'object') return null;

  // Extract modulus (various forms)
  let modulus = keyObj['cert:modulus'] ||
                keyObj[CERT_NS + 'modulus'] ||
                keyObj['http://www.w3.org/ns/auth/cert#modulus'];

  // Extract exponent (various forms)
  let exponent = keyObj['cert:exponent'] ||
                 keyObj[CERT_NS + 'exponent'] ||
                 keyObj['http://www.w3.org/ns/auth/cert#exponent'];

  // Handle @value wrapper
  if (modulus && typeof modulus === 'object' && modulus['@value']) {
    modulus = modulus['@value'];
  }
  if (exponent && typeof exponent === 'object' && exponent['@value']) {
    exponent = exponent['@value'];
  }

  // Convert exponent to string if number
  if (typeof exponent === 'number') {
    exponent = exponent.toString();
  }

  if (!modulus || !exponent) return null;

  return {
    modulus: String(modulus).toLowerCase().replace(/[\s:]/g, ''),
    exponent: String(exponent)
  };
}

/**
 * Fetch and parse WebID profile
 * @param {string} webId - WebID URI to fetch
 * @returns {Promise<Array<{modulus: string, exponent: string}>>}
 */
async function fetchProfileKeys(webId) {
  const response = await fetchWithTimeout(webId, {
    headers: {
      'Accept': 'application/ld+json, text/turtle, application/json'
    }
  });

  if (!response.ok) {
    throw new Error(`Failed to fetch WebID profile: ${response.status}`);
  }

  const contentType = response.headers.get('content-type') || '';
  const text = await response.text();

  let jsonLd;

  if (contentType.includes('text/turtle') || contentType.includes('text/n3')) {
    // Parse Turtle to JSON-LD
    jsonLd = await turtleToJsonLd(text, webId);
  } else if (contentType.includes('text/html')) {
    // Try to extract JSON-LD from HTML data island
    const jsonLdMatch = text.match(/<script\s+type=["']application\/ld\+json["']\s*>([\s\S]*?)<\/script>/i);
    if (jsonLdMatch) {
      jsonLd = JSON.parse(jsonLdMatch[1]);
    } else {
      throw new Error('No JSON-LD found in HTML profile');
    }
  } else {
    // Assume JSON-LD
    jsonLd = JSON.parse(text);
  }

  return extractCertKeys(jsonLd, webId);
}

/**
 * Verify certificate against WebID profile
 * @param {object} certificate - Node.js TLS certificate object
 * @param {string} webId - WebID URI
 * @returns {Promise<boolean>} True if certificate matches profile
 */
export async function verifyWebIdTls(certificate, webId) {
  if (!certificate.modulus || !certificate.exponent) {
    throw new Error('Certificate missing modulus or exponent');
  }

  // Normalize certificate values
  const certModulus = certificate.modulus.toLowerCase().replace(/[\s:]/g, '');
  // Certificate exponent is hex, convert to decimal string
  const certExponent = parseInt(certificate.exponent, 16).toString();

  // Check cache
  const cacheKey = `${webId}:${certModulus}`;
  const cached = cache.get(cacheKey);
  if (cached && Date.now() - cached.timestamp < CACHE_TTL) {
    return cached.verified;
  }

  try {
    const profileKeys = await fetchProfileKeys(webId);

    // Check if any key matches
    const verified = profileKeys.some(key =>
      key.modulus === certModulus && key.exponent === certExponent
    );

    cache.set(cacheKey, { verified, timestamp: Date.now() });
    return verified;
  } catch (err) {
    console.error(`WebID-TLS verification error for ${webId}:`, err.message);
    cache.set(cacheKey, { verified: false, timestamp: Date.now() });
    return false;
  }
}

/**
 * WebID-TLS authentication middleware
 * Extracts WebID from client certificate and verifies against profile
 *
 * @param {object} request - Fastify request object
 * @returns {Promise<string|null>} WebID if verified, null otherwise
 */
export async function webIdTlsAuth(request) {
  // Get socket from request
  const socket = request.raw?.socket || request.socket;

  if (!socket?.getPeerCertificate) {
    return null; // Not a TLS connection or no cert support
  }

  const cert = socket.getPeerCertificate();

  // No certificate or empty certificate
  if (!cert || Object.keys(cert).length === 0) {
    return null;
  }

  // Extract WebID from SAN
  const webId = extractWebIdFromSAN(cert.subjectaltname);
  if (!webId) {
    return null; // No WebID in certificate
  }

  // Only accept https:// WebIDs for now
  if (!webId.startsWith('https://')) {
    return null;
  }

  // Verify certificate against profile
  const verified = await verifyWebIdTls(cert, webId);
  return verified ? webId : null;
}

/**
 * Check if request has a client certificate
 * @param {object} request - Fastify request object
 * @returns {boolean}
 */
export function hasClientCertificate(request) {
  const socket = request.raw?.socket || request.socket;
  if (!socket?.getPeerCertificate) return false;

  const cert = socket.getPeerCertificate();
  return cert && Object.keys(cert).length > 0;
}

/**
 * Clear verification cache (for testing)
 */
export function clearCache() {
  cache.clear();
}
