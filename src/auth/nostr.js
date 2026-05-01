/**
 * Nostr NIP-98 Authentication
 *
 * Implements HTTP authentication using Schnorr signatures as defined in:
 * - NIP-98: https://nips.nostr.com/98
 * - JIP-0001: https://github.com/JavaScriptSolidServer/jips/blob/main/jip-0001.md
 *
 * Authorization header format: "Nostr <base64-encoded-event>"
 *
 * The authenticated identity is returned as a did:nostr URI:
 *   did:nostr:<64-char-hex-pubkey>
 */

import { verifyEvent } from '../nostr/event.js';
import crypto from 'crypto';
import { resolveDidNostrToWebId } from './did-nostr.js';

// NIP-98 event kind (references RFC 7235)
const HTTP_AUTH_KIND = 27235;

// Timestamp tolerance in seconds
const TIMESTAMP_TOLERANCE = 60;

/**
 * Check if request has Nostr authentication
 * Supports both "Nostr <token>" and "Basic <base64(nostr:token)>" formats
 * The Basic format allows git clients to authenticate via NIP-98
 * @param {object} request - Fastify request object
 * @returns {boolean}
 */
export function hasNostrAuth(request) {
  const authHeader = request.headers.authorization;
  if (!authHeader) return false;

  // Direct Nostr header
  if (authHeader.startsWith('Nostr ')) return true;

  // Basic auth with username=nostr (for git clients)
  if (authHeader.startsWith('Basic ')) {
    try {
      const decoded = Buffer.from(authHeader.slice(6), 'base64').toString('utf8');
      return decoded.startsWith('nostr:');
    } catch {
      return false;
    }
  }

  return false;
}

/**
 * Extract token from Nostr authorization header
 * Supports both "Nostr <token>" and "Basic <base64(nostr:token)>" formats
 * @param {string} authHeader - Authorization header value
 * @returns {string|null}
 */
export function extractNostrToken(authHeader) {
  if (!authHeader) return null;

  // Direct Nostr header
  if (authHeader.startsWith('Nostr ')) {
    return authHeader.slice(6).trim();
  }

  // Basic auth with username=nostr, password=token
  if (authHeader.startsWith('Basic ')) {
    try {
      const decoded = Buffer.from(authHeader.slice(6), 'base64').toString('utf8');
      if (decoded.startsWith('nostr:')) {
        return decoded.slice(6); // Remove "nostr:" prefix to get token
      }
    } catch {
      return null;
    }
  }

  return null;
}

// Maximum size for Nostr event (64KB should be plenty for auth events)
const MAX_NOSTR_EVENT_SIZE = 64 * 1024;

/**
 * Decode NIP-98 event from base64 token
 * @param {string} token - Base64 encoded event
 * @returns {object|null} Decoded event or null
 */
function decodeEvent(token) {
  try {
    // Security: limit token size before decoding
    if (token.length > MAX_NOSTR_EVENT_SIZE) {
      return null;
    }
    const decoded = Buffer.from(token, 'base64').toString('utf8');
    // Security: limit decoded size before parsing
    if (decoded.length > MAX_NOSTR_EVENT_SIZE) {
      return null;
    }
    return JSON.parse(decoded);
  } catch {
    return null;
  }
}

/**
 * Get tag value from event
 * @param {object} event - Nostr event
 * @param {string} tagName - Tag name (e.g., 'u', 'method')
 * @returns {string|null} Tag value or null
 */
function getTagValue(event, tagName) {
  if (!event.tags || !Array.isArray(event.tags)) {
    return null;
  }
  const tag = event.tags.find(t => Array.isArray(t) && t[0] === tagName);
  return tag ? tag[1] : null;
}

/**
 * Convert Nostr pubkey to did:nostr URI
 * @param {string} pubkey - 64-char hex public key
 * @returns {string} did:nostr URI
 */
export function pubkeyToDidNostr(pubkey) {
  return `did:nostr:${pubkey.toLowerCase()}`;
}

/**
 * Verify NIP-98 authentication and return agent identity
 * @param {object} request - Fastify request object
 * @returns {Promise<{webId: string|null, error: string|null}>}
 */
export async function verifyNostrAuth(request) {
  const token = extractNostrToken(request.headers.authorization);

  if (!token) {
    return { webId: null, error: 'Missing Nostr token' };
  }

  // Decode the event
  const event = decodeEvent(token);
  if (!event) {
    return { webId: null, error: 'Invalid token format: could not decode base64 JSON' };
  }

  // Validate event kind (must be 27235)
  if (event.kind !== HTTP_AUTH_KIND) {
    return { webId: null, error: `Invalid event kind: expected ${HTTP_AUTH_KIND}, got ${event.kind}` };
  }

  // Validate timestamp (within ±60 seconds)
  const now = Math.floor(Date.now() / 1000);
  const eventTime = event.created_at;
  if (!eventTime || Math.abs(now - eventTime) > TIMESTAMP_TOLERANCE) {
    return { webId: null, error: 'Event timestamp outside acceptable window (±60s)' };
  }

  // Build full URL for validation
  const protocol = request.protocol || 'http';
  const host = request.headers.host || request.hostname;
  const fullUrl = `${protocol}://${host}${request.url}`;

  // Validate URL tag matches request URL
  const eventUrl = getTagValue(event, 'u');
  if (!eventUrl) {
    return { webId: null, error: 'Missing URL tag in event' };
  }

  // Compare URLs (normalize by removing trailing slashes)
  const normalizedEventUrl = eventUrl.replace(/\/$/, '');
  const normalizedRequestUrl = fullUrl.replace(/\/$/, '');
  const normalizedRequestUrlNoQuery = fullUrl.split('?')[0].replace(/\/$/, '');

  // Check for exact match first
  let urlMatches = normalizedEventUrl === normalizedRequestUrl ||
                   normalizedEventUrl === normalizedRequestUrlNoQuery;

  // For git clients: allow prefix matching (event URL is base of request URL)
  // This enables git credential helpers that sign for the repo base URL
  if (!urlMatches && normalizedRequestUrlNoQuery.startsWith(normalizedEventUrl + '/')) {
    urlMatches = true;
  }

  if (!urlMatches) {
    return { webId: null, error: `URL mismatch: event URL "${eventUrl}" does not match request URL "${fullUrl}"` };
  }

  // Validate method tag matches request method
  // For git clients: allow '*' as wildcard method
  // If method tag is missing, infer from HTTP request (lenient mode)
  const eventMethod = getTagValue(event, 'method');
  if (eventMethod && eventMethod !== '*' && eventMethod.toUpperCase() !== request.method.toUpperCase()) {
    return { webId: null, error: `Method mismatch: expected ${request.method}, got ${eventMethod}` };
  }

  // Validate payload hash if present and request has body
  const payloadTag = getTagValue(event, 'payload');
  if (payloadTag && request.body) {
    let bodyString;
    if (typeof request.body === 'string') {
      bodyString = request.body;
    } else if (Buffer.isBuffer(request.body)) {
      bodyString = request.body.toString();
    } else {
      bodyString = JSON.stringify(request.body);
    }

    const expectedHash = crypto.createHash('sha256').update(bodyString).digest('hex');
    if (payloadTag.toLowerCase() !== expectedHash.toLowerCase()) {
      return { webId: null, error: 'Payload hash mismatch' };
    }
  }

  // Validate pubkey exists
  if (!event.pubkey || typeof event.pubkey !== 'string' || event.pubkey.length !== 64) {
    return { webId: null, error: 'Invalid or missing pubkey' };
  }

  // Compute event id if missing (lenient mode for nosdav compatibility)
  if (!event.id) {
    const serialized = JSON.stringify([
      0,
      event.pubkey,
      event.created_at,
      event.kind,
      event.tags,
      event.content
    ]);
    event.id = crypto.createHash('sha256').update(serialized).digest('hex');
  }

  // Verify Schnorr signature
  const isValid = verifyEvent(event);
  if (!isValid) {
    return { webId: null, error: 'Invalid Schnorr signature' };
  }

  // Try to resolve did:nostr to a linked WebID
  // This checks if the pubkey has an alsoKnownAs pointing to a WebID
  // and verifies the WebID links back to did:nostr (bidirectional)
  const resolvedWebId = await resolveDidNostrToWebId(event.pubkey);
  if (resolvedWebId) {
    return { webId: resolvedWebId, error: null };
  }

  // Fall back to did:nostr as the agent identifier
  const didNostr = pubkeyToDidNostr(event.pubkey);

  return { webId: didNostr, error: null };
}

/**
 * Get Nostr pubkey from request if authenticated via NIP-98
 * @param {object} request - Fastify request object
 * @returns {Promise<string|null>} Hex pubkey or null
 */
export async function getNostrPubkey(request) {
  if (!hasNostrAuth(request)) {
    return null;
  }

  const token = extractNostrToken(request.headers.authorization);
  if (!token) {
    return null;
  }

  try {
    const event = decodeEvent(token);
    return event?.pubkey || null;
  } catch {
    return null;
  }
}
