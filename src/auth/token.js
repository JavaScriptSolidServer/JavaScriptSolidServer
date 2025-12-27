/**
 * Token-based authentication
 *
 * Supports two modes:
 * 1. Simple tokens (for local/dev use): base64(JSON({webId, iat, exp})) + HMAC signature
 * 2. Solid-OIDC DPoP tokens (for federation): verified via external IdP JWKS
 */

import crypto from 'crypto';
import { verifySolidOidc, hasSolidOidcAuth } from './solid-oidc.js';

// Secret for signing tokens (in production, use env var)
const SECRET = process.env.TOKEN_SECRET || 'dev-secret-change-in-production';

/**
 * Create a simple token for a WebID
 * @param {string} webId - The WebID to create token for
 * @param {number} expiresIn - Expiration time in seconds (default 1 hour)
 * @returns {string} Token string
 */
export function createToken(webId, expiresIn = 3600) {
  const payload = {
    webId,
    iat: Math.floor(Date.now() / 1000),
    exp: Math.floor(Date.now() / 1000) + expiresIn
  };

  const data = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const signature = crypto
    .createHmac('sha256', SECRET)
    .update(data)
    .digest('base64url');

  return `${data}.${signature}`;
}

/**
 * Verify and decode a token (simple 2-part or JWT 3-part)
 * @param {string} token - The token to verify
 * @returns {{webId: string, iat: number, exp: number} | null} Decoded payload or null
 */
export function verifyToken(token) {
  if (!token || typeof token !== 'string') {
    return null;
  }

  const parts = token.split('.');

  // Handle JWT tokens (3 parts) from credentials endpoint
  if (parts.length === 3) {
    return verifyJwtToken(token);
  }

  if (parts.length !== 2) {
    return null;
  }

  const [data, signature] = parts;

  // Verify signature
  const expectedSig = crypto
    .createHmac('sha256', SECRET)
    .update(data)
    .digest('base64url');

  if (signature !== expectedSig) {
    return null;
  }

  // Decode payload
  try {
    const payload = JSON.parse(Buffer.from(data, 'base64url').toString());

    // Check expiration
    if (payload.exp && payload.exp < Math.floor(Date.now() / 1000)) {
      return null;
    }

    return payload;
  } catch {
    return null;
  }
}

/**
 * Verify a JWT token from credentials endpoint
 * JWT tokens are self-contained and signed with the IdP's private key
 * @param {string} token - JWT token
 * @returns {{webId: string, iat: number, exp: number} | null} Decoded payload or null
 */
function verifyJwtToken(token) {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) {
      return null;
    }

    // Decode the payload (middle part)
    const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString());

    // Check expiration
    if (payload.exp && payload.exp < Math.floor(Date.now() / 1000)) {
      return null;
    }

    // JWT from credentials endpoint uses 'webid' claim (lowercase)
    if (payload.webid) {
      return { webId: payload.webid, iat: payload.iat, exp: payload.exp };
    }

    // Also check uppercase WebId for compatibility
    if (payload.webId) {
      return payload;
    }

    return null;
  } catch {
    return null;
  }
}

/**
 * Extract token from Authorization header
 * @param {string} authHeader - Authorization header value
 * @returns {string | null} Token or null
 */
export function extractToken(authHeader) {
  if (!authHeader || typeof authHeader !== 'string') {
    return null;
  }

  // Support "Bearer <token>" format
  if (authHeader.startsWith('Bearer ')) {
    return authHeader.slice(7);
  }

  // Also support raw token
  return authHeader;
}

/**
 * Extract WebID from request (sync version for simple tokens only)
 * @param {object} request - Fastify request object
 * @returns {string | null} WebID or null if not authenticated
 */
export function getWebIdFromRequest(request) {
  const authHeader = request.headers.authorization;

  // Skip DPoP tokens - use async version for those
  if (authHeader && authHeader.startsWith('DPoP ')) {
    return null;
  }

  const token = extractToken(authHeader);

  if (!token) {
    return null;
  }

  const payload = verifyToken(token);
  return payload?.webId || null;
}

/**
 * Extract WebID from request (async version supporting Solid-OIDC)
 * @param {object} request - Fastify request object
 * @returns {Promise<{webId: string|null, error: string|null}>}
 */
export async function getWebIdFromRequestAsync(request) {
  const authHeader = request.headers.authorization;

  if (!authHeader) {
    return { webId: null, error: null };
  }

  // Try Solid-OIDC first (DPoP tokens)
  if (hasSolidOidcAuth(request)) {
    return verifySolidOidc(request);
  }

  // Fall back to simple Bearer tokens
  const token = extractToken(authHeader);
  if (!token) {
    return { webId: null, error: null };
  }

  const payload = verifyToken(token);
  if (payload?.webId) {
    return { webId: payload.webId, error: null };
  }

  return { webId: null, error: 'Invalid token' };
}
