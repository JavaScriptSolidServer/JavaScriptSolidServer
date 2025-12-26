/**
 * Simple token-based authentication
 *
 * For now, we use a simple JWT-like approach:
 * - Token format: base64(JSON({webId, iat, exp}))
 * - In production, this would be replaced with proper Solid-OIDC DPoP tokens
 */

import crypto from 'crypto';

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
 * Verify and decode a token
 * @param {string} token - The token to verify
 * @returns {{webId: string, iat: number, exp: number} | null} Decoded payload or null
 */
export function verifyToken(token) {
  if (!token || typeof token !== 'string') {
    return null;
  }

  const parts = token.split('.');
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
 * Extract WebID from request
 * @param {object} request - Fastify request object
 * @returns {string | null} WebID or null if not authenticated
 */
export function getWebIdFromRequest(request) {
  const authHeader = request.headers.authorization;
  const token = extractToken(authHeader);

  if (!token) {
    return null;
  }

  const payload = verifyToken(token);
  return payload?.webId || null;
}
