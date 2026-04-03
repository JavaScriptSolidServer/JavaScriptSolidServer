/**
 * Token-based authentication
 *
 * Supports multiple modes:
 * 1. Simple tokens (for local/dev use): base64(JSON({webId, iat, exp})) + HMAC signature
 * 2. Solid-OIDC DPoP tokens (for federation): verified via external IdP JWKS
 * 3. Nostr NIP-98 tokens: Schnorr signatures, returns did:nostr identity
 */

import crypto from 'crypto';
import { verifySolidOidc, hasSolidOidcAuth } from './solid-oidc.js';
import { verifyNostrAuth, hasNostrAuth } from './nostr.js';
import { webIdTlsAuth, hasClientCertificate } from './webid-tls.js';

// Secret for signing tokens
// SECURITY: In production, TOKEN_SECRET must be set via environment variable
const getSecret = () => {
  if (process.env.TOKEN_SECRET) {
    return process.env.TOKEN_SECRET;
  }

  // In production (NODE_ENV=production), require explicit secret
  if (process.env.NODE_ENV === 'production') {
    console.error('SECURITY ERROR: TOKEN_SECRET environment variable must be set in production');
    console.error('Generate one with: node -e "console.log(require(\'crypto\').randomBytes(32).toString(\'hex\'))"');
    process.exit(1);
  }

  // In development, generate a random secret per process (tokens won't survive restarts)
  const devSecret = crypto.randomBytes(32).toString('hex');
  console.warn('WARNING: No TOKEN_SECRET set. Using random secret (tokens will not survive restarts).');
  console.warn('Set TOKEN_SECRET environment variable for persistent tokens.');
  return devSecret;
};

// Initialize secret once at module load
const SECRET = getSecret();

/**
 * Create a simple token for a WebID
 * @param {string} webId - The WebID to create token for
 * @param {number} [expiresIn] - Expiration time in seconds (default: no expiry)
 * @returns {string} Token string
 */
export function createToken(webId, expiresIn) {
  const payload = {
    webId,
    iat: Math.floor(Date.now() / 1000),
  };
  if (expiresIn) {
    payload.exp = Math.floor(Date.now() / 1000) + expiresIn;
  }

  const data = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const signature = crypto
    .createHmac('sha256', SECRET)
    .update(data)
    .digest('base64url');

  return `${data}.${signature}`;
}

/**
 * Verify and decode a simple token (2-part HMAC-signed)
 *
 * SECURITY: Only accepts 2-part simple tokens signed with HMAC.
 * JWT tokens (3-part) require async verification via verifyTokenAsync().
 *
 * @param {string} token - The token to verify
 * @returns {{webId: string, iat: number, exp: number} | null} Decoded payload or null
 */
export function verifyToken(token) {
  if (!token || typeof token !== 'string') {
    return null;
  }

  const parts = token.split('.');

  // JWT tokens (3 parts) require async verification - reject in sync function
  if (parts.length === 3) {
    return null;
  }

  if (parts.length !== 2) {
    return null;
  }

  const [data, signature] = parts;

  // Verify HMAC signature
  const expectedSig = crypto
    .createHmac('sha256', SECRET)
    .update(data)
    .digest('base64url');

  // Constant-time comparison to prevent timing attacks
  try {
    if (!crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(expectedSig))) {
      return null;
    }
  } catch {
    // If lengths don't match, timingSafeEqual throws
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
 * Verify a JWT token from the credentials endpoint
 * Properly verifies signature against IdP's JWKS
 *
 * @param {string} token - JWT token
 * @returns {Promise<{webId: string, iat: number, exp: number} | null>}
 */
async function verifyJwtFromIdp(token) {
  try {
    // Dynamically import to avoid circular dependencies
    const { getPublicJwks } = await import('../idp/keys.js');
    const jose = await import('jose');

    const jwks = await getPublicJwks();
    if (!jwks || !jwks.keys || jwks.keys.length === 0) {
      return null;
    }

    // Create JWKS for verification
    const keySet = jose.createLocalJWKSet(jwks);

    // Verify the token
    const { payload } = await jose.jwtVerify(token, keySet, {
      // Allow some clock skew
      clockTolerance: 60,
    });

    // Extract webid claim
    const webId = payload.webid || payload.webId || payload.sub;
    if (!webId) {
      return null;
    }

    return {
      webId,
      iat: payload.iat,
      exp: payload.exp
    };
  } catch (err) {
    // Verification failed - invalid signature, expired, etc.
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

  // Skip Nostr tokens - use async version for those
  if (authHeader && authHeader.startsWith('Nostr ')) {
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

  // Try Authorization header methods first
  if (authHeader) {
    // Try Solid-OIDC first (DPoP tokens)
    if (hasSolidOidcAuth(request)) {
      return verifySolidOidc(request);
    }

    // Try Nostr NIP-98 (Schnorr signatures)
    if (hasNostrAuth(request)) {
      return verifyNostrAuth(request);
    }

    // Fall back to Bearer tokens
    const token = extractToken(authHeader);
    if (token) {
      // Try simple 2-part token first
      const payload = verifyToken(token);
      if (payload?.webId) {
        return { webId: payload.webId, error: null };
      }

      // If 3-part JWT, verify against IdP's JWKS
      const parts = token.split('.');
      if (parts.length === 3) {
        const jwtPayload = await verifyJwtFromIdp(token);
        if (jwtPayload?.webId) {
          return { webId: jwtPayload.webId, error: null };
        }
        return { webId: null, error: 'Invalid or unverifiable JWT token' };
      }

      return { webId: null, error: 'Invalid token' };
    }
  }

  // Try WebID-TLS (client certificate authentication)
  // This works even without Authorization header
  if (hasClientCertificate(request)) {
    try {
      const webId = await webIdTlsAuth(request);
      if (webId) {
        return { webId, error: null };
      }
      // Certificate present but verification failed
      return { webId: null, error: 'WebID-TLS certificate verification failed' };
    } catch (err) {
      return { webId: null, error: `WebID-TLS error: ${err.message}` };
    }
  }

  return { webId: null, error: null };
}
