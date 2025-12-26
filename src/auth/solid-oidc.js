/**
 * Solid-OIDC Resource Server
 * Verifies DPoP-bound access tokens from external Identity Providers
 *
 * Flow:
 * 1. User authenticates at external IdP (e.g., solidcommunity.net)
 * 2. User gets DPoP-bound access token
 * 3. User sends request with Authorization: DPoP <token> and DPoP: <proof>
 * 4. We verify the token and DPoP proof
 * 5. Extract WebID from token
 */

import * as jose from 'jose';

// Cache for OIDC configurations and JWKS
const oidcConfigCache = new Map();
const jwksCache = new Map();

// Cache TTL (15 minutes)
const CACHE_TTL = 15 * 60 * 1000;

// DPoP proof max age (5 minutes)
const DPOP_MAX_AGE = 5 * 60;

/**
 * Verify a Solid-OIDC request and extract WebID
 * @param {object} request - Fastify request object
 * @returns {Promise<{webId: string|null, error: string|null}>}
 */
export async function verifySolidOidc(request) {
  const authHeader = request.headers.authorization;
  const dpopHeader = request.headers.dpop;

  // Check for DPoP authorization scheme
  if (!authHeader || !authHeader.startsWith('DPoP ')) {
    return { webId: null, error: null }; // Not a Solid-OIDC request
  }

  if (!dpopHeader) {
    return { webId: null, error: 'Missing DPoP proof header' };
  }

  const accessToken = authHeader.slice(5); // Remove 'DPoP ' prefix

  try {
    // Step 1: Decode access token (without verification) to get issuer
    const tokenPayload = jose.decodeJwt(accessToken);
    const issuer = tokenPayload.iss;

    if (!issuer) {
      return { webId: null, error: 'Access token missing issuer' };
    }

    // Step 2: Verify DPoP proof
    const dpopResult = await verifyDpopProof(dpopHeader, request, accessToken);
    if (dpopResult.error) {
      return { webId: null, error: dpopResult.error };
    }

    // Step 3: Fetch JWKS and verify access token
    const jwks = await getJwks(issuer);
    const { payload } = await jose.jwtVerify(accessToken, jwks, {
      issuer,
      clockTolerance: 30 // 30 seconds clock skew tolerance
    });

    // Step 4: Verify DPoP binding (cnf.jkt must match DPoP key thumbprint)
    if (payload.cnf?.jkt) {
      if (payload.cnf.jkt !== dpopResult.thumbprint) {
        return { webId: null, error: 'DPoP key does not match token binding' };
      }
    }

    // Step 5: Extract WebID
    const webId = payload.webid || payload.sub;
    if (!webId) {
      return { webId: null, error: 'Token missing WebID claim' };
    }

    // Validate WebID is a valid URL
    try {
      new URL(webId);
    } catch {
      return { webId: null, error: 'Invalid WebID URL' };
    }

    return { webId, error: null };

  } catch (err) {
    // Handle specific JWT errors
    if (err.code === 'ERR_JWT_EXPIRED') {
      return { webId: null, error: 'Access token expired' };
    }
    if (err.code === 'ERR_JWS_SIGNATURE_VERIFICATION_FAILED') {
      return { webId: null, error: 'Invalid token signature' };
    }
    if (err.code === 'ERR_JWKS_NO_MATCHING_KEY') {
      return { webId: null, error: 'No matching key found in JWKS' };
    }

    console.error('Solid-OIDC verification error:', err.message);
    return { webId: null, error: 'Token verification failed' };
  }
}

/**
 * Verify DPoP proof JWT
 * @param {string} dpopProof - The DPoP proof JWT
 * @param {object} request - Fastify request
 * @param {string} accessToken - The access token (for ath claim verification)
 * @returns {Promise<{thumbprint: string|null, error: string|null}>}
 */
async function verifyDpopProof(dpopProof, request, accessToken) {
  try {
    // Decode header to get the public key
    const protectedHeader = jose.decodeProtectedHeader(dpopProof);

    if (protectedHeader.typ !== 'dpop+jwt') {
      return { thumbprint: null, error: 'Invalid DPoP proof type' };
    }

    if (!protectedHeader.jwk) {
      return { thumbprint: null, error: 'DPoP proof missing jwk header' };
    }

    // Import the public key from the JWK in the header
    const publicKey = await jose.importJWK(protectedHeader.jwk, protectedHeader.alg);

    // Verify the DPoP proof signature
    const { payload } = await jose.jwtVerify(dpopProof, publicKey, {
      clockTolerance: 30
    });

    // Verify required claims
    // htm: HTTP method
    const expectedMethod = request.method.toUpperCase();
    if (payload.htm !== expectedMethod) {
      return { thumbprint: null, error: `DPoP htm mismatch: expected ${expectedMethod}` };
    }

    // htu: HTTP URI (without query string and fragment)
    const requestUrl = `${request.protocol}://${request.hostname}${request.url.split('?')[0]}`;
    // Normalize both URLs for comparison
    const payloadHtu = payload.htu?.replace(/\/$/, '');
    const expectedHtu = requestUrl.replace(/\/$/, '');

    if (payloadHtu !== expectedHtu) {
      // Also try without port for localhost
      const altHtu = requestUrl.replace(/:(\d+)/, '').replace(/\/$/, '');
      if (payloadHtu !== altHtu) {
        return { thumbprint: null, error: `DPoP htu mismatch: expected ${expectedHtu}` };
      }
    }

    // iat: Issued at (must be recent)
    const now = Math.floor(Date.now() / 1000);
    if (!payload.iat || Math.abs(now - payload.iat) > DPOP_MAX_AGE) {
      return { thumbprint: null, error: 'DPoP proof expired or invalid iat' };
    }

    // jti: Unique identifier (we should track these to prevent replay, but skip for now)
    if (!payload.jti) {
      return { thumbprint: null, error: 'DPoP proof missing jti' };
    }

    // ath: Access token hash (optional but recommended)
    if (payload.ath) {
      const expectedAth = await calculateAth(accessToken);
      if (payload.ath !== expectedAth) {
        return { thumbprint: null, error: 'DPoP ath mismatch' };
      }
    }

    // Calculate JWK thumbprint for binding verification
    const thumbprint = await jose.calculateJwkThumbprint(protectedHeader.jwk, 'sha256');

    return { thumbprint, error: null };

  } catch (err) {
    console.error('DPoP verification error:', err.message);
    return { thumbprint: null, error: 'Invalid DPoP proof' };
  }
}

/**
 * Calculate access token hash (ath) for DPoP binding
 */
async function calculateAth(accessToken) {
  const encoder = new TextEncoder();
  const data = encoder.encode(accessToken);
  const hash = await crypto.subtle.digest('SHA-256', data);
  return jose.base64url.encode(new Uint8Array(hash));
}

/**
 * Fetch and cache OIDC configuration
 */
async function getOidcConfig(issuer) {
  const cached = oidcConfigCache.get(issuer);
  if (cached && Date.now() - cached.timestamp < CACHE_TTL) {
    return cached.config;
  }

  const configUrl = `${issuer.replace(/\/$/, '')}/.well-known/openid-configuration`;

  try {
    const response = await fetch(configUrl);
    if (!response.ok) {
      throw new Error(`Failed to fetch OIDC config: ${response.status}`);
    }

    const config = await response.json();
    oidcConfigCache.set(issuer, { config, timestamp: Date.now() });
    return config;

  } catch (err) {
    console.error(`Failed to fetch OIDC config from ${issuer}:`, err.message);
    throw err;
  }
}

/**
 * Get JWKS for an issuer (with caching)
 */
async function getJwks(issuer) {
  const cached = jwksCache.get(issuer);
  if (cached && Date.now() - cached.timestamp < CACHE_TTL) {
    return cached.jwks;
  }

  // Get OIDC config to find JWKS URI
  const config = await getOidcConfig(issuer);
  const jwksUri = config.jwks_uri;

  if (!jwksUri) {
    throw new Error('OIDC config missing jwks_uri');
  }

  // Create a remote JWKS set
  const jwks = jose.createRemoteJWKSet(new URL(jwksUri));

  jwksCache.set(issuer, { jwks, timestamp: Date.now() });
  return jwks;
}

/**
 * Clear caches (useful for testing)
 */
export function clearCaches() {
  oidcConfigCache.clear();
  jwksCache.clear();
}

/**
 * Check if request has Solid-OIDC authorization
 */
export function hasSolidOidcAuth(request) {
  const authHeader = request.headers.authorization;
  return authHeader && authHeader.startsWith('DPoP ');
}
