/**
 * Programmatic credentials endpoint for CTH compatibility
 * Allows obtaining tokens via email/password without browser interaction
 */

import * as jose from 'jose';
import crypto from 'crypto';
import { authenticate } from './accounts.js';
import { getJwks } from './keys.js';

/**
 * Handle POST /idp/credentials
 * Accepts email/password (or username/password) and returns access token
 *
 * Request body (JSON or form):
 * - email or username: User email address
 * - password: User password
 *
 * Optional headers:
 * - DPoP: DPoP proof JWT (for DPoP-bound tokens)
 *
 * Response:
 * - access_token: JWT access token with webid claim
 * - token_type: 'DPoP' or 'Bearer'
 * - expires_in: Token lifetime in seconds
 * - webid: User's WebID
 */
export async function handleCredentials(request, reply, issuer) {
  // Parse body (JSON or form-encoded)
  let email, password;

  const contentType = request.headers['content-type'] || '';
  let body = request.body;

  // Convert buffer to string if needed
  if (Buffer.isBuffer(body)) {
    body = body.toString('utf-8');
  }

  if (contentType.includes('application/json')) {
    // JSON - Fastify parses this automatically
    if (typeof body === 'string') {
      try {
        body = JSON.parse(body);
      } catch {
        // Not valid JSON
      }
    }
    email = body?.email || body?.username;
    password = body?.password;
  } else if (contentType.includes('application/x-www-form-urlencoded')) {
    // Parse form-encoded body
    if (typeof body === 'string') {
      const params = new URLSearchParams(body);
      email = params.get('email') || params.get('username');
      password = params.get('password');
    } else if (typeof body === 'object') {
      email = body?.email || body?.username;
      password = body?.password;
    }
  } else {
    // Try to parse as object
    if (typeof body === 'object') {
      email = body?.email || body?.username;
      password = body?.password;
    }
  }

  // Validate input
  if (!email || !password) {
    return reply.code(400).send({
      error: 'invalid_request',
      error_description: 'Username/email and password are required',
    });
  }

  // Authenticate
  const account = await authenticate(email, password);

  if (!account) {
    return reply.code(401).send({
      error: 'invalid_grant',
      error_description: 'Invalid email or password',
    });
  }

  // Check for DPoP header
  const dpopHeader = request.headers['dpop'];
  let dpopJkt = null;

  if (dpopHeader) {
    try {
      // Validate DPoP proof and extract thumbprint
      const credUrl = `${issuer.replace(/\/$/, '')}/idp/credentials`;
      dpopJkt = await validateDpopProof(dpopHeader, 'POST', credUrl);
    } catch (err) {
      return reply.code(400).send({
        error: 'invalid_dpop_proof',
        error_description: err.message,
      });
    }
  }

  const expiresIn = 3600; // 1 hour

  // Always generate a proper JWT - CTH requires JWT format
  const jwks = await getJwks();
  const signingKey = jwks.keys[0];
  const signingAlg = signingKey.alg || 'ES256'; // Use key's algorithm
  const privateKey = await jose.importJWK(signingKey, signingAlg);

  const now = Math.floor(Date.now() / 1000);
  const tokenPayload = {
    iss: issuer,
    sub: account.id,
    aud: 'solid', // Solid-OIDC requires this audience
    webid: account.webId,
    iat: now,
    exp: now + expiresIn,
    jti: crypto.randomUUID(),
    client_id: 'credentials_client',
    scope: 'openid webid',
  };

  // Add DPoP binding confirmation if DPoP proof was provided
  let tokenType;
  if (dpopJkt) {
    tokenPayload.cnf = { jkt: dpopJkt };
    tokenType = 'DPoP';
  } else {
    tokenType = 'Bearer';
  }

  const accessToken = await new jose.SignJWT(tokenPayload)
    .setProtectedHeader({ alg: signingAlg, kid: signingKey.kid })
    .sign(privateKey);

  // Response
  const response = {
    access_token: accessToken,
    token_type: tokenType,
    expires_in: expiresIn,
    webid: account.webId,
    id: account.id,
  };

  reply.header('Cache-Control', 'no-store');
  reply.header('Pragma', 'no-cache');

  return response;
}

/**
 * Validate a DPoP proof and return the JWK thumbprint
 * @param {string} proof - The DPoP proof JWT
 * @param {string} method - HTTP method
 * @param {string} url - Request URL
 * @returns {Promise<string>} - JWK thumbprint
 */
async function validateDpopProof(proof, method, url) {
  // Decode the proof header to get the public key
  const protectedHeader = jose.decodeProtectedHeader(proof);

  // DPoP proofs must have a JWK in the header
  if (!protectedHeader.jwk) {
    throw new Error('DPoP proof must contain jwk in header');
  }

  // Verify the proof signature
  const publicKey = await jose.importJWK(protectedHeader.jwk, protectedHeader.alg);

  let payload;
  try {
    const result = await jose.jwtVerify(proof, publicKey, {
      typ: 'dpop+jwt',
      maxTokenAge: '60s',
    });
    payload = result.payload;
  } catch (err) {
    throw new Error(`DPoP proof verification failed: ${err.message}`);
  }

  // Verify htm (HTTP method)
  if (payload.htm !== method) {
    throw new Error(`DPoP htm mismatch: expected ${method}, got ${payload.htm}`);
  }

  // Verify htu (HTTP URL) - compare without query string
  const proofUrl = new URL(payload.htu);
  const requestUrl = new URL(url);
  if (proofUrl.origin + proofUrl.pathname !== requestUrl.origin + requestUrl.pathname) {
    throw new Error('DPoP htu mismatch');
  }

  // Calculate JWK thumbprint
  const thumbprint = await jose.calculateJwkThumbprint(protectedHeader.jwk, 'sha256');

  return thumbprint;
}

/**
 * Handle GET /idp/credentials
 * Returns info about the credentials endpoint
 */
export function handleCredentialsInfo(request, reply, issuer) {
  return {
    endpoint: `${issuer}/idp/credentials`,
    method: 'POST',
    description: 'Obtain access tokens using email/username and password',
    content_types: ['application/json', 'application/x-www-form-urlencoded'],
    parameters: {
      email: 'User email address (or use "username")',
      username: 'Alias for email (for CTH compatibility)',
      password: 'User password',
    },
    optional_headers: {
      DPoP: 'DPoP proof JWT for DPoP-bound tokens',
    },
    response: {
      access_token: 'JWT access token with webid claim',
      token_type: 'DPoP or Bearer',
      expires_in: 'Token lifetime in seconds',
      webid: 'User WebID',
    },
  };
}
