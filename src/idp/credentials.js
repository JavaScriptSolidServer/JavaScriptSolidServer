/**
 * Programmatic credentials endpoint for CTH compatibility
 * Allows obtaining tokens via email/password without browser interaction
 */

import * as jose from 'jose';
import crypto from 'crypto';
import fs from 'fs-extra';
import path from 'path';
import { authenticate, findByWebId, updatePassword, verifyPassword, deleteAccount } from './accounts.js';
import { getJwks } from './keys.js';
import { getWebIdFromRequestAsync } from '../auth/token.js';

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
 * Handle PUT /idp/credentials
 * Authenticated owner rotates their own password.
 *
 * Auth: caller must be authenticated (Bearer/DPoP/Nostr-NIP-98).
 * Body (JSON): { currentPassword, newPassword }
 *
 * Responses:
 *   200 { ok: true, webid, passwordChangedAt }
 *   400 missing fields
 *   401 unauthenticated, or currentPassword wrong
 *   403 caller's WebID does not match any account
 */
export async function handleChangePassword(request, reply) {
  // 1. Authenticate caller
  const { webId, error: authError } = await getWebIdFromRequestAsync(request);
  if (!webId) {
    return reply.code(401).send({
      error: 'invalid_token',
      error_description: authError || 'Authentication required',
    });
  }

  // 2. Parse body
  let body = request.body;
  if (Buffer.isBuffer(body)) body = body.toString('utf-8');
  if (typeof body === 'string') {
    try { body = JSON.parse(body); } catch { body = {}; }
  }
  const currentPassword = body?.currentPassword;
  const newPassword = body?.newPassword;

  if (typeof currentPassword !== 'string' || typeof newPassword !== 'string'
      || !currentPassword || !newPassword) {
    return reply.code(400).send({
      error: 'invalid_request',
      error_description: 'currentPassword and newPassword are required (strings)',
    });
  }

  // 3. Resolve account from caller's WebID
  const account = await findByWebId(webId);
  if (!account) {
    return reply.code(403).send({
      error: 'forbidden',
      error_description: 'No account found for authenticated WebID',
    });
  }

  // 4. Verify currentPassword (re-auth proof). Side-effect-free — does NOT
  // stamp lastLogin, since password rotation isn't a login event.
  if (!(await verifyPassword(account, currentPassword))) {
    return reply.code(401).send({
      error: 'invalid_grant',
      error_description: 'Current password is incorrect',
    });
  }

  // 5. Rotate
  await updatePassword(account.id, newPassword);

  // Re-read to surface passwordChangedAt
  const updated = await findByWebId(webId);

  reply.header('Cache-Control', 'no-store');
  reply.header('Pragma', 'no-cache');
  return {
    ok: true,
    webid: account.webId,
    passwordChangedAt: updated?.passwordChangedAt,
  };
}

/**
 * Handle DELETE /idp/account (#352)
 *
 * Owner-initiated account deletion. Authenticated caller proves
 * possession via re-entering currentPassword (matches the
 * password-rotation pattern in #351). Optional `purgeData: true` also
 * removes the pod's filesystem tree at <dataRoot>/<username>/.
 *
 * Failure modes:
 *   401 — unauthenticated, or wrong currentPassword
 *   400 — invalid request body / missing password
 *   403 — single-user mode (deletion would brick the server until
 *         re-seed; operator should use the CLI), or no account for the
 *         caller's WebID. The "no account" case lands here rather than
 *         404 because the caller had a valid token — they're proving
 *         identity, just not for an account this server holds.
 *
 * Out of scope: invalidating in-flight access tokens. Tokens reference
 * the WebID; once the account record is gone, follow-up auth attempts
 * fail at findByWebId(). Existing bearer tokens that don't round-trip
 * through findByWebId() will appear valid until they expire — same
 * shape as the password-change endpoint.
 *
 * @param {object} request - Fastify request
 * @param {object} reply - Fastify reply
 * @param {object} options
 * @param {boolean} [options.singleUser] - When true, the endpoint
 *   refuses (deletion would leave the server with no IDP account).
 */
export async function handleDeleteAccount(request, reply, options = {}) {
  // Single-user mode: deletion via HTTP is blocked. The single-user
  // pod has exactly one account; deleting it bricks the server until
  // re-seed. The CLI (`jss account delete`) stays available for the
  // operator who has filesystem access.
  if (options.singleUser) {
    return reply.code(403).send({
      error: 'forbidden',
      error_description: 'Account deletion via HTTP is disabled in single-user mode. Use the `jss account delete` CLI on the server.',
    });
  }

  // 1. Authenticate caller
  const { webId, error: authError } = await getWebIdFromRequestAsync(request);
  if (!webId) {
    return reply.code(401).send({
      error: 'invalid_token',
      error_description: authError || 'Authentication required',
    });
  }

  // 2. Parse body — same flexible shape as handleChangePassword
  let body = request.body;
  if (Buffer.isBuffer(body)) body = body.toString('utf-8');
  if (typeof body === 'string') {
    try { body = JSON.parse(body); } catch { body = {}; }
  }
  const currentPassword = body?.currentPassword;
  const purgeData = body?.purgeData === true;

  if (typeof currentPassword !== 'string' || !currentPassword) {
    return reply.code(400).send({
      error: 'invalid_request',
      error_description: 'currentPassword is required (string)',
    });
  }

  // 3. Resolve account from caller's WebID
  const account = await findByWebId(webId);
  if (!account) {
    return reply.code(403).send({
      error: 'forbidden',
      error_description: 'No account found for authenticated WebID',
    });
  }

  // 4. Verify currentPassword (re-auth proof)
  if (!(await verifyPassword(account, currentPassword))) {
    return reply.code(401).send({
      error: 'invalid_grant',
      error_description: 'Current password is incorrect',
    });
  }

  // 5. Delete the account record + indexes
  await deleteAccount(account.id);

  // 6. Optionally purge the pod's filesystem data. Mirrors the CLI
  // `--purge` semantics. The path is `<dataRoot>/<podName>/`.
  //
  // Use account.podName, NOT account.username: createAccount normalizes
  // username to lowercase (`username.toLowerCase().trim()`) but the pod
  // directory on disk is created with the original case (per the input
  // to handleCreatePod). On case-sensitive filesystems, deriving the
  // purge path from username would either no-op (path doesn't exist)
  // or hit a different directory if one exists at the lowercased name.
  // Pod-name validation regex is /^[a-zA-Z0-9_-]+$/ (alphanum + dash +
  // underscore; no dots, no traversal sequences) so podName is safe to
  // join — defensive normalize stays as belt-and-suspenders.
  //
  // Best-effort: if fs.remove throws (permissions, transient FS error,
  // race with another consumer), the account is already deleted and we
  // shouldn't 500 over the leftover files. Log server-side and return
  // purged: false so the caller knows pod data may still exist; an
  // operator can finish the cleanup with a follow-up `rm -rf` or
  // CLI `--purge` against the now-orphaned directory.
  let purged = false;
  if (purgeData) {
    const dataRoot = process.env.DATA_ROOT || './data';
    const candidate = path.resolve(dataRoot, account.podName || account.username);
    const root = path.resolve(dataRoot);
    // Belt-and-suspenders: refuse to remove anything that isn't a
    // proper child of the data root. Won't trigger on registered pod
    // names; protects against config drift / future bugs. Use
    // path.relative so the check works when dataRoot is a filesystem
    // root like `/` (where startsWith(root + path.sep) would compare
    // against `//`, false-negative all valid children).
    const rel = path.relative(root, candidate);
    const isProperChild = rel && rel !== '' && !rel.startsWith('..') && !path.isAbsolute(rel);
    if (isProperChild) {
      try {
        await fs.remove(candidate);
        purged = true;
      } catch (err) {
        request.log.error({ err, path: candidate, username: account.username },
          'Pod data purge failed after account deletion');
        // Don't surface the raw error to the user (file paths,
        // permission detail leak); response.purged signals the
        // outcome.
      }
    }
  }

  reply.header('Cache-Control', 'no-store');
  reply.header('Pragma', 'no-cache');
  return {
    ok: true,
    webid: account.webId,
    purged,
  };
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
