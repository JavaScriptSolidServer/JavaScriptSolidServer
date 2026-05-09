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
import { accountDeletePage } from './views.js';

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
 * removes the pod's filesystem tree at `<dataRoot>/<podName>/` (falling
 * back to `<username>` only if podName is absent on the account record).
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

  // 5. Delete via the shared helper (also handles optional pod-data purge).
  // See deleteAccountAndOptionallyPurge below for the purge semantics
  // and rationale (#391 pass 2 / pass 3).
  const { purged } = await deleteAccountAndOptionallyPurge(request, account, purgeData);

  reply.header('Cache-Control', 'no-store');
  reply.header('Pragma', 'no-cache');
  return {
    ok: true,
    webid: account.webId,
    purged,
  };
}

/**
 * Internal: delete an account record + optional pod-data purge.
 * Shared between the JSON endpoint (handleDeleteAccount) and the
 * form-driven endpoint (handleAccountDeleteForm in #392).
 *
 * Best-effort purge — fs.remove can throw, but the account is already
 * gone and we want a clean signal rather than a 500. Path is derived
 * from account.podName (NOT username, which createAccount lowercases —
 * pod dir on disk is original case, see #391 pass 2). Belt-and-
 * suspenders path-relative check rejects ../traversal and works at FS
 * roots (see #391 pass 3).
 *
 * @param {object} request - Fastify request, used only for log access
 * @param {object} account - Account record (with username, podName, webId)
 * @param {boolean} purgeData - If true, also remove the pod's filesystem tree
 * @returns {Promise<{purged: boolean}>}
 */
async function deleteAccountAndOptionallyPurge(request, account, purgeData) {
  await deleteAccount(account.id);

  let purged = false;
  if (purgeData) {
    const dataRoot = process.env.DATA_ROOT || './data';
    const candidate = path.resolve(dataRoot, account.podName || account.username);
    const root = path.resolve(dataRoot);
    const rel = path.relative(root, candidate);
    const isProperChild = rel && rel !== '' && !rel.startsWith('..') && !path.isAbsolute(rel);
    if (isProperChild) {
      try {
        await fs.remove(candidate);
        purged = true;
      } catch (err) {
        request.log.error({ err, path: candidate, username: account.username },
          'Pod data purge failed after account deletion');
      }
    }
  }
  return { purged };
}

/**
 * Handle GET / POST /idp/account/delete (#392) — form-driven account deletion.
 *
 * Public unauthenticated endpoint that takes a form-encoded body with
 * username + currentPassword + confirmUsername (+ optional purgeData
 * checkbox). Authenticates the user via password directly (no Bearer
 * token round-trip required), validates the destructive-action UX
 * guard, then calls into the same delete logic as the JSON endpoint
 * via deleteAccountAndOptionallyPurge. Returns HTML directly:
 *   - success → success page
 *   - any failure → the form re-rendered with an error message and the
 *     username field pre-filled (no redirect — single response, status
 *     200 with the rendered form)
 *
 * Single-user mode: rendered as the disabled-message page instead of
 * the form, both on GET and POST. Same policy as the JSON endpoint
 * (which 403s with the equivalent message).
 *
 * @param {object} request - Fastify request
 * @param {object} reply - Fastify reply
 * @param {object} options
 * @param {boolean} [options.singleUser] - Single-user mode flag
 */
export async function handleAccountDeleteForm(request, reply, options = {}) {
  if (options.singleUser) {
    return reply.type('text/html').send(accountDeletePage({ singleUser: true }));
  }

  // Parse form-encoded body. Fastify with @fastify/formbody (registered
  // for /idp/register etc.) puts fields directly on request.body.
  let body = request.body;
  if (Buffer.isBuffer(body)) body = body.toString('utf-8');
  if (typeof body === 'string') {
    // Manual urlencoded parse fallback if formbody isn't registered for
    // this content-type on this route.
    try {
      const params = new URLSearchParams(body);
      body = Object.fromEntries(params);
    } catch { body = {}; }
  }

  const username = (body?.username || '').trim();
  const currentPassword = body?.currentPassword || '';
  const confirmUsername = (body?.confirmUsername || '').trim();
  const purgeData = body?.purgeData === 'on' || body?.purgeData === true;

  if (!username || !currentPassword || !confirmUsername) {
    return reply.type('text/html').send(accountDeletePage({
      error: 'All fields are required.',
      username,
    }));
  }

  // Destructive-action UX guard: typed username must match. Compare
  // case-sensitively against the *typed* form value, not the resolved
  // account — the user shouldn't be able to typo their way to a delete
  // that hits a different (lowercased) record.
  if (username !== confirmUsername) {
    return reply.type('text/html').send(accountDeletePage({
      error: 'Confirmation does not match the username you entered.',
      username,
    }));
  }

  // Authenticate. authenticate() looks up by username then by email,
  // verifies bcrypt, and returns the account (sans password hash) or null.
  const account = await authenticate(username, currentPassword);
  if (!account) {
    return reply.type('text/html').send(accountDeletePage({
      error: 'Username or password is incorrect.',
      username,
    }));
  }

  const { purged } = await deleteAccountAndOptionallyPurge(request, account, purgeData);

  // If the user asked for a purge but it didn't run (fs.remove threw,
  // path-relative check rejected, etc.), surface that on the success
  // page. Account deletion succeeded — don't roll that back — but the
  // operator may need to finish cleanup. Don't leak server paths.
  const purgeFailed = purgeData && !purged;
  return reply.type('text/html').send(accountDeletePage({ success: true, purgeFailed }));
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
