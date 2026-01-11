/**
 * Passkey (WebAuthn) authentication endpoints
 * Handles registration and authentication of passkey credentials
 */

import {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse
} from '@simplewebauthn/server';
import crypto from 'crypto';
import * as accounts from './accounts.js';

// Temporary challenge storage (in-memory, cleared on restart)
// For production clusters, use Redis or session storage
const challenges = new Map();

// Clean up expired challenges periodically
setInterval(() => {
  const now = Date.now();
  for (const [key, value] of challenges.entries()) {
    if (now > value.expires) {
      challenges.delete(key);
    }
  }
}, 60000); // Clean every minute

/**
 * Get Relying Party configuration from request
 */
function getRP(request) {
  const hostname = request.hostname.split(':')[0]; // Remove port
  return {
    name: 'Solid Pod',
    id: hostname
  };
}

/**
 * Get origin from request
 */
function getOrigin(request) {
  return `${request.protocol}://${request.hostname}`;
}

/**
 * POST /idp/passkey/register/options
 * Generate registration options for a logged-in user
 */
export async function registrationOptions(request, reply) {
  const { accountId } = request.body || {};

  if (!accountId) {
    return reply.code(401).send({ error: 'Must provide accountId' });
  }

  const account = await accounts.findById(accountId);
  if (!account) {
    return reply.code(404).send({ error: 'Account not found' });
  }

  const rp = getRP(request);

  const options = await generateRegistrationOptions({
    rpName: rp.name,
    rpID: rp.id,
    userID: new TextEncoder().encode(account.id),
    userName: account.username,
    userDisplayName: account.username,
    attestationType: 'none', // Don't require attestation for privacy
    excludeCredentials: (account.passkeys || []).map(pk => ({
      id: Buffer.from(pk.credentialId, 'base64url'),
      type: 'public-key',
      transports: pk.transports
    })),
    authenticatorSelection: {
      residentKey: 'preferred',
      userVerification: 'preferred'
    }
  });

  // Store challenge for verification
  challenges.set(account.id, {
    challenge: options.challenge,
    type: 'registration',
    expires: Date.now() + 60000 // 1 minute
  });

  return reply.send(options);
}

/**
 * POST /idp/passkey/register/verify
 * Verify and store the registration response
 */
export async function registrationVerify(request, reply) {
  const { accountId, credential, name } = request.body || {};

  if (!accountId || !credential) {
    return reply.code(400).send({ error: 'Missing accountId or credential' });
  }

  const account = await accounts.findById(accountId);
  if (!account) {
    return reply.code(404).send({ error: 'Account not found' });
  }

  const stored = challenges.get(account.id);
  if (!stored || stored.type !== 'registration' || Date.now() > stored.expires) {
    return reply.code(400).send({ error: 'Challenge expired or invalid' });
  }

  const rp = getRP(request);

  try {
    const verification = await verifyRegistrationResponse({
      response: credential,
      expectedChallenge: stored.challenge,
      expectedOrigin: getOrigin(request),
      expectedRPID: rp.id
    });

    if (!verification.verified || !verification.registrationInfo) {
      return reply.code(400).send({ error: 'Verification failed' });
    }

    const { credential: regCredential, credentialPublicKey, counter } = verification.registrationInfo;

    await accounts.addPasskey(accountId, {
      credentialId: Buffer.from(regCredential.id).toString('base64url'),
      publicKey: Buffer.from(credentialPublicKey).toString('base64url'),
      counter,
      transports: credential.response?.transports || [],
      name: name || 'Security Key'
    });

    challenges.delete(account.id);

    return reply.send({ success: true });
  } catch (err) {
    console.error('Passkey registration error:', err);
    return reply.code(400).send({ error: err.message });
  }
}

/**
 * POST /idp/passkey/login/options
 * Generate authentication options
 */
export async function authenticationOptions(request, reply) {
  const { username } = request.body || {};
  const rp = getRP(request);

  let allowCredentials = [];
  let accountId = null;

  // If username provided, limit to that user's credentials
  if (username) {
    const account = await accounts.findByUsername(username);
    if (account && account.passkeys?.length) {
      accountId = account.id;
      allowCredentials = account.passkeys.map(pk => ({
        id: Buffer.from(pk.credentialId, 'base64url'),
        type: 'public-key',
        transports: pk.transports
      }));
    }
  }

  const options = await generateAuthenticationOptions({
    rpID: rp.id,
    allowCredentials,
    userVerification: 'preferred'
  });

  // Store challenge - use visitorId for anonymous requests
  const challengeKey = accountId || request.body?.visitorId || crypto.randomUUID();
  challenges.set(challengeKey, {
    challenge: options.challenge,
    type: 'authentication',
    accountId,
    expires: Date.now() + 60000 // 1 minute
  });

  return reply.send({ ...options, challengeKey });
}

/**
 * POST /idp/passkey/login/verify
 * Verify authentication and return account info
 */
export async function authenticationVerify(request, reply) {
  const { challengeKey, credential } = request.body || {};

  if (!challengeKey || !credential) {
    return reply.code(400).send({ error: 'Missing challengeKey or credential' });
  }

  const stored = challenges.get(challengeKey);
  if (!stored || stored.type !== 'authentication' || Date.now() > stored.expires) {
    return reply.code(400).send({ error: 'Challenge expired or invalid' });
  }

  // Find account by credential ID
  const credentialId = credential.id;
  const account = stored.accountId
    ? await accounts.findById(stored.accountId)
    : await accounts.findByCredentialId(credentialId);

  if (!account) {
    return reply.code(400).send({ error: 'Unknown credential' });
  }

  const passkey = account.passkeys?.find(pk => pk.credentialId === credentialId);
  if (!passkey) {
    return reply.code(400).send({ error: 'Credential not found' });
  }

  const rp = getRP(request);

  try {
    const verification = await verifyAuthenticationResponse({
      response: credential,
      expectedChallenge: stored.challenge,
      expectedOrigin: getOrigin(request),
      expectedRPID: rp.id,
      credential: {
        id: Buffer.from(passkey.credentialId, 'base64url'),
        publicKey: Buffer.from(passkey.publicKey, 'base64url'),
        counter: passkey.counter
      }
    });

    if (!verification.verified) {
      return reply.code(400).send({ error: 'Verification failed' });
    }

    // Update counter to prevent replay attacks
    await accounts.updatePasskeyCounter(
      account.id,
      credentialId,
      verification.authenticationInfo.newCounter
    );

    // Update last login
    await accounts.updateLastLogin(account.id);

    challenges.delete(challengeKey);

    // Return account info for session creation
    return reply.send({
      success: true,
      accountId: account.id,
      webId: account.webId
    });
  } catch (err) {
    console.error('Passkey authentication error:', err);
    return reply.code(400).send({ error: err.message });
  }
}
