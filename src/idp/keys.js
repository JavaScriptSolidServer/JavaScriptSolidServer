/**
 * JWKS key management for the Identity Provider
 * Generates and stores signing keys for tokens
 */

import * as jose from 'jose';
import fs from 'fs-extra';
import path from 'path';
import crypto from 'crypto';

/**
 * Get keys directory (dynamic to support changing DATA_ROOT)
 */
function getKeysDir() {
  const dataRoot = process.env.DATA_ROOT || './data';
  return path.join(dataRoot, '.idp', 'keys');
}

function getJwksPath() {
  return path.join(getKeysDir(), 'jwks.json');
}

/**
 * Generate a new EC P-256 key pair for signing
 * @returns {Promise<object>} - JWK key pair with private key
 */
async function generateSigningKey() {
  const { publicKey, privateKey } = await jose.generateKeyPair('ES256', {
    extractable: true,
  });

  const privateJwk = await jose.exportJWK(privateKey);
  const publicJwk = await jose.exportJWK(publicKey);

  // Add metadata
  const kid = crypto.randomUUID();
  const now = Math.floor(Date.now() / 1000);

  return {
    ...privateJwk,
    kid,
    use: 'sig',
    alg: 'ES256',
    iat: now,
  };
}

/**
 * Generate cookie signing keys
 * @returns {string[]} - Array of random secret strings
 */
function generateCookieKeys() {
  return [
    crypto.randomBytes(32).toString('base64url'),
    crypto.randomBytes(32).toString('base64url'),
  ];
}

/**
 * Initialize JWKS - generate keys if they don't exist
 * @returns {Promise<object>} - { jwks, cookieKeys }
 */
export async function initializeKeys() {
  await fs.ensureDir(getKeysDir());

  try {
    // Try to load existing keys
    const data = await fs.readJson(getJwksPath());
    return data;
  } catch (err) {
    if (err.code !== 'ENOENT') throw err;

    // Generate new keys
    console.log('Generating new IdP signing keys...');
    const signingKey = await generateSigningKey();
    const cookieKeys = generateCookieKeys();

    const data = {
      jwks: {
        keys: [signingKey],
      },
      cookieKeys,
      createdAt: new Date().toISOString(),
    };

    await fs.writeJson(getJwksPath(), data, { spaces: 2 });
    console.log('IdP signing keys generated and saved.');

    return data;
  }
}

/**
 * Get the JWKS (public keys only) for /.well-known/jwks.json
 * @returns {Promise<object>} - JWKS with public keys only
 */
export async function getPublicJwks() {
  const { jwks } = await initializeKeys();

  // Return only public key components
  const publicKeys = jwks.keys.map((key) => {
    // For EC keys, remove 'd' (private key component)
    const { d, ...publicKey } = key;
    return publicKey;
  });

  return { keys: publicKeys };
}

/**
 * Get the full JWKS (including private keys) for oidc-provider
 * @returns {Promise<object>} - Full JWKS
 */
export async function getJwks() {
  const { jwks } = await initializeKeys();
  return jwks;
}

/**
 * Get cookie signing keys
 * @returns {Promise<string[]>} - Cookie keys
 */
export async function getCookieKeys() {
  const { cookieKeys } = await initializeKeys();
  return cookieKeys;
}

/**
 * Rotate signing keys (add new key, keep old for verification)
 * @returns {Promise<void>}
 */
export async function rotateKeys() {
  const data = await fs.readJson(getJwksPath());

  // Mark old keys
  data.jwks.keys.forEach((key) => {
    if (!key.rotatedAt) {
      key.rotatedAt = new Date().toISOString();
    }
  });

  // Generate new signing key
  const newKey = await generateSigningKey();
  data.jwks.keys.unshift(newKey); // New key first (primary)

  // Keep only last 3 keys for verification
  if (data.jwks.keys.length > 3) {
    data.jwks.keys = data.jwks.keys.slice(0, 3);
  }

  // Rotate cookie keys too
  data.cookieKeys = generateCookieKeys();
  data.rotatedAt = new Date().toISOString();

  await fs.writeJson(getJwksPath(), data, { spaces: 2 });
  console.log('IdP keys rotated.');
}
