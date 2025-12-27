/**
 * Account management for the Identity Provider
 * Handles user accounts with email/password authentication
 */

import bcrypt from 'bcrypt';
import crypto from 'crypto';
import fs from 'fs-extra';
import path from 'path';

/**
 * Get accounts directory (computed dynamically to support changing DATA_ROOT)
 */
function getAccountsDir() {
  const dataRoot = process.env.DATA_ROOT || './data';
  return path.join(dataRoot, '.idp', 'accounts');
}

function getEmailIndexPath() {
  return path.join(getAccountsDir(), '_email_index.json');
}

function getWebIdIndexPath() {
  return path.join(getAccountsDir(), '_webid_index.json');
}

const SALT_ROUNDS = 10;

/**
 * Initialize the accounts directory
 */
async function ensureDir() {
  await fs.ensureDir(getAccountsDir());
}

/**
 * Load an index file
 */
async function loadIndex(indexPath) {
  try {
    return await fs.readJson(indexPath);
  } catch (err) {
    if (err.code === 'ENOENT') return {};
    throw err;
  }
}

/**
 * Save an index file
 */
async function saveIndex(indexPath, index) {
  await fs.writeJson(indexPath, index, { spaces: 2 });
}

/**
 * Create a new user account
 * @param {object} options - Account options
 * @param {string} options.email - User email
 * @param {string} options.password - Plain text password
 * @param {string} options.webId - User's WebID URI
 * @param {string} options.podName - Pod name
 * @returns {Promise<object>} - Created account (without password)
 */
export async function createAccount({ email, password, webId, podName }) {
  await ensureDir();

  const normalizedEmail = email.toLowerCase().trim();

  // Check email uniqueness
  const existingByEmail = await findByEmail(normalizedEmail);
  if (existingByEmail) {
    throw new Error('Email already registered');
  }

  // Check webId uniqueness
  const existingByWebId = await findByWebId(webId);
  if (existingByWebId) {
    throw new Error('WebID already has an account');
  }

  // Generate account ID and hash password
  const id = crypto.randomUUID();
  const passwordHash = await bcrypt.hash(password, SALT_ROUNDS);

  const account = {
    id,
    email: normalizedEmail,
    passwordHash,
    webId,
    podName,
    createdAt: new Date().toISOString(),
    lastLogin: null,
  };

  // Save account
  const accountPath = path.join(getAccountsDir(), `${id}.json`);
  await fs.writeJson(accountPath, account, { spaces: 2 });

  // Update email index
  const emailIndex = await loadIndex(getEmailIndexPath());
  emailIndex[normalizedEmail] = id;
  await saveIndex(getEmailIndexPath(), emailIndex);

  // Update webId index
  const webIdIndex = await loadIndex(getWebIdIndexPath());
  webIdIndex[webId] = id;
  await saveIndex(getWebIdIndexPath(), webIdIndex);

  // Return account without password hash
  const { passwordHash: _, ...safeAccount } = account;
  return safeAccount;
}

/**
 * Authenticate a user with email and password
 * @param {string} email - User email
 * @param {string} password - Plain text password
 * @returns {Promise<object|null>} - Account if valid, null if invalid
 */
export async function authenticate(email, password) {
  const account = await findByEmail(email);
  if (!account) return null;

  const valid = await bcrypt.compare(password, account.passwordHash);
  if (!valid) return null;

  // Update last login
  account.lastLogin = new Date().toISOString();
  const accountPath = path.join(getAccountsDir(), `${account.id}.json`);
  await fs.writeJson(accountPath, account, { spaces: 2 });

  // Return account without password hash
  const { passwordHash: _, ...safeAccount } = account;
  return safeAccount;
}

/**
 * Find an account by ID
 * @param {string} id - Account ID
 * @returns {Promise<object|null>} - Account or null
 */
export async function findById(id) {
  try {
    const accountPath = path.join(getAccountsDir(), `${id}.json`);
    return await fs.readJson(accountPath);
  } catch (err) {
    if (err.code === 'ENOENT') return null;
    throw err;
  }
}

/**
 * Find an account by email
 * @param {string} email - User email
 * @returns {Promise<object|null>} - Account or null
 */
export async function findByEmail(email) {
  const normalizedEmail = email.toLowerCase().trim();
  const emailIndex = await loadIndex(getEmailIndexPath());
  const id = emailIndex[normalizedEmail];
  if (!id) return null;
  return findById(id);
}

/**
 * Find an account by WebID
 * @param {string} webId - User WebID
 * @returns {Promise<object|null>} - Account or null
 */
export async function findByWebId(webId) {
  const webIdIndex = await loadIndex(getWebIdIndexPath());
  const id = webIdIndex[webId];
  if (!id) return null;
  return findById(id);
}

/**
 * Update account password
 * @param {string} id - Account ID
 * @param {string} newPassword - New plain text password
 */
export async function updatePassword(id, newPassword) {
  const account = await findById(id);
  if (!account) {
    throw new Error('Account not found');
  }

  account.passwordHash = await bcrypt.hash(newPassword, SALT_ROUNDS);
  account.passwordChangedAt = new Date().toISOString();

  const accountPath = path.join(getAccountsDir(), `${id}.json`);
  await fs.writeJson(accountPath, account, { spaces: 2 });
}

/**
 * Delete an account
 * @param {string} id - Account ID
 */
export async function deleteAccount(id) {
  const account = await findById(id);
  if (!account) return;

  // Remove from indexes
  const emailIndex = await loadIndex(getEmailIndexPath());
  delete emailIndex[account.email];
  await saveIndex(getEmailIndexPath(), emailIndex);

  const webIdIndex = await loadIndex(getWebIdIndexPath());
  delete webIdIndex[account.webId];
  await saveIndex(getWebIdIndexPath(), webIdIndex);

  // Delete account file
  const accountPath = path.join(getAccountsDir(), `${id}.json`);
  await fs.remove(accountPath);
}

/**
 * Get account for oidc-provider's findAccount
 * This is the interface oidc-provider expects
 * @param {string} id - Account ID
 * @returns {Promise<object|undefined>} - Account interface for oidc-provider
 */
export async function getAccountForProvider(id) {
  const account = await findById(id);
  if (!account) return undefined;

  return {
    accountId: id,
    /**
     * Return claims for the token
     * @param {string} use - 'id_token' or 'userinfo'
     * @param {string} scope - Requested scopes
     * @param {object} claims - Requested claims
     * @param {string[]} rejected - Rejected claims
     */
    async claims(use, scope, claims, rejected) {
      const result = {
        sub: id,
      };

      // Always include webid for Solid-OIDC
      result.webid = account.webId;

      // Handle scope being a string, array, Set, or object with keys
      const hasScope = (s) => {
        if (typeof scope === 'string') return scope.includes(s);
        if (Array.isArray(scope)) return scope.includes(s);
        if (scope instanceof Set) return scope.has(s);
        if (scope && typeof scope === 'object') return s in scope || Object.keys(scope).includes(s);
        return false;
      };

      // Profile scope
      if (hasScope('profile')) {
        result.name = account.podName;
      }

      // Email scope
      if (hasScope('email')) {
        result.email = account.email;
        result.email_verified = false; // We don't have email verification yet
      }

      return result;
    },
  };
}
