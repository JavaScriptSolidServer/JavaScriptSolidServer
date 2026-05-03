/**
 * Account management for the Identity Provider
 * Handles user accounts with username/password authentication
 * Email is optional - internally uses username@jss if not provided
 */

// Use bcryptjs for cross-platform compatibility (works on Android/Termux/Windows)
const bcrypt = await import('bcryptjs').then(m => m.default);
import crypto from 'crypto';
import fs from 'fs-extra';
import path from 'path';

// Internal domain for generated emails
const INTERNAL_DOMAIN = 'jss';

/**
 * Get accounts directory (computed dynamically to support changing DATA_ROOT)
 */
function getAccountsDir() {
  const dataRoot = process.env.DATA_ROOT || './data';
  return path.join(dataRoot, '.idp', 'accounts');
}

function getUsernameIndexPath() {
  return path.join(getAccountsDir(), '_username_index.json');
}

function getEmailIndexPath() {
  return path.join(getAccountsDir(), '_email_index.json');
}

function getWebIdIndexPath() {
  return path.join(getAccountsDir(), '_webid_index.json');
}

function getCredentialIndexPath() {
  return path.join(getAccountsDir(), '_credential_index.json');
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
 * @param {string} options.username - Username (typically same as podName)
 * @param {string} options.password - Plain text password
 * @param {string} options.webId - User's WebID URI
 * @param {string} options.podName - Pod name
 * @param {string} [options.email] - Optional email (defaults to username@jss)
 * @returns {Promise<object>} - Created account (without password)
 */
export async function createAccount({ username, password, webId, podName, email }) {
  await ensureDir();

  const normalizedUsername = username.toLowerCase().trim();
  // Use provided email or generate internal one
  const normalizedEmail = email
    ? email.toLowerCase().trim()
    : `${normalizedUsername}@${INTERNAL_DOMAIN}`;

  // Check username uniqueness
  const existingByUsername = await findByUsername(normalizedUsername);
  if (existingByUsername) {
    throw new Error('Username already taken');
  }

  // Check email uniqueness (if real email provided)
  if (email) {
    const existingByEmail = await findByEmail(normalizedEmail);
    if (existingByEmail) {
      throw new Error('Email already registered');
    }
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
    username: normalizedUsername,
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

  // Update username index
  const usernameIndex = await loadIndex(getUsernameIndexPath());
  usernameIndex[normalizedUsername] = id;
  await saveIndex(getUsernameIndexPath(), usernameIndex);

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
 * Verify a password against an account's stored hash without side effects.
 * Use this for re-auth proofs (e.g. password rotation) where stamping
 * lastLogin would falsify the audit trail.
 * @param {object} account - Account object with passwordHash
 * @param {string} password - Plain text password
 * @returns {Promise<boolean>}
 */
export async function verifyPassword(account, password) {
  if (!account?.passwordHash) return false;
  return bcrypt.compare(password, account.passwordHash);
}

/**
 * Authenticate a user with username/email and password
 * @param {string} identifier - Username or email
 * @param {string} password - Plain text password
 * @returns {Promise<object|null>} - Account if valid, null if invalid
 */
export async function authenticate(identifier, password) {
  // Try to find by username first, then by email
  let account = await findByUsername(identifier);
  if (!account) {
    account = await findByEmail(identifier);
  }
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
 * Find an account by username
 * @param {string} username - Username
 * @returns {Promise<object|null>} - Account or null
 */
export async function findByUsername(username) {
  const normalizedUsername = username.toLowerCase().trim();
  const usernameIndex = await loadIndex(getUsernameIndexPath());
  const id = usernameIndex[normalizedUsername];
  if (!id) return null;
  return findById(id);
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
  if (account.username) {
    const usernameIndex = await loadIndex(getUsernameIndexPath());
    delete usernameIndex[account.username];
    await saveIndex(getUsernameIndexPath(), usernameIndex);
  }

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
 * Save an account (internal helper)
 * @param {object} account - Account object
 */
async function saveAccount(account) {
  const accountPath = path.join(getAccountsDir(), `${account.id}.json`);
  await fs.writeJson(accountPath, account, { spaces: 2 });
}

/**
 * Update last login timestamp
 * @param {string} id - Account ID
 */
export async function updateLastLogin(id) {
  const account = await findById(id);
  if (!account) return;
  account.lastLogin = new Date().toISOString();
  await saveAccount(account);
}

/**
 * Add a passkey credential to an account
 * @param {string} accountId - Account ID
 * @param {object} credential - Passkey credential
 * @param {string} credential.credentialId - Base64url encoded credential ID
 * @param {string} credential.publicKey - Base64url encoded public key
 * @param {number} credential.counter - Authenticator counter
 * @param {string[]} [credential.transports] - Supported transports
 * @param {string} [credential.name] - User-friendly name
 * @returns {Promise<boolean>} - Success
 */
export async function addPasskey(accountId, credential) {
  const account = await findById(accountId);
  if (!account) return false;

  account.passkeys = account.passkeys || [];

  // Check for duplicate credentialId
  const existingPasskey = account.passkeys.find(pk => pk.credentialId === credential.credentialId);
  if (existingPasskey) {
    return false; // Already registered
  }

  account.passkeys.push({
    credentialId: credential.credentialId,
    publicKey: credential.publicKey,
    counter: credential.counter || 0,
    transports: credential.transports || [],
    createdAt: new Date().toISOString(),
    lastUsed: null,
    name: credential.name || 'Security Key'
  });

  await saveAccount(account);

  // Update credential index
  const credentialIndex = await loadIndex(getCredentialIndexPath());
  credentialIndex[credential.credentialId] = accountId;
  await saveIndex(getCredentialIndexPath(), credentialIndex);

  return true;
}

/**
 * Find an account by passkey credential ID
 * @param {string} credentialId - Base64url encoded credential ID
 * @returns {Promise<object|null>} - Account or null
 */
export async function findByCredentialId(credentialId) {
  const credentialIndex = await loadIndex(getCredentialIndexPath());
  const id = credentialIndex[credentialId];
  if (!id) return null;
  return findById(id);
}

/**
 * Update passkey counter after successful authentication
 * @param {string} accountId - Account ID
 * @param {string} credentialId - Credential ID
 * @param {number} newCounter - New counter value
 */
export async function updatePasskeyCounter(accountId, credentialId, newCounter) {
  const account = await findById(accountId);
  if (!account || !account.passkeys) return;

  const passkey = account.passkeys.find(p => p.credentialId === credentialId);
  if (passkey) {
    passkey.counter = newCounter;
    passkey.lastUsed = new Date().toISOString();
    await saveAccount(account);
  }
}

/**
 * Remove a passkey from an account
 * @param {string} accountId - Account ID
 * @param {string} credentialId - Credential ID to remove
 * @returns {Promise<boolean>} - Success
 */
export async function removePasskey(accountId, credentialId) {
  const account = await findById(accountId);
  if (!account || !account.passkeys) return false;

  const index = account.passkeys.findIndex(p => p.credentialId === credentialId);
  if (index === -1) return false;

  account.passkeys.splice(index, 1);
  await saveAccount(account);

  // Update credential index
  const credentialIndex = await loadIndex(getCredentialIndexPath());
  delete credentialIndex[credentialId];
  await saveIndex(getCredentialIndexPath(), credentialIndex);

  return true;
}

/**
 * Set passkey prompt dismissed flag
 * @param {string} accountId - Account ID
 * @param {boolean} dismissed - Whether prompt was dismissed
 */
export async function setPasskeyPromptDismissed(accountId, dismissed = true) {
  const account = await findById(accountId);
  if (!account) return;
  account.passkeyPromptDismissed = dismissed;
  await saveAccount(account);
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
