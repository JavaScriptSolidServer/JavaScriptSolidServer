/**
 * Invite code management for invite-only registration
 * Stores codes in /data/.server/invites.json
 */

import { promises as fs } from 'fs';
import { join } from 'path';
import crypto from 'crypto';
import { getDataRoot } from '../utils/url.js';

const INVITES_DIR = '.server';
const INVITES_FILE = 'invites.json';

/**
 * Get path to invites file
 */
function getInvitesPath() {
  return join(getDataRoot(), INVITES_DIR, INVITES_FILE);
}

/**
 * Ensure .server directory exists
 */
async function ensureServerDir() {
  const dirPath = join(getDataRoot(), INVITES_DIR);
  try {
    await fs.mkdir(dirPath, { recursive: true });
  } catch (err) {
    if (err.code !== 'EEXIST') throw err;
  }
}

/**
 * Load all invites from storage
 * @returns {Promise<object>} Map of code -> invite data
 */
export async function loadInvites() {
  try {
    const data = await fs.readFile(getInvitesPath(), 'utf-8');
    return JSON.parse(data);
  } catch (err) {
    if (err.code === 'ENOENT') {
      return {};
    }
    throw err;
  }
}

/**
 * Save invites to storage
 * @param {object} invites - Map of code -> invite data
 */
async function saveInvites(invites) {
  await ensureServerDir();
  await fs.writeFile(getInvitesPath(), JSON.stringify(invites, null, 2));
}

/**
 * Generate a random invite code
 * @returns {string} 8-character uppercase alphanumeric code
 */
function generateCode() {
  const bytes = crypto.randomBytes(6);
  // Base64 encode and take first 8 chars, uppercase, remove ambiguous chars
  return bytes.toString('base64')
    .replace(/[+/=]/g, '')
    .substring(0, 8)
    .toUpperCase()
    .replace(/O/g, '0')
    .replace(/I/g, '1')
    .replace(/L/g, '1');
}

/**
 * Create a new invite code
 * @param {object} options
 * @param {number} options.maxUses - Maximum number of uses (default 1)
 * @param {string} options.note - Optional note/description
 * @returns {Promise<{code: string, invite: object}>}
 */
export async function createInvite({ maxUses = 1, note = '' } = {}) {
  const invites = await loadInvites();

  // Generate unique code
  let code;
  do {
    code = generateCode();
  } while (invites[code]);

  const invite = {
    created: new Date().toISOString(),
    maxUses,
    uses: 0,
    note
  };

  invites[code] = invite;
  await saveInvites(invites);

  return { code, invite };
}

/**
 * List all invite codes
 * @returns {Promise<Array<{code: string, ...invite}>>}
 */
export async function listInvites() {
  const invites = await loadInvites();
  return Object.entries(invites).map(([code, invite]) => ({
    code,
    ...invite
  }));
}

/**
 * Revoke (delete) an invite code
 * @param {string} code - The invite code to revoke
 * @returns {Promise<boolean>} True if code existed and was deleted
 */
export async function revokeInvite(code) {
  const invites = await loadInvites();
  const upperCode = code.toUpperCase();

  if (!invites[upperCode]) {
    return false;
  }

  delete invites[upperCode];
  await saveInvites(invites);
  return true;
}

/**
 * Validate and consume an invite code
 * @param {string} code - The invite code to validate
 * @returns {Promise<{valid: boolean, error?: string}>}
 */
export async function validateInvite(code) {
  if (!code || typeof code !== 'string') {
    return { valid: false, error: 'Invite code required' };
  }

  const invites = await loadInvites();
  const upperCode = code.toUpperCase().trim();
  const invite = invites[upperCode];

  if (!invite) {
    return { valid: false, error: 'Invalid invite code' };
  }

  if (invite.uses >= invite.maxUses) {
    return { valid: false, error: 'Invite code has been fully used' };
  }

  // Consume one use
  invite.uses += 1;
  await saveInvites(invites);

  return { valid: true };
}

/**
 * Check if an invite code is valid without consuming it
 * @param {string} code - The invite code to check
 * @returns {Promise<boolean>}
 */
export async function isValidInvite(code) {
  if (!code || typeof code !== 'string') {
    return false;
  }

  const invites = await loadInvites();
  const upperCode = code.toUpperCase().trim();
  const invite = invites[upperCode];

  if (!invite) {
    return false;
  }

  return invite.uses < invite.maxUses;
}
