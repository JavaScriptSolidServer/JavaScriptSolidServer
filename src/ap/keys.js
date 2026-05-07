/**
 * ActivityPub RSA Keypair Management
 * Generate and persist keypairs for HTTP Signatures
 */

import { generateKeyPairSync } from 'crypto'
import { existsSync, readFileSync, writeFileSync, mkdirSync } from 'fs'
import { dirname, join } from 'path'

/**
 * Get default key path under DATA_ROOT/.idp/ap/
 * @param {string} username
 */
export function getDefaultKeyPath(username = 'me') {
  const dataRoot = process.env.DATA_ROOT || './data'
  return join(dataRoot, '.idp', 'ap', 'keys.json')
}

/**
 * Generate RSA keypair
 * @param {number} modulusLength - Key size in bits (default 2048)
 * @returns {{ publicKey: string, privateKey: string }}
 */
export function generateKeypair(modulusLength = 2048) {
  const { publicKey, privateKey } = generateKeyPairSync('rsa', {
    modulusLength,
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
  })
  return { publicKey, privateKey }
}

/**
 * Load keypair from disk, generate if not exists
 * @param {string} [path] - Path to keys file (defaults to DATA_ROOT/.idp/ap/keys.json)
 * @returns {{ publicKey: string, privateKey: string }}
 */
export function loadOrCreateKeypair(path) {
  const resolvedPath = path || getDefaultKeyPath('me')
  if (existsSync(resolvedPath)) {
    return JSON.parse(readFileSync(resolvedPath, 'utf8'))
  }

  // Generate new keypair
  const keypair = generateKeypair()

  // Ensure directory exists
  const dir = dirname(resolvedPath)
  if (!existsSync(dir)) {
    mkdirSync(dir, { recursive: true })
  }

  // Save to disk
  writeFileSync(resolvedPath, JSON.stringify(keypair, null, 2))
  console.log(`Generated new ActivityPub keypair: ${resolvedPath}`)

  return keypair
}

/**
 * Get key ID for HTTP Signatures
 * @param {string} actorId - Actor URL (e.g., https://example.com/profile/card.jsonld#me)
 * @returns {string} Key ID (e.g., https://example.com/profile/card.jsonld#main-key)
 */
export function getKeyId(actorId) {
  // Strip fragment and add #main-key
  const base = actorId.replace(/#.*$/, '')
  return `${base}#main-key`
}

export default { generateKeypair, loadOrCreateKeypair, getKeyId }
